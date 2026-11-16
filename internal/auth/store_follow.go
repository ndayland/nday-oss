package auth

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Follows: the vendors and products a user follows (migrations/0010_follows.sql,
// docs/follows.md). All SQL for user_follows lives in this file.
//
// A follow is one free-text term; it matches a CVE when an affected row of
// the CVE has lower(vendor) = term OR lower(product) = term. The key is
// computed by the database (lower(label)), so the key and the comparison in
// MatchFollows use the same lower().

// Follow is one followed term: Term is the matching key (lower case), Label
// the spelling the user chose.
type Follow struct {
	Term  string `json:"term"`
	Label string `json:"label"`
}

// Follow limits.
const (
	MaxFollows     = 50  // per user
	MaxFollowRunes = 200 // characters of a label (and of its key)
	MaxMatchCVEs   = 200 // CVE ids per MatchFollows call
	// 50 labels of 200 four-byte characters are 40 000 bytes, plus about
	// 15 bytes of JSON per label: 64 KiB leaves room for white space.
	followBodyLimit = 64 << 10
	matchBodyLimit  = 16 << 10
)

// Follow errors (their text is returned to the client as the error message).
var (
	ErrFollowInvalid  = errors.New("a followed term is 1-200 characters without control characters")
	ErrTooManyFollows = errors.New("at most 50 followed terms")
)

// NormalizeFollow trims a label and collapses runs of white space to one
// space. It returns ErrFollowInvalid for an empty or over-long result, invalid
// UTF-8, or control and format characters (C0/C1 controls, bidi overrides,
// zero-width characters).
func NormalizeFollow(label string) (string, error) {
	if !utf8.ValidString(label) {
		return "", ErrFollowInvalid
	}
	var b strings.Builder
	space := false
	for _, r := range label {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return "", ErrFollowInvalid
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	s := b.String()
	if n := utf8.RuneCountInString(s); n == 0 || n > MaxFollowRunes || utf8.RuneCountInString(strings.ToLower(s)) > MaxFollowRunes {
		return "", ErrFollowInvalid
	}
	return s, nil
}

// NormalizeFollows normalises every label and drops later duplicates (same
// lower-case form). ErrFollowInvalid or ErrTooManyFollows (more than
// MaxFollows distinct terms).
func NormalizeFollows(labels []string) ([]string, error) {
	out := make([]string, 0, len(labels))
	seen := map[string]bool{}
	for _, l := range labels {
		n, err := NormalizeFollow(l)
		if err != nil {
			return nil, err
		}
		if k := strings.ToLower(n); !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	if len(out) > MaxFollows {
		return nil, ErrTooManyFollows
	}
	return out, nil
}

const followsSQL = `SELECT term_key, label FROM user_follows WHERE user_id = $1 ORDER BY created_at, term_key`

func collectFollows(rows pgx.Rows) ([]Follow, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Follow, error) {
		var f Follow
		return f, r.Scan(&f.Term, &f.Label)
	})
}

// Follows lists the user's followed terms (oldest first); never nil.
func (s *Store) Follows(ctx context.Context, user UserID) ([]Follow, error) {
	out := []Follow{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, followsSQL, user)
		if err != nil {
			return err
		}
		l, err := collectFollows(rows)
		if l != nil {
			out = l
		}
		return err
	})
	return out, err
}

// SetFollows replaces the user's whole list with labels (normalised with
// NormalizeFollows) in one transaction and returns the saved list. Terms that
// stay keep their created_at (and so their place); a label may change its
// spelling. The MaxFollows cap is checked again inside the transaction.
func (s *Store) SetFollows(ctx context.Context, user UserID, labels []string) ([]Follow, error) {
	labels, err := NormalizeFollows(labels)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []Follow
	err = s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			// lock the user row: two concurrent replacements serialise
			var one int
			if err := tx.QueryRow(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, user).Scan(&one); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			// $2 in order; a label whose lower() equals an earlier one's is
			// dropped (the database's lower() decides, like the key).
			const in = `SELECT DISTINCT ON (lower(l)) lower(l) AS k, l, o FROM unnest($2::text[]) WITH ORDINALITY AS t(l, o) ORDER BY lower(l), o`
			if _, err := tx.Exec(ctx, `DELETE FROM user_follows WHERE user_id = $1
				AND term_key NOT IN (SELECT k FROM (`+in+`) x)`, user, labels); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO user_follows (user_id, term_key, label, created_at)
				SELECT $1, k, l, $3::timestamptz + (o * interval '1 microsecond') FROM (`+in+`) x
				ON CONFLICT (user_id, term_key) DO UPDATE SET label = EXCLUDED.label`, user, labels, now); err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_follows WHERE user_id = $1`, user).Scan(&n); err != nil {
				return err
			}
			if n > MaxFollows {
				return ErrTooManyFollows
			}
			rows, err := tx.Query(ctx, followsSQL, user)
			if err != nil {
				return err
			}
			out, err = collectFollows(rows)
			return err
		})
	})
	if out == nil {
		out = []Follow{}
	}
	return out, err
}

// MatchFollows returns the ids among cves (canonical CVE ids, at most
// MaxMatchCVEs) of vulnerabilities with an affected row whose vendor or
// product equals one of the user's terms (case-insensitively), in the order
// of cves. One query.
func (s *Store) MatchFollows(ctx context.Context, user UserID, cves []string) ([]string, error) {
	out := []string{}
	if len(cves) == 0 {
		return out, nil
	}
	hit := map[string]bool{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT DISTINCT a.cve_id FROM affected a
			JOIN user_follows f ON f.user_id = $1 AND (lower(a.vendor) = f.term_key OR lower(a.product) = f.term_key)
			WHERE a.cve_id = ANY($2::text[])`, user, cves)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, id := range ids {
			hit[id] = true
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, id := range cves {
		if hit[id] {
			out = append(out, id)
			delete(hit, id) // a duplicate in cves is listed once
		}
	}
	return out, nil
}
