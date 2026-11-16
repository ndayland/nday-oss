package corrections

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
)

// Store is the database layer of vuln_corrections (migrations/0017). Every
// write is one transaction; the conditions are part of the writing
// statement (INSERT ... SELECT, conditional UPDATE), the caps are counted
// under per-user and per-vulnerability advisory locks, and a decision
// writes its audit row in the same transaction.
type Store struct {
	// DB is a writable pool (`nday serve` passes the sign-in pool: the
	// traffic is small).
	DB  auth.ConnSource
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Store errors.
var (
	ErrNotFound    = errors.New("no such correction")
	ErrNoVuln      = errors.New("no such vulnerability")
	ErrWrongStatus = errors.New("the correction has already been decided")
	ErrUserOpen    = errors.New("you already have the maximum number of open corrections on this vulnerability")
	ErrVulnOpen    = errors.New("this vulnerability has the maximum number of open corrections")
)

// LimitError is a refused submission because of a time-based limit.
type LimitError struct {
	Code       string // "daily_limit"
	RetryAfter time.Duration
}

func (e *LimitError) Error() string { return "corrections: " + e.Code }

// Correction is a correction as its submitter (and staff, in the decision
// responses) sees it. The internal note is never part of it.
type Correction struct {
	ID          string     `json:"id"`
	CVE         string     `json:"cve"`
	Category    string     `json:"category"`
	Body        string     `json:"body"`
	EvidenceURL *string    `json:"evidence_url"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at"`
	PublicNote  *string    `json:"public_note"`
}

const cols = `id::text, cve_id, category, body, evidence_url, status, created_at, decided_at, public_note`

func scan(row pgx.Row) (*Correction, error) {
	c := &Correction{}
	if err := row.Scan(&c.ID, &c.CVE, &c.Category, &c.Body, &c.EvidenceURL, &c.Status, &c.CreatedAt, &c.DecidedAt, &c.PublicNote); err != nil {
		return nil, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	if c.DecidedAt != nil {
		t := c.DecidedAt.UTC()
		c.DecidedAt = &t
	}
	return c, nil
}

func lock(ctx context.Context, tx pgx.Tx, kind, key string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "nday.corrections."+kind+":"+key)
	return err
}

// Submission is a submission (validated and normalised by the caller).
type Submission struct {
	CVE, Submitter, Category, Body string
	EvidenceURL                    *string
}

// NewAccountOpenPerUser is the open-per-user cap (Limits.OpenPerUser) of
// a new account on one vulnerability (docs/corrections.md).
const NewAccountOpenPerUser = 1

// Submit stores a pending correction. In one transaction, serialised per
// submitter and per vulnerability (advisory locks, always in that order):
// whether the submitter is a new account (the discussion's rule,
// discuss.IsNewAccount with nl's NewAccountAge and NewAccountComments,
// counting visible comments plus accepted corrections); the rolling 24-hour
// cap, for a new account at most nl.NewPostDaily (*LimitError
// "daily_limit"); the submitter's open corrections on the vulnerability,
// for a new account at most NewAccountOpenPerUser (ErrUserOpen); the
// vulnerability's open corrections, not counting those whose submitter
// deleted the account or is suspended now (ErrVulnOpen); then an INSERT
// ... SELECT that requires the vulnerability to exist (ErrNoVuln).
func (s *Store) Submit(ctx context.Context, n Submission, lim Limits, nl discuss.Limits) (*Correction, error) {
	var out *Correction
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if err := lock(ctx, tx, "user", n.Submitter); err != nil {
				return err
			}
			if err := lock(ctx, tx, "vuln", n.CVE); err != nil {
				return err
			}
			now := s.now() // after the locks
			var created time.Time
			var contributions, daily int64
			var oldest *time.Time
			if err := tx.QueryRow(ctx, `SELECT u.created_at,
					(SELECT count(*) FROM (SELECT 1 FROM comments WHERE author_id = u.id AND status = 'visible' LIMIT $3) v)
					+ (SELECT count(*) FROM (SELECT 1 FROM vuln_corrections WHERE submitter_id = u.id AND status = 'accepted' LIMIT $3) a),
					(SELECT count(*) FROM vuln_corrections WHERE submitter_id = u.id AND created_at > $2),
					(SELECT min(created_at) FROM vuln_corrections WHERE submitter_id = u.id AND created_at > $2)
				FROM users u WHERE u.id = $1::uuid`, n.Submitter, now.Add(-24*time.Hour), max(nl.NewAccountComments, 0)).Scan(
				&created, &contributions, &daily, &oldest); err != nil {
				return err
			}
			newAcct := discuss.IsNewAccount(created, int(contributions), now, nl)
			dailyCap, userCap := lim.Daily, lim.OpenPerUser
			if newAcct {
				dailyCap, userCap = min(dailyCap, nl.NewPostDaily), min(userCap, NewAccountOpenPerUser)
			}
			if daily >= int64(dailyCap) {
				wait := time.Hour
				if oldest != nil {
					wait = oldest.Add(24 * time.Hour).Sub(now)
				}
				return &LimitError{Code: "daily_limit", RetryAfter: max(wait, time.Second)}
			}
			// The vulnerability's cap counts only open corrections of
			// submitters who still have an account and are not suspended now
			// (auth.User.EffectiveStatus: an elapsed suspension counts as
			// active), so accounts that filled the queue and were then
			// suspended or deleted do not keep it full.
			var mine, all int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE c.submitter_id = $2::uuid),
					count(*) FILTER (WHERE u.id IS NOT NULL AND NOT `+site.SuspendedNowSQL("u", "$3")+`)
				FROM vuln_corrections c LEFT JOIN users u ON u.id = c.submitter_id
				WHERE c.cve_id = $1 AND c.status = 'pending'`, n.CVE, n.Submitter, now).Scan(&mine, &all); err != nil {
				return err
			}
			if mine >= int64(userCap) {
				return ErrUserOpen
			}
			if all >= int64(lim.OpenPerVuln) {
				return ErrVulnOpen
			}
			var err error
			out, err = scan(tx.QueryRow(ctx, `INSERT INTO vuln_corrections (cve_id, submitter_id, category, body, evidence_url, created_at)
				SELECT v.cve_id, $2::uuid, $3, $4, $5, $6 FROM vuln v WHERE v.cve_id = $1
				RETURNING `+cols, n.CVE, n.Submitter, n.Category, n.Body, n.EvidenceURL, now))
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoVuln
			}
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Mine lists user's corrections, newest first (at most MineMax), of one
// vulnerability when cve is not "".
func (s *Store) Mine(ctx context.Context, user, cve string) ([]*Correction, error) {
	var out []*Correction
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+cols+` FROM vuln_corrections WHERE submitter_id = $1::uuid AND ($2 = '' OR cve_id = $2)
			ORDER BY created_at DESC, id DESC LIMIT $3`, user, cve, MineMax)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// decide changes a pending correction to status (with its note) and writes
// the audit row, in one transaction. Not pending: ErrWrongStatus; unknown:
// ErrNotFound.
func (s *Store) decide(ctx context.Context, id, moderator, status string, publicNote, internalNote *string) (*Correction, error) {
	var out *Correction
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			// the row lock first, then the time: concurrent decisions on one
			// row are serialised and the later one sees it decided
			var cur string
			err := tx.QueryRow(ctx, `SELECT status FROM vuln_corrections WHERE id = $1::uuid FOR UPDATE`, id).Scan(&cur)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return ErrNotFound
			case err != nil:
				return err
			case cur != StatusPending:
				return ErrWrongStatus
			}
			now := s.now()
			if out, err = scan(tx.QueryRow(ctx, `UPDATE vuln_corrections SET status = $2, decided_at = $3, decided_by = $4::uuid,
					public_note = $5, internal_note = $6
				WHERE id = $1::uuid AND status = 'pending' RETURNING `+cols, id, status, now, moderator, publicNote, internalNote)); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrWrongStatus
				}
				return err
			}
			e := audit.Entry{ActorID: &moderator, Action: audit.CorrectionAccept, TargetType: audit.TargetCorrection, TargetID: out.ID,
				TargetLabel: audit.Excerpt(out.CVE+" "+out.Body, audit.MaxLabel),
				Details:     map[string]any{"cve": out.CVE, "category": out.Category}}
			if status == StatusAccepted {
				// reason is cut to audit.MaxReason (500) characters; the
				// note may have MaxPublicNote (1000): details keep it whole
				e.Reason = *publicNote
				e.Details["public_note"] = *publicNote
			} else {
				e.Action = audit.CorrectionReject
				if internalNote != nil {
					e.Reason = *internalNote
				}
			}
			return audit.Write(ctx, tx, e)
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Accept accepts a pending correction with the public note an editor wrote.
func (s *Store) Accept(ctx context.Context, id, moderator, publicNote string) (*Correction, error) {
	return s.decide(ctx, id, moderator, StatusAccepted, &publicNote, nil)
}

// Reject rejects a pending correction, with an optional internal note.
func (s *Store) Reject(ctx context.Context, id, moderator string, internalNote *string) (*Correction, error) {
	return s.decide(ctx, id, moderator, StatusRejected, nil, internalNote)
}
