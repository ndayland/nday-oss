package discuss

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
)

// Store is the discussion database layer (tables of migrations/0005). Every
// multi-step change runs in one transaction; permission conditions are part
// of the writing statement (conditional UPDATE / INSERT ... SELECT), so there
// is no gap between a check and the write. Timestamps are taken after the
// row locks are held, and every UPDATE of a comment increments its rev.
type Store struct {
	// DB is the writable pool: every write, and every read that must see
	// the caller's own writes (signed-in views, moderator lists).
	DB auth.ConnSource
	// ReadDB, if set, serves the public, caller-independent reads (the
	// anonymous stream, Stream/StreamPage/Version, the vulnerability
	// check): `nday serve` passes the site's read-only pool, so a read flood
	// cannot take the write pool's connections. nil: DB.
	ReadDB auth.ConnSource
	Now    func() time.Time
}

func (s *Store) read() auth.ConnSource {
	if s.ReadDB != nil {
		return s.ReadDB
	}
	return s.DB
}

// readFor is the pool for a read on behalf of viewer (nil = anonymous).
func (s *Store) readFor(viewer *string) auth.ConnSource {
	if viewer == nil {
		return s.read()
	}
	return s.DB
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Store errors.
var (
	ErrNotFound     = errors.New("no such comment")
	ErrNoVuln       = errors.New("no such vulnerability")
	ErrNotAuthor    = errors.New("only the author can do this")
	ErrWrongStatus  = errors.New("the comment's status does not allow this")
	ErrBadParent    = errors.New("replies must answer a visible top-level comment of the same vulnerability")
	ErrThreadFull   = errors.New("this thread has reached its reply limit")
	ErrDuplicate    = errors.New("you posted the same comment here a moment ago")
	ErrOwnComment   = errors.New("you cannot report your own comment")
	ErrReportClosed = errors.New("this report is already resolved")
	ErrBadPurpose   = errors.New("purpose must be one of " + strings.Join(Purposes, ", ") + ", and only on a top-level comment")
)

// Purposes are the purposes a top-level comment may declare (comments.purpose,
// migrations/0016_comment_purpose.sql); replies have none.
var Purposes = []string{"analysis", "reproduction", "fix", "detection", "question"}

// ValidPurpose reports whether p is one of Purposes.
func ValidPurpose(p string) bool {
	for _, x := range Purposes {
		if p == x {
			return true
		}
	}
	return false
}

// LimitError is a refused write because of a limit; RetryAfter is how long
// until it would pass.
type LimitError struct {
	Code       string // "daily_limit" or "rate_limited"
	RetryAfter time.Duration
}

func (e *LimitError) Error() string { return "discuss: " + e.Code }

// Author is the public part of a user.
type Author struct {
	Handle      *string `json:"handle"`
	DisplayName *string `json:"display_name"`
	Role        string  `json:"role"`
}

// Row is a comment as stored, with its author's public fields.
type Row struct {
	ID           string
	CVE          string
	ParentID     *string
	AuthorID     *string
	Author       *Author // nil when the account was deleted
	Body         string
	Lang         string
	Links        bool
	Status       string
	CreatedAt    time.Time
	EditedAt     *time.Time
	DeletedAt    *time.Time
	UpdatedAt    time.Time
	HiddenAt     *time.Time
	HiddenByID   *string
	HiddenBy     *Author
	HiddenReason *string
	OpenReports  int
	Replies      int  // replies of a top-level comment (all statuses)
	LiveReplies  int  // replies of a top-level comment that are not deleted
	Reported     bool // the viewer has an open report on it
	Rev          int64
	Revisions    int     // stored previous bodies (comment_revisions)
	Purpose      *string // top-level comments only: one of Purposes, nil = none
}

// Statuses.
const (
	StatusVisible = "visible"
	StatusHidden  = "hidden"
	StatusDeleted = "deleted"
)

// rowCols / rowFrom select a Row; $1 is the viewer's user id (or NULL).
const rowCols = `c.id::text, c.cve_id, c.parent_id::text, c.author_id::text, u.handle, u.display_name, u.role,
	c.body, c.lang, c.links, c.status, c.created_at, c.edited_at, c.deleted_at, c.updated_at,
	c.hidden_at, c.hidden_by::text, h.handle, h.display_name, h.role, c.hidden_reason,
	(SELECT count(*) FROM comment_reports rr WHERE rr.comment_id = c.id AND rr.resolved_at IS NULL),
	(CASE WHEN c.parent_id IS NULL THEN (SELECT count(*) FROM comments x WHERE x.parent_id = c.id) ELSE 0 END),
	(CASE WHEN c.parent_id IS NULL THEN (SELECT count(*) FROM comments x WHERE x.parent_id = c.id AND x.status <> 'deleted') ELSE 0 END),
	EXISTS (SELECT 1 FROM comment_reports rv WHERE rv.comment_id = c.id AND rv.resolved_at IS NULL AND rv.reporter_id = $1::uuid),
	c.rev, (SELECT count(*) FROM comment_revisions cr WHERE cr.comment_id = c.id), c.purpose`

const rowFrom = ` FROM comments c LEFT JOIN users u ON u.id = c.author_id LEFT JOIN users h ON h.id = c.hidden_by `

func scanRow(row pgx.Row, extra ...any) (*Row, error) {
	r := &Row{}
	var ah, ad, ar, hh, hd, hr *string
	var open, replies, live, revs int64
	dst := append([]any{&r.ID, &r.CVE, &r.ParentID, &r.AuthorID, &ah, &ad, &ar,
		&r.Body, &r.Lang, &r.Links, &r.Status, &r.CreatedAt, &r.EditedAt, &r.DeletedAt, &r.UpdatedAt,
		&r.HiddenAt, &r.HiddenByID, &hh, &hd, &hr, &r.HiddenReason, &open, &replies, &live, &r.Reported,
		&r.Rev, &revs, &r.Purpose}, extra...)
	if err := row.Scan(dst...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.OpenReports, r.Replies, r.LiveReplies, r.Revisions = int(open), int(replies), int(live), int(revs)
	if r.AuthorID != nil && ar != nil {
		r.Author = &Author{Handle: ah, DisplayName: ad, Role: *ar}
	}
	if r.HiddenByID != nil && hr != nil {
		r.HiddenBy = &Author{Handle: hh, DisplayName: hd, Role: *hr}
	}
	return r, nil
}

func collectRows(rows pgx.Rows) ([]*Row, error) {
	defer rows.Close()
	var out []*Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getRow(ctx context.Context, q querier, viewer *string, id string) (*Row, error) {
	return scanRow(q.QueryRow(ctx, `SELECT `+rowCols+rowFrom+`WHERE c.id = $2::uuid`, viewer, id))
}

// Get loads one comment as seen by viewer (nil = anonymous; the viewer only
// matters for Row.Reported).
func (s *Store) Get(ctx context.Context, viewer *string, id string) (*Row, error) {
	var r *Row
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		r, err = getRow(ctx, c, viewer, id)
		return err
	})
	return r, err
}

// VulnExists reports whether cve is a known vulnerability.
func (s *Store) VulnExists(ctx context.Context, cve string) (bool, error) {
	var ok bool
	err := s.read().WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln WHERE cve_id = $1)`, cve).Scan(&ok)
	})
	return ok, err
}

// Cursor is a position in an ordered list: (time, id).
type Cursor struct {
	At time.Time
	ID string
}

const nilUUID = "00000000-0000-0000-0000-000000000000"

// Page is one page of a vulnerability's stream.
type Page struct {
	Top     []*Row
	Replies map[string][]*Row // by parent id, oldest first
	Next    *Cursor           // nil: no more top-level comments
	Visible int               // visible comments of the vulnerability (all pages)
}

// Page loads up to limit top-level comments after cursor (nil = from the
// start), oldest first, with their non-deleted replies. A deleted top-level
// comment is included only while it has a non-deleted reply; deleted
// replies are never included. The page stops early once it would hold more
// than PageMaxComments comments (it always holds at least one thread), and
// only the replies of the threads it keeps are fetched: at most limit+1
// top-level rows and PageMaxComments+MaxReplies replies are ever read. The
// byte budget (PageMaxHTMLBytes) is applied by the service after rendering.
// Anonymous pages (viewer nil) are read from ReadDB.
func (s *Store) Page(ctx context.Context, viewer *string, cve string, after *Cursor, limit int) (*Page, error) {
	if limit <= 0 || limit > PageMax {
		limit = PageDefault
	}
	cur := Cursor{ID: nilUUID}
	if after != nil {
		cur = *after
	}
	p := &Page{Replies: map[string][]*Row{}}
	err := s.readFor(viewer).WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+rowCols+rowFrom+`WHERE c.cve_id = $2 AND c.parent_id IS NULL
			AND (c.status <> 'deleted' OR EXISTS (SELECT 1 FROM comments x WHERE x.parent_id = c.id AND x.status <> 'deleted'))
			AND (c.created_at, c.id) > ($3, $4::uuid)
			ORDER BY c.created_at, c.id LIMIT $5`, viewer, cve, cur.At, cur.ID, limit+1)
		if err != nil {
			return err
		}
		top, err := collectRows(rows)
		if err != nil {
			return err
		}
		more := len(top) > limit
		if more {
			top = top[:limit]
		}
		total := 0
		for i, t := range top {
			n := 1 + t.LiveReplies
			if i > 0 && total+n > PageMaxComments {
				more = true
				break
			}
			total += n
			p.Top = append(p.Top, t)
		}
		if more && len(p.Top) > 0 {
			last := p.Top[len(p.Top)-1]
			p.Next = &Cursor{At: last.CreatedAt, ID: last.ID}
		}
		ids := make([]string, len(p.Top))
		for i, t := range p.Top {
			ids[i] = t.ID
		}
		if len(ids) > 0 {
			rows, err = c.Query(ctx, `SELECT `+rowCols+rowFrom+`WHERE c.parent_id = ANY($2::uuid[]) AND c.status <> 'deleted'
				ORDER BY c.parent_id, c.created_at, c.id LIMIT $3`, viewer, ids, PageMaxComments+MaxReplies)
			if err != nil {
				return err
			}
			reps, err := collectRows(rows)
			if err != nil {
				return err
			}
			for _, r := range reps {
				p.Replies[*r.ParentID] = append(p.Replies[*r.ParentID], r)
			}
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM comments WHERE cve_id = $1 AND status = 'visible'`, cve).Scan(&p.Visible)
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Visible counts the visible comments of cve.
func (s *Store) Visible(ctx context.Context, viewer *string, cve string) (int, error) {
	var n int
	err := s.readFor(viewer).WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM comments WHERE cve_id = $1 AND status = 'visible'`, cve).Scan(&n)
	})
	return n, err
}

// Thread loads one top-level comment of cve and up to MaxReplies of its
// non-deleted replies after cursor (nil = from the first), oldest first
// (the continuation of a thread cut by the page byte budget). ErrNotFound
// when id is not a top-level comment of cve (or a deleted one without
// replies).
func (s *Store) Thread(ctx context.Context, viewer *string, cve, id string, after *Cursor) (*Row, []*Row, error) {
	cur := Cursor{ID: nilUUID}
	if after != nil {
		cur = *after
	}
	var top *Row
	var reps []*Row
	err := s.readFor(viewer).WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		top, err = scanRow(c.QueryRow(ctx, `SELECT `+rowCols+rowFrom+`WHERE c.id = $2::uuid AND c.cve_id = $3 AND c.parent_id IS NULL
			AND (c.status <> 'deleted' OR EXISTS (SELECT 1 FROM comments x WHERE x.parent_id = c.id AND x.status <> 'deleted'))`,
			viewer, id, cve))
		if err != nil {
			return err
		}
		rows, err := c.Query(ctx, `SELECT `+rowCols+rowFrom+`WHERE c.parent_id = $2::uuid AND c.status <> 'deleted'
			AND (c.created_at, c.id) > ($3, $4::uuid) ORDER BY c.created_at, c.id LIMIT $5`, viewer, id, cur.At, cur.ID, MaxReplies)
		if err != nil {
			return err
		}
		reps, err = collectRows(rows)
		return err
	})
	return top, reps, err
}

// Version is a value that changes with every committed change a rendered
// page shows, independent of any clock: it digests, in id order, every
// comment's (id, rev, status) — rev is incremented by every UPDATE — and
// its author's handle, display name and role, or that the author account
// is gone. A comment of another vulnerability never changes it. Cost: one
// indexed pass over the vulnerability's comments (read from ReadDB).
func (s *Store) Version(ctx context.Context, cve string) (string, error) {
	var n int64
	var digest string
	err := s.read().WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*),
				coalesce(md5(string_agg(c.id::text || ':' || c.rev || ':' || c.status || ':' || (c.author_id IS NULL)::text
					|| ':' || coalesce(u.role, '') || ':' || coalesce(u.handle, '') || ':' || coalesce(u.display_name, ''), ',' ORDER BY c.id)), '')
			FROM comments c LEFT JOIN users u ON u.id = c.author_id WHERE c.cve_id = $1`, cve).Scan(&n, &digest)
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("d2-%d-%s", n, digest), nil
}

// NewAccount reports whether user counts as a new account (younger than
// l.NewAccountAge, or fewer than l.NewAccountComments visible comments).
func (s *Store) NewAccount(ctx context.Context, user string, l Limits) (bool, error) {
	var created time.Time
	var visible int64
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT u.created_at,
				(SELECT count(*) FROM (SELECT 1 FROM comments WHERE author_id = u.id AND status = 'visible' LIMIT $2) v)
			FROM users u WHERE u.id = $1::uuid`, user, l.NewAccountComments).Scan(&created, &visible)
	})
	if err != nil {
		return false, err
	}
	return isNew(created, int(visible), s.now(), l), nil
}

func isNew(created time.Time, visible int, now time.Time, l Limits) bool {
	return now.Sub(created) < l.NewAccountAge || visible < l.NewAccountComments
}

// IsNewAccount is the rule of NewAccount for other writers (readers'
// corrections, internal/corrections): an account created at created, with
// contributions counted against l.NewAccountComments, is new at now while
// younger than l.NewAccountAge or with fewer contributions than that.
func IsNewAccount(created time.Time, contributions int, now time.Time, l Limits) bool {
	return isNew(created, contributions, now, l)
}

// NewComment is a comment to create. Body must already be normalised
// (NormalizeBody) and Lang an enabled locale tag.
type NewComment struct {
	CVE    string
	Parent *string
	Author string
	Body   string
	Lang   string
	// Purpose: one of Purposes or nil; a reply with a purpose is refused
	// (ErrBadPurpose).
	Purpose *string
}

// Gate is called inside Create's transaction, after the daily cap and the
// duplicate guard passed and before the insert, with whether the author
// counts as new; a non-nil error aborts the create (rate limits).
type Gate func(newAccount bool) error

func userLock(ctx context.Context, tx pgx.Tx, kind, user string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "nday.discuss."+kind+":"+user)
	return err
}

// Create inserts a comment. In one transaction, serialised per author
// (advisory lock): the rolling 24-hour cap (PostDaily, or NewPostDaily for
// new accounts) -> *LimitError "daily_limit"; the duplicate guard (same
// author, vulnerability and body within DuplicateWindow, not deleted) ->
// ErrDuplicate; gate; then an INSERT ... SELECT that itself requires the
// vulnerability to exist (ErrNoVuln) and the parent, if any, to be a visible
// top-level comment of the same vulnerability, locked FOR SHARE until commit
// (ErrBadParent), with fewer than MaxReplies replies (ErrThreadFull; exact:
// replies to one thread are serialised by an advisory lock). It
// returns the new row and whether the author counted as new (then
// links=false).
func (s *Store) Create(ctx context.Context, in NewComment, l Limits, gate Gate) (*Row, bool, error) {
	if in.Purpose != nil && (in.Parent != nil || !ValidPurpose(*in.Purpose)) {
		return nil, false, ErrBadPurpose
	}
	var out *Row
	var newAcct bool
	gate = gateOnce(gate) // a retried transaction must not count twice
	err := withConnRetry(ctx, s.DB, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if err := userLock(ctx, tx, "post", in.Author); err != nil {
				return err
			}
			// Replies to one thread are serialised (always after the author
			// lock, so the order is fixed): the INSERT's snapshot, taken after
			// this lock, sees every committed reply, so the MaxReplies cap is
			// exact.
			if in.Parent != nil {
				if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
					"nday.discuss.thread:"+*in.Parent); err != nil {
					return err
				}
			}
			now := s.now() // after the locks
			var created time.Time
			var visible, daily int64
			var oldest *time.Time
			var dup bool
			dayAgo := now.Add(-24 * time.Hour)
			if err := tx.QueryRow(ctx, `SELECT u.created_at,
					(SELECT count(*) FROM (SELECT 1 FROM comments WHERE author_id = u.id AND status = 'visible' LIMIT $2) v),
					(SELECT count(*) FROM comments WHERE author_id = u.id AND created_at > $3),
					(SELECT min(created_at) FROM comments WHERE author_id = u.id AND created_at > $3),
					EXISTS (SELECT 1 FROM comments WHERE author_id = u.id AND cve_id = $4 AND body = $5
						AND status <> 'deleted' AND created_at > $6)
				FROM users u WHERE u.id = $1::uuid`, in.Author, l.NewAccountComments, dayAgo, in.CVE, in.Body,
				now.Add(-l.DuplicateWindow)).Scan(&created, &visible, &daily, &oldest, &dup); err != nil {
				return err
			}
			newAcct = isNew(created, int(visible), now, l)
			limit := l.PostDaily
			if newAcct {
				limit = l.NewPostDaily
			}
			if daily >= int64(limit) {
				wait := time.Hour
				if oldest != nil {
					wait = oldest.Add(24 * time.Hour).Sub(now)
				}
				return &LimitError{Code: "daily_limit", RetryAfter: max(wait, time.Second)}
			}
			if dup {
				return ErrDuplicate
			}
			if gate != nil {
				if err := gate(newAcct); err != nil {
					return err
				}
			}
			var id string
			err := tx.QueryRow(ctx, `WITH p AS (
					SELECT id FROM comments WHERE id = $2::uuid AND cve_id = $1 AND parent_id IS NULL AND status = 'visible'
					FOR SHARE)
				INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links, created_at, updated_at, purpose)
				SELECT v.cve_id, $2::uuid, $2::uuid IS NOT NULL, $3::uuid, $4, $5, $6, $7, $7, $9 FROM vuln v
				WHERE v.cve_id = $1 AND ($2::uuid IS NULL OR (EXISTS (SELECT 1 FROM p)
					AND (SELECT count(*) FROM comments x WHERE x.parent_id = $2::uuid) < $8))
				RETURNING id::text`, in.CVE, in.Parent, in.Author, in.Body, in.Lang, !newAcct, now, MaxReplies, in.Purpose).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				var vuln, parentOK bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln WHERE cve_id = $1),
						EXISTS (SELECT 1 FROM comments WHERE id = $2::uuid AND cve_id = $1 AND parent_id IS NULL AND status = 'visible')`,
					in.CVE, in.Parent).Scan(&vuln, &parentOK); err != nil {
					return err
				}
				switch {
				case !vuln:
					return ErrNoVuln
				case !parentOK:
					return ErrBadParent
				}
				return ErrThreadFull
			}
			if err != nil {
				return err
			}
			out, err = getRow(ctx, tx, &in.Author, id)
			return err
		})
	})
	if vulnGone(err) {
		err = ErrNoVuln
	}
	return out, newAcct, err
}

// vulnGone: err is a foreign-key violation saying the vulnerability went
// away while the transaction waited for its row (docs/ghsa.md: the merge
// that moves a GHSA-keyed vulnerability under its CVE deletes the row and
// moves the threads), on the vuln reference or on a parent that moved with
// its thread.
func vulnGone(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503" &&
		(pe.ConstraintName == "comments_cve_id_fkey" || pe.ConstraintName == "comments_parent_fk")
}

// withConnRetry is db.WithConn(ctx, f), run once more when f fails with
// deadlock_detected (40P01): its transaction was rolled back whole, so the
// retry starts over.
func withConnRetry(ctx context.Context, db auth.ConnSource, f func(*pgx.Conn) error) error {
	err := db.WithConn(ctx, f)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "40P01" {
		err = db.WithConn(ctx, f)
	}
	return err
}

// gateOnce calls gate at most once and repeats its answer.
func gateOnce(gate Gate) Gate {
	if gate == nil {
		return nil
	}
	called := false
	var res error
	return func(newAccount bool) error {
		if !called {
			called, res = true, gate(newAccount)
		}
		return res
	}
}

// diagnose explains why a conditional write matched no row: ErrNotFound,
// ErrNotAuthor (author != "" and not the comment's author) or ErrWrongStatus.
func diagnose(ctx context.Context, q querier, id, author string) error {
	var owner *string
	err := q.QueryRow(ctx, `SELECT author_id::text FROM comments WHERE id = $1::uuid`, id).Scan(&owner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case author != "" && (owner == nil || *owner != author):
		return ErrNotAuthor
	}
	return ErrWrongStatus
}

// Edit replaces the body of the author's visible comment (the purpose is
// kept): EditComment with only a body.
func (s *Store) Edit(ctx context.Context, id, author, body string) (r *Row, changed bool, err error) {
	return s.EditComment(ctx, id, author, EditInput{Body: body})
}

// EditInput is an edit of a comment.
type EditInput struct {
	Body string // normalised (NormalizeBody)
	// SetPurpose: replace the purpose with Purpose (nil = none); otherwise
	// the purpose is kept. A purpose on a reply is refused (ErrBadPurpose).
	SetPurpose bool
	Purpose    *string
}

// EditComment replaces the body (and, with SetPurpose, the purpose) of the
// author's visible comment; the previous body and purpose are kept together
// in one comment_revisions row. The row is locked FOR UPDATE and the UPDATE
// repeats the author and status conditions. changed is false (and nothing
// is written) when neither the body nor the purpose changes.
func (s *Store) EditComment(ctx context.Context, id, author string, in EditInput) (r *Row, changed bool, err error) {
	if in.SetPurpose && in.Purpose != nil && !ValidPurpose(*in.Purpose) {
		return nil, false, ErrBadPurpose
	}
	body := in.Body
	err = s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var old string
			var oldPurpose, parent *string
			err := tx.QueryRow(ctx, `SELECT body, purpose, parent_id::text FROM comments WHERE id = $1::uuid AND author_id = $2::uuid AND status = 'visible'
				FOR UPDATE`, id, author).Scan(&old, &oldPurpose, &parent)
			if errors.Is(err, pgx.ErrNoRows) {
				return diagnose(ctx, tx, id, author)
			}
			if err != nil {
				return err
			}
			purpose := oldPurpose
			if in.SetPurpose {
				if in.Purpose != nil && parent != nil {
					return ErrBadPurpose
				}
				purpose = in.Purpose
			}
			now := s.now() // after the row lock
			if old != body || !samePurpose(oldPurpose, purpose) {
				if _, err := tx.Exec(ctx, `INSERT INTO comment_revisions (comment_id, body, purpose, replaced_at) VALUES ($1::uuid, $2, $3, $4)`,
					id, old, oldPurpose, now); err != nil {
					return err
				}
				tag, err := tx.Exec(ctx, `UPDATE comments SET body = $3, purpose = $5, edited_at = $4, updated_at = $4, rev = rev + 1
					WHERE id = $1::uuid AND author_id = $2::uuid AND status = 'visible'`, id, author, body, now, purpose)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return ErrWrongStatus
				}
				changed = true
			}
			r, err = getRow(ctx, tx, &author, id)
			return err
		})
	})
	return r, changed, err
}

func samePurpose(a, b *string) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// lockedUpdate runs, in one transaction: lock the comment if cond holds
// (SELECT ... FOR UPDATE; else diagnose with author), take the time, then
// the UPDATE (whose WHERE repeats cond; set must bump rev) with $1 = id, $2
// = the time and args from $3. In cond, "$A" is the author parameter (the
// first of args in the UPDATE). after runs in the same transaction.
func (s *Store) lockedUpdate(ctx context.Context, id, author, cond string, condArgs []any, set string, args []any,
	after func(tx pgx.Tx, now time.Time) error) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var got string
			err := tx.QueryRow(ctx, `SELECT id::text FROM comments WHERE id = $1::uuid AND `+strings.ReplaceAll(cond, "$A", "$2")+` FOR UPDATE`,
				append([]any{id}, condArgs...)...).Scan(&got)
			if errors.Is(err, pgx.ErrNoRows) {
				return diagnose(ctx, tx, id, author)
			}
			if err != nil {
				return err
			}
			now := s.now() // after the row lock
			tag, err := tx.Exec(ctx, `UPDATE comments SET `+set+` WHERE id = $1::uuid AND `+strings.ReplaceAll(cond, "$A", "$3"),
				append([]any{id, now}, args...)...)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrWrongStatus
			}
			return after(tx, now)
		})
	})
}

// Delete soft-deletes the author's visible or hidden comment.
func (s *Store) Delete(ctx context.Context, id, author string) (*Row, error) {
	var r *Row
	err := s.lockedUpdate(ctx, id, author, `author_id = $A::uuid AND status IN ('visible', 'hidden')`, []any{author},
		`status = 'deleted', deleted_at = $2, updated_at = $2, rev = rev + 1`, []any{author},
		func(tx pgx.Tx, _ time.Time) error {
			var err error
			r, err = getRow(ctx, tx, &author, id)
			return err
		})
	return r, err
}

// Hide hides a visible comment (moderator nil = the CLI) and resolves its
// open reports with resolution "hidden", in one transaction. A report
// committed before the hide took the row lock is resolved here; one that
// waits for the lock (AddReport locks the comment FOR SHARE) then sees the
// hidden status and is refused.
func (s *Store) Hide(ctx context.Context, id string, moderator *string, reason string) (*Row, int64, error) {
	var r *Row
	var resolved int64
	err := s.lockedUpdate(ctx, id, "", `status = 'visible'`, nil,
		`status = 'hidden', hidden_at = $2, hidden_by = $3::uuid, hidden_reason = $4, updated_at = $2, rev = rev + 1`,
		[]any{moderator, reason},
		func(tx pgx.Tx, now time.Time) error {
			tag, err := tx.Exec(ctx, `UPDATE comment_reports SET resolved_at = $3, resolved_by = $2::uuid, resolution = 'hidden'
				WHERE comment_id = $1::uuid AND resolved_at IS NULL`, id, moderator, now)
			if err != nil {
				return err
			}
			resolved = tag.RowsAffected()
			if r, err = getRow(ctx, tx, moderator, id); err != nil {
				return err
			}
			return audit.Write(ctx, tx, commentEntry(audit.CommentHide, moderator, r, reason,
				map[string]any{"cve": r.CVE, "resolved_reports": resolved}))
		})
	return r, resolved, err
}

// commentEntry is the audit row of a moderation action on comment r
// (moderator nil = the CLI); the label is a plain-text excerpt of the body.
func commentEntry(action string, moderator *string, r *Row, reason string, details map[string]any) audit.Entry {
	return audit.Entry{ActorID: moderator, Action: action, TargetType: audit.TargetComment, TargetID: r.ID,
		TargetLabel: audit.Excerpt(r.Body, audit.MaxLabel), Reason: reason, Details: details}
}

// Unhide makes a hidden comment visible again (clearing the hide fields).
func (s *Store) Unhide(ctx context.Context, id string, moderator *string) (*Row, error) {
	var r *Row
	err := s.lockedUpdate(ctx, id, "", `status = 'hidden'`, nil,
		`status = 'visible', hidden_at = NULL, hidden_by = NULL, hidden_reason = NULL, updated_at = $2, rev = rev + 1`, nil,
		func(tx pgx.Tx, _ time.Time) error {
			var err error
			if r, err = getRow(ctx, tx, moderator, id); err != nil {
				return err
			}
			return audit.Write(ctx, tx, commentEntry(audit.CommentUnhide, moderator, r, "", map[string]any{"cve": r.CVE}))
		})
	return r, err
}

// Revision is an earlier body of a comment, with the purpose it had then
// (nil: none, a reply, or an edit made before purposes existed).
type Revision struct {
	Body       string    `json:"body"`
	Purpose    *string   `json:"purpose"`
	ReplacedAt time.Time `json:"replaced_at"`
}

// MaxRevisions is how many revisions Revisions returns (newest first).
const MaxRevisions = 200

// Revisions lists a comment's earlier bodies, newest first (ErrNotFound
// for an unknown comment).
func (s *Store) Revisions(ctx context.Context, id string) ([]Revision, error) {
	out := []Revision{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var ok bool
		if err := c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM comments WHERE id = $1::uuid)`, id).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		rows, err := c.Query(ctx, `SELECT body, purpose, replaced_at FROM comment_revisions WHERE comment_id = $1::uuid
			ORDER BY replaced_at DESC, id DESC LIMIT $2`, id, MaxRevisions)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rv Revision
			if err := rows.Scan(&rv.Body, &rv.Purpose, &rv.ReplacedAt); err != nil {
				return err
			}
			rv.ReplacedAt = rv.ReplacedAt.UTC()
			out = append(out, rv)
		}
		return rows.Err()
	})
	return out, err
}

// Report reasons.
var ReportReasons = []string{"spam", "abuse", "off_topic", "misinformation", "malicious_link", "illegal", "other"}

// Report is a report with its comment.
type Report struct {
	ID         string     `json:"id"`
	Reason     string     `json:"reason"`
	Note       *string    `json:"note"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Resolution *string    `json:"resolution"`
	Reporter   *Author    `json:"reporter"`
	ResolvedBy *Author    `json:"resolved_by"`
	Comment    *Row       `json:"-"`
}

func (r *Report) utc() {
	r.CreatedAt = r.CreatedAt.UTC()
	r.ResolvedAt = utc(r.ResolvedAt)
}

// AddReport records reporter's report on a visible comment of someone else.
// Idempotent: while the reporter has an open report on the comment, that
// report is returned with already=true and nothing is written. Otherwise
// the rolling 24-hour cap (daily) applies (*LimitError "daily_limit").
func (s *Store) AddReport(ctx context.Context, id, reporter, reason string, note *string, daily int) (rep *Report, already bool, err error) {
	err = s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if err := userLock(ctx, tx, "report", reporter); err != nil {
				return err
			}
			var owner *string
			var status string
			// FOR SHARE: a concurrent Hide either commits first (then the
			// status read here is "hidden") or waits until this report is
			// committed (then it resolves it).
			err := tx.QueryRow(ctx, `SELECT author_id::text, status FROM comments WHERE id = $1::uuid FOR SHARE`, id).Scan(&owner, &status)
			now := s.now() // after the locks
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return ErrNotFound
			case err != nil:
				return err
			case owner != nil && *owner == reporter:
				return ErrOwnComment
			case status != StatusVisible:
				return ErrWrongStatus
			}
			rep = &Report{}
			err = tx.QueryRow(ctx, `SELECT id::text, reason, note, created_at FROM comment_reports
				WHERE comment_id = $1::uuid AND reporter_id = $2::uuid AND resolved_at IS NULL`, id, reporter).
				Scan(&rep.ID, &rep.Reason, &rep.Note, &rep.CreatedAt)
			if err == nil {
				already = true
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			var n int64
			var oldest *time.Time
			if err := tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM comment_reports
				WHERE reporter_id = $1::uuid AND created_at > $2`, reporter, now.Add(-24*time.Hour)).Scan(&n, &oldest); err != nil {
				return err
			}
			if n >= int64(daily) {
				wait := time.Hour
				if oldest != nil {
					wait = oldest.Add(24 * time.Hour).Sub(now)
				}
				return &LimitError{Code: "daily_limit", RetryAfter: max(wait, time.Second)}
			}
			return tx.QueryRow(ctx, `INSERT INTO comment_reports (comment_id, reporter_id, reason, note, created_at)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5) RETURNING id::text, reason, note, created_at`,
				id, reporter, reason, note, now).Scan(&rep.ID, &rep.Reason, &rep.Note, &rep.CreatedAt)
		})
	})
	if rep != nil {
		rep.utc()
	}
	return rep, already, err
}

const reportCols = `r.id::text, r.reason, r.note, r.created_at, r.resolved_at, r.resolution,
	r.reporter_id::text, ru.handle, ru.display_name, ru.role, r.resolved_by::text, rb.handle, rb.display_name, rb.role`

const reportFrom = ` FROM comment_reports r JOIN comments c ON c.id = r.comment_id
	LEFT JOIN users u ON u.id = c.author_id LEFT JOIN users h ON h.id = c.hidden_by
	LEFT JOIN users ru ON ru.id = r.reporter_id LEFT JOIN users rb ON rb.id = r.resolved_by `

func scanReport(row pgx.Row) (*Report, error) {
	rep := &Report{}
	var rid, rh, rd, rr, bid, bh, bd, br *string
	c, err := scanRow(row, &rep.ID, &rep.Reason, &rep.Note, &rep.CreatedAt, &rep.ResolvedAt, &rep.Resolution,
		&rid, &rh, &rd, &rr, &bid, &bh, &bd, &br)
	if err != nil {
		return nil, err
	}
	rep.Comment = c
	rep.utc()
	if rid != nil && rr != nil {
		rep.Reporter = &Author{Handle: rh, DisplayName: rd, Role: *rr}
	}
	if bid != nil && br != nil {
		rep.ResolvedBy = &Author{Handle: bh, DisplayName: bd, Role: *br}
	}
	return rep, nil
}

// Reports lists open reports oldest first, or resolved reports most
// recently resolved first, after cursor, at most limit (1..ModPageMax).
func (s *Store) Reports(ctx context.Context, viewer *string, open bool, after *Cursor, limit int) ([]*Report, *Cursor, error) {
	if limit <= 0 || limit > ModPageMax {
		limit = ModPageMax
	}
	q := `SELECT ` + rowCols + `, ` + reportCols + reportFrom
	var args []any
	if open {
		cur := Cursor{ID: nilUUID}
		if after != nil {
			cur = *after
		}
		q += `WHERE r.resolved_at IS NULL AND (r.created_at, r.id) > ($2, $3::uuid) ORDER BY r.created_at, r.id LIMIT $4`
		args = []any{viewer, cur.At, cur.ID, limit + 1}
	} else {
		cur := Cursor{At: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}
		if after != nil {
			cur = *after
		}
		q += `WHERE r.resolved_at IS NOT NULL AND (r.resolved_at, r.id) < ($2, $3::uuid) ORDER BY r.resolved_at DESC, r.id DESC LIMIT $4`
		args = []any{viewer, cur.At, cur.ID, limit + 1}
	}
	var out []*Report
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rep, err := scanReport(rows)
			if err != nil {
				return err
			}
			out = append(out, rep)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	var next *Cursor
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		at := last.CreatedAt
		if !open {
			at = *last.ResolvedAt
		}
		next = &Cursor{At: at, ID: last.ID}
	}
	return out, next, nil
}

// Report resolutions a moderator may choose ("hidden" is set by Hide).
var Resolutions = []string{"dismissed", "actioned"}

// ResolveReport resolves an open report.
func (s *Store) ResolveReport(ctx context.Context, id string, moderator *string, resolution string) (*Report, error) {
	now := s.now()
	var rep *Report
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error { // the resolution and its audit row together
			tag, err := tx.Exec(ctx, `UPDATE comment_reports SET resolved_at = $3, resolved_by = $2::uuid, resolution = $4
				WHERE id = $1::uuid AND resolved_at IS NULL`, id, moderator, now, resolution)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM comment_reports WHERE id = $1::uuid)`, id).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					return ErrNotFound
				}
				return ErrReportClosed
			}
			if rep, err = scanReport(tx.QueryRow(ctx, `SELECT `+rowCols+`, `+reportCols+reportFrom+`WHERE r.id = $2::uuid`, moderator, id)); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Entry{ActorID: moderator, Action: audit.ReportResolve, TargetType: audit.TargetReport,
				TargetID: rep.ID, TargetLabel: audit.Excerpt(rep.Comment.Body, audit.MaxLabel),
				Details: map[string]any{"comment_id": rep.Comment.ID, "cve": rep.Comment.CVE, "resolution": resolution, "reason": rep.Reason}})
		})
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// Recent lists the latest comments site-wide (all statuses), newest first.
func (s *Store) Recent(ctx context.Context, viewer *string, after *Cursor, limit int) ([]*Row, *Cursor, error) {
	if limit <= 0 || limit > ModPageMax {
		limit = ModPageMax
	}
	cur := Cursor{At: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}
	if after != nil {
		cur = *after
	}
	var out []*Row
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+rowCols+rowFrom+`WHERE (c.created_at, c.id) < ($2, $3::uuid)
			ORDER BY c.created_at DESC, c.id DESC LIMIT $4`, viewer, cur.At, cur.ID, limit+1)
		if err != nil {
			return err
		}
		out, err = collectRows(rows)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	var next *Cursor
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = &Cursor{At: last.CreatedAt, ID: last.ID}
	}
	return out, next, nil
}
