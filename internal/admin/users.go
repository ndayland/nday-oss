package admin

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
)

// User management (/admin/users, /admin/users/{id}). Reads on ReadDB.

// UserListRow is one row of the user list.
type UserListRow struct {
	auth.UserRow
	Comments int
}

// Users lists one page of the accounts matching q (auth.Store.SearchUsers'
// order; keyset both ways; UsersCount is its length) and adds
// comment counts.
func (s *Service) Users(ctx context.Context, q string, pos Keyset[auth.UserCursor]) ([]UserListRow, *auth.UserCursor, *auth.UserCursor, error) {
	rows, prev, next, err := keysetPage(pos, ListPage, func(cur *auth.UserCursor, back bool, n int) ([]auth.UserRow, error) {
		return s.read.SearchUsersFrom(ctx, q, cur, back, n)
	}, func(r auth.UserRow) auth.UserCursor { return auth.UserCursor{CreatedAt: r.CreatedAt, ID: r.ID} })
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]UserListRow, len(rows))
	ids := make([]string, len(rows))
	for i, r := range rows {
		out[i].UserRow, ids[i] = r, r.ID
	}
	if len(ids) == 0 {
		return out, prev, next, nil
	}
	counts := map[string]int{}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rs, err := c.Query(ctx, `SELECT author_id::text, count(*)::int FROM comments WHERE author_id = ANY($1::uuid[]) GROUP BY 1`, ids)
		if err != nil {
			return err
		}
		var id string
		var n int
		_, err = pgx.ForEachRow(rs, []any{&id, &n}, func() error { counts[id] = n; return nil })
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range out {
		out[i].Comments = counts[out[i].ID]
	}
	return out, prev, next, nil
}

// UsersCount is the length of the user list for q (auth.Store.CountUsers:
// one pass over the users table).
func (s *Service) UsersCount(ctx context.Context, q string) (int, error) {
	return s.read.CountUsers(ctx, q)
}

// EncodeUserCursor / DecodeUserCursor make the user list cursor URL-safe.
func EncodeUserCursor(c *auth.UserCursor) string {
	if c == nil {
		return ""
	}
	return EncodeCursor(&Cursor{At: c.CreatedAt, ID: c.ID})
}

// DecodeUserCursor parses EncodeUserCursor's output (nil when invalid).
func DecodeUserCursor(s string) *auth.UserCursor {
	c := DecodeCursor(s)
	if c == nil {
		return nil
	}
	return &auth.UserCursor{CreatedAt: c.At, ID: c.ID}
}

// ReportRow is a report in a user's history.
type ReportRow struct {
	ID         string
	CommentID  string
	CVE        string
	Reason     string
	Note       *string
	CreatedAt  time.Time
	ResolvedAt *time.Time
	Resolution *string
	Excerpt    string // of the reported comment, plain text
}

// UserDetail is the user page. Full is false for moderators: then only the
// fields a moderator may see are loaded (no identities, sessions, passkeys,
// suspension reason, reports filed, audit entries). Each list is one page
// of a numbered list (UserPages).
type UserDetail struct {
	User         *auth.User
	Status       string // effective
	Full         bool
	Summary      *auth.UserSummary
	CommentCount int
	Comments     []*Comment
	CommentsW    Window
	ReportsAbout []ReportRow
	AboutW       Window
	ReportsFiled []ReportRow
	FiledW       Window
	Audit        []audit.Row
	AuditW       Window
}

// UserPages are the requested pages of the user page's lists (1-based;
// anything out of range is clamped).
type UserPages struct {
	Comments, About, Filed, Audit int
}

// MaxUserItems is the page size of each list of the user page.
const MaxUserItems = ListPage

// ErrNoUser: no such account.
var ErrNoUser = errors.New("admin: no such user")

// UserDetail loads the user page (full = the admin view).
func (s *Service) UserDetail(ctx context.Context, id string, full bool, pg UserPages) (*UserDetail, error) {
	u, err := s.read.User(ctx, id)
	if errors.Is(err, auth.ErrNotFound) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	d := &UserDetail{User: u, Status: u.EffectiveStatus(s.auth.Now()), Full: full}
	if !full {
		u.StatusReason, u.LastSeenAt, u.Locale, u.TermsVersion, u.TermsAcceptedAt = nil, time.Time{}, nil, nil, nil
	}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		if err := c.QueryRow(ctx, `SELECT count(*)::int FROM comments WHERE author_id = $1`, u.ID).Scan(&d.CommentCount); err != nil {
			return err
		}
		var err error
		if d.ReportsAbout, d.AboutW, err = reportRows(ctx, c, `c.author_id = $1`, u.ID, pg.About); err != nil {
			return err
		}
		if full {
			d.ReportsFiled, d.FiledW, err = reportRows(ctx, c, `r.reporter_id = $1`, u.ID, pg.Filed)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if d.Comments, d.CommentsW, err = s.UserComments(ctx, u.ID, d.CommentCount, pg.Comments); err != nil {
		return nil, err
	}
	if full {
		if d.Summary, err = s.read.Summary(ctx, u.ID, s.auth.Config().SessionIdle); err != nil {
			return nil, err
		}
		f := audit.Filter{TargetType: audit.TargetUser, TargetID: u.ID}
		n, err := audit.Count(ctx, s.o.ReadDB, f) // the target index serves it
		if err != nil {
			return nil, err
		}
		d.AuditW = window(n, pg.Audit)
		if d.Audit, err = audit.Query(ctx, s.o.ReadDB, f, audit.Span{Offset: d.AuditW.Offset()}, ListPage); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func reportRows(ctx context.Context, c *pgx.Conn, cond string, id string, page int) ([]ReportRow, Window, error) {
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*)::int FROM comment_reports r JOIN comments c ON c.id = r.comment_id WHERE `+cond, id).Scan(&n); err != nil {
		return nil, Window{}, err
	}
	w := window(n, page)
	rows, err := c.Query(ctx, `SELECT r.id::text, c.id::text, c.cve_id, r.reason, r.note, r.created_at, r.resolved_at, r.resolution, c.body
		FROM comment_reports r JOIN comments c ON c.id = r.comment_id WHERE `+cond+`
		ORDER BY r.created_at DESC, r.id DESC LIMIT $2 OFFSET $3`, id, MaxUserItems, w.Offset())
	if err != nil {
		return nil, Window{}, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReportRow, error) {
		var x ReportRow
		var body string
		err := r.Scan(&x.ID, &x.CommentID, &x.CVE, &x.Reason, &x.Note, &x.CreatedAt, &x.ResolvedAt, &x.Resolution, &body)
		x.Excerpt = audit.Excerpt(body, 160)
		x.CreatedAt = x.CreatedAt.UTC()
		return x, err
	})
	return out, w, err
}

// AuditLog lists one page of the audit log, newest first (keyset both
// ways on the id; AuditCount is its length). prev and next are the ids to
// pass as pos.Newer and pos.Older (nil: no such page).
func (s *Service) AuditLog(ctx context.Context, f audit.Filter, pos Keyset[int64]) ([]audit.Row, *int64, *int64, error) {
	return keysetPage(pos, ListPage, func(cur *int64, back bool, n int) ([]audit.Row, error) {
		span := audit.Span{}
		switch {
		case cur != nil && back:
			span.After = *cur
		case cur != nil:
			span.Before = *cur
		case back:
			span.Oldest = true
		}
		return audit.Query(ctx, s.o.ReadDB, f, span, n)
	}, func(r audit.Row) int64 { return r.ID })
}

// AuditCount is the length of the audit log for f, counted exactly: the log
// grows by staff actions only, and each filter but the target has an index
// (admin_audit_action_idx, admin_audit_actor_idx; the unfiltered log is an
// index-only scan of its primary key or a pass over the table).
func (s *Service) AuditCount(ctx context.Context, f audit.Filter) (int, error) {
	return audit.Count(ctx, s.o.ReadDB, f)
}
