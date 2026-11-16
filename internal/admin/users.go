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

// Users searches accounts (auth.Store.SearchUsers) and adds comment counts.
func (s *Service) Users(ctx context.Context, q string, after *auth.UserCursor) ([]UserListRow, *auth.UserCursor, error) {
	rows, next, err := s.read.SearchUsers(ctx, q, after, 50)
	if err != nil {
		return nil, nil, err
	}
	out := make([]UserListRow, len(rows))
	ids := make([]string, len(rows))
	for i, r := range rows {
		out[i].UserRow, ids[i] = r, r.ID
	}
	if len(ids) == 0 {
		return out, next, nil
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
		return nil, nil, err
	}
	for i := range out {
		out[i].Comments = counts[out[i].ID]
	}
	return out, next, nil
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
// suspension reason, reports filed, audit entries).
type UserDetail struct {
	User         *auth.User
	Status       string // effective
	Full         bool
	Summary      *auth.UserSummary
	CommentCount int
	Comments     []*Comment
	ReportsAbout []ReportRow
	ReportsFiled []ReportRow
	Audit        []audit.Row
}

// MaxUserItems caps each list of the user page.
const MaxUserItems = 20

// ErrNoUser: no such account.
var ErrNoUser = errors.New("admin: no such user")

// UserDetail loads the user page (full = the admin view).
func (s *Service) UserDetail(ctx context.Context, id string, full bool) (*UserDetail, error) {
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
	if d.Comments, _, err = s.RecentComments(ctx, "", u.ID, nil, MaxUserItems); err != nil {
		return nil, err
	}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		if err := c.QueryRow(ctx, `SELECT count(*)::int FROM comments WHERE author_id = $1`, u.ID).Scan(&d.CommentCount); err != nil {
			return err
		}
		var err error
		if d.ReportsAbout, err = reportRows(ctx, c, `c.author_id = $1`, u.ID); err != nil {
			return err
		}
		if full {
			d.ReportsFiled, err = reportRows(ctx, c, `r.reporter_id = $1`, u.ID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if full {
		if d.Summary, err = s.read.Summary(ctx, u.ID, s.auth.Config().SessionIdle); err != nil {
			return nil, err
		}
		if d.Audit, _, err = audit.List(ctx, s.o.ReadDB, audit.Filter{TargetType: audit.TargetUser, TargetID: u.ID}, 0, MaxUserItems); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func reportRows(ctx context.Context, c *pgx.Conn, cond string, id string) ([]ReportRow, error) {
	rows, err := c.Query(ctx, `SELECT r.id::text, c.id::text, c.cve_id, r.reason, r.note, r.created_at, r.resolved_at, r.resolution, c.body
		FROM comment_reports r JOIN comments c ON c.id = r.comment_id WHERE `+cond+`
		ORDER BY r.created_at DESC, r.id DESC LIMIT $2`, id, MaxUserItems)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReportRow, error) {
		var x ReportRow
		var body string
		err := r.Scan(&x.ID, &x.CommentID, &x.CVE, &x.Reason, &x.Note, &x.CreatedAt, &x.ResolvedAt, &x.Resolution, &body)
		x.Excerpt = audit.Excerpt(body, 160)
		x.CreatedAt = x.CreatedAt.UTC()
		return x, err
	})
}

// AuditLog lists the audit log (see audit.List).
func (s *Service) AuditLog(ctx context.Context, f audit.Filter, before int64) ([]audit.Row, int64, error) {
	return audit.List(ctx, s.o.ReadDB, f, before, 50)
}
