package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// The moderation module (/admin/moderation): open reports grouped by
// comment, and a patrol list of recent comments. Read-only queries on
// ReadDB; the actions are the discussion endpoints.

// Comment is a comment as the moderation pages show it. Body is the
// Markdown source (render it with package discuss/md; show it nowhere else
// but as text).
type Comment struct {
	ID           string
	CVE          string
	ParentID     *string
	AuthorID     *string
	Handle       *string // nil: no handle, or account deleted (AuthorID nil)
	Role         *string
	Body         string
	Links        bool
	Status       string
	CreatedAt    time.Time
	EditedAt     *time.Time
	HiddenAt     *time.Time
	HiddenReason *string
	HiddenBy     *string // handle of the moderator ("" via CLI: nil)
	OpenReports  int
	Revisions    int
}

const commentCols = `c.id::text, c.cve_id, c.parent_id::text, c.author_id::text, u.handle, u.role, c.body, c.links, c.status,
	c.created_at, c.edited_at, c.hidden_at, c.hidden_reason, h.handle,
	(SELECT count(*) FROM comment_reports rr WHERE rr.comment_id = c.id AND rr.resolved_at IS NULL)::int,
	(SELECT count(*) FROM comment_revisions cr WHERE cr.comment_id = c.id)::int`

const commentFrom = ` FROM comments c LEFT JOIN users u ON u.id = c.author_id LEFT JOIN users h ON h.id = c.hidden_by `

func scanComment(row pgx.Row, extra ...any) (*Comment, error) {
	c := &Comment{}
	err := row.Scan(append([]any{&c.ID, &c.CVE, &c.ParentID, &c.AuthorID, &c.Handle, &c.Role, &c.Body, &c.Links, &c.Status,
		&c.CreatedAt, &c.EditedAt, &c.HiddenAt, &c.HiddenReason, &c.HiddenBy, &c.OpenReports, &c.Revisions}, extra...)...)
	if err != nil {
		return nil, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// Revision is an earlier body of a comment (plain text).
type Revision struct {
	Body       string
	ReplacedAt time.Time
}

// ReportItem is one open report.
type ReportItem struct {
	ID        string
	Reason    string
	Note      *string
	CreatedAt time.Time
}

// ReportGroup is a reported comment with its open reports.
type ReportGroup struct {
	Comment   *Comment
	Reports   []ReportItem // oldest first, at most MaxGroupReports
	Reasons   map[string]int
	Reporters int // distinct reporters (deleted accounts count as one)
	Total     int // open reports of the comment
	First     time.Time
	History   []Revision // earlier bodies, newest first (at most MaxRevisions)
}

// Page sizes and caps of the moderation module.
const (
	QueuePage       = ListPage
	RecentPage      = ListPage
	MaxGroupReports = 50
	MaxRevisions    = 20
)

// Cursor is a page position (opaque to callers).
type Cursor struct {
	At time.Time `json:"t"`
	ID string    `json:"i"`
}

// EncodeCursor makes a cursor URL-safe ("" for nil).
func EncodeCursor(c *Cursor) string {
	if c == nil {
		return ""
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses EncodeCursor's output (nil for anything invalid).
func DecodeCursor(s string) *Cursor {
	if s == "" || len(s) > 200 {
		return nil
	}
	c := decodeAny(s)
	if c == nil || !ValidID(c.ID) || c.At.IsZero() {
		return nil
	}
	return c
}

// decodeAny parses a cursor without checking its id's form.
func decodeAny(s string) *Cursor {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	var c Cursor
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

// ReportQueue lists one page of the comments with open reports, the one
// reported first first (numbered: the queue is small and counted).
func (s *Service) ReportQueue(ctx context.Context, page int) ([]ReportGroup, Window, error) {
	var out []ReportGroup
	var w Window
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var total int
		if err := c.QueryRow(ctx, `SELECT count(*)::int FROM (SELECT comment_id FROM comment_reports WHERE resolved_at IS NULL
			GROUP BY comment_id) g JOIN comments c ON c.id = g.comment_id`).Scan(&total); err != nil {
			return err
		}
		w = window(total, page)
		rows, err := c.Query(ctx, `WITH g AS (
				SELECT comment_id, min(created_at) AS first, count(*)::int AS total,
				       count(DISTINCT coalesce(reporter_id::text, '-'))::int AS reporters
				FROM comment_reports WHERE resolved_at IS NULL GROUP BY comment_id)
			SELECT `+commentCols+`, g.first, g.total, g.reporters`+commentFrom+`JOIN g ON g.comment_id = c.id
			ORDER BY g.first, c.id LIMIT $1 OFFSET $2`, ListPage, w.Offset())
		if err != nil {
			return err
		}
		for rows.Next() {
			var g ReportGroup
			cm, err := scanComment(rows, &g.First, &g.Total, &g.Reporters)
			if err != nil {
				rows.Close()
				return err
			}
			g.Comment, g.Reasons = cm, map[string]int{}
			out = append(out, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range out {
			g := &out[i]
			rs, err := c.Query(ctx, `SELECT id::text, reason, note, created_at FROM comment_reports
				WHERE comment_id = $1 AND resolved_at IS NULL ORDER BY created_at, id`, g.Comment.ID)
			if err != nil {
				return err
			}
			for rs.Next() {
				var it ReportItem
				if err := rs.Scan(&it.ID, &it.Reason, &it.Note, &it.CreatedAt); err != nil {
					rs.Close()
					return err
				}
				g.Reasons[it.Reason]++
				if len(g.Reports) < MaxGroupReports {
					it.CreatedAt = it.CreatedAt.UTC()
					g.Reports = append(g.Reports, it)
				}
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return err
			}
			if g.Comment.Revisions > 0 {
				if g.History, err = revisions(ctx, c, g.Comment.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, Window{}, err
	}
	return out, w, nil
}

func revisions(ctx context.Context, c *pgx.Conn, id string) ([]Revision, error) {
	rows, err := c.Query(ctx, `SELECT body, replaced_at FROM comment_revisions WHERE comment_id = $1
		ORDER BY replaced_at DESC, id DESC LIMIT $2`, id, MaxRevisions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Revision, error) {
		var v Revision
		err := r.Scan(&v.Body, &v.ReplacedAt)
		v.ReplacedAt = v.ReplacedAt.UTC()
		return v, err
	})
}

// CommentStatuses are the patrol list's status filter values ("" = all).
var CommentStatuses = []string{"visible", "hidden", "deleted"}

// RecentComments lists one page of the comments newest first (keyset both
// ways; RecentCommentsCount is its length), optionally of one status.
func (s *Service) RecentComments(ctx context.Context, status string, pos Keyset[Cursor]) ([]*Comment, *Cursor, *Cursor, error) {
	return keysetPage(pos, RecentPage, func(cur *Cursor, back bool, n int) ([]*Comment, error) {
		cmp, ord := "<", "DESC"
		if back {
			cmp, ord = ">", "ASC"
		}
		at, id := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), "ffffffff-ffff-ffff-ffff-ffffffffffff"
		if cur != nil {
			at, id = cur.At, cur.ID
		}
		return s.comments(ctx, `WHERE (c.created_at, c.id) `+cmp+` ($1, $2::uuid) AND ($3 = '' OR c.status = $3)
			ORDER BY c.created_at `+ord+`, c.id `+ord+` LIMIT $4`, at, id, status, n)
	}, func(c *Comment) Cursor { return Cursor{At: c.CreatedAt, ID: c.ID} })
}

// RecentCommentsCount is the length of the patrol list for status ("" =
// all): the comments table, an index-only scan of comments_created_idx or a
// pass over the table.
func (s *Service) RecentCommentsCount(ctx context.Context, status string) (n int, err error) {
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*)::int FROM comments c WHERE ($1 = '' OR c.status = $1)`, status).Scan(&n)
	})
	return n, err
}

// UserComments lists one page of a user's comments, newest first
// (numbered: total is the user's comment count).
func (s *Service) UserComments(ctx context.Context, author string, total, page int) ([]*Comment, Window, error) {
	w := window(total, page)
	rows, err := s.comments(ctx, `WHERE c.author_id = $1::uuid ORDER BY c.created_at DESC, c.id DESC LIMIT $2 OFFSET $3`,
		author, ListPage, w.Offset())
	return rows, w, err
}

// comments runs the comment query with this WHERE … ORDER BY … tail.
func (s *Service) comments(ctx context.Context, tail string, args ...any) ([]*Comment, error) {
	var out []*Comment
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+commentCols+commentFrom+tail, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			cm, err := scanComment(rows)
			if err != nil {
				return err
			}
			out = append(out, cm)
		}
		return rows.Err()
	})
	return out, err
}

// History returns the earlier bodies of a comment, newest first.
func (s *Service) History(ctx context.Context, id string) ([]Revision, error) {
	var out []Revision
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		out, err = revisions(ctx, c, id)
		return err
	})
	return out, err
}
