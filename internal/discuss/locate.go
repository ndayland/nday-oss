package discuss

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Position says where a visible comment is shown, for pages that link to a
// single comment (?c=<id> on a vulnerability page). Read-only.
type Position struct {
	ThreadID string // the top-level comment of its thread (the comment itself for a top-level one)
	Reply    bool
	// PageCursor is the StreamPage cursor of a page that begins with the
	// thread ("" when it is the first thread of the vulnerability).
	PageCursor string
	// ReplyCursor (replies only) is the StreamThread cursor of a
	// continuation that begins with this reply ("" when it is the first).
	ReplyCursor string
}

// Locate finds a visible comment of cve as an anonymous visitor sees it.
// ErrNotFound when id is not a UUID, not a comment of cve, not visible
// (hidden or deleted), or a reply whose thread is not shown.
func (s *Service) Locate(ctx context.Context, cve, id string) (*Position, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	return s.store.Locate(ctx, cve, strings.ToLower(id))
}

// Locate is Service.Locate on the read pool: one statement.
func (s *Store) Locate(ctx context.Context, cve, id string) (*Position, error) {
	var (
		p                     Position
		parent, top, pID, rID *string
		pAt, rAt              *time.Time
	)
	err := s.read().WithConn(ctx, func(c *pgx.Conn) error {
		// t: the thread's top-level row (shown while visible/hidden, or
		// deleted with a non-deleted reply, as in Page and Thread).
		return c.QueryRow(ctx, `WITH me AS (
				SELECT id, parent_id, created_at, coalesce(parent_id, id) AS top FROM comments
				WHERE id = $2::uuid AND cve_id = $1 AND status = 'visible'),
			t AS (
				SELECT c.id, c.created_at FROM comments c JOIN me ON c.id = me.top
				WHERE c.parent_id IS NULL AND (c.status <> 'deleted'
					OR EXISTS (SELECT 1 FROM comments x WHERE x.parent_id = c.id AND x.status <> 'deleted')))
			SELECT me.parent_id::text, t.id::text,
				(SELECT p.created_at FROM comments p WHERE p.cve_id = $1 AND p.parent_id IS NULL
					AND (p.status <> 'deleted' OR EXISTS (SELECT 1 FROM comments x WHERE x.parent_id = p.id AND x.status <> 'deleted'))
					AND (p.created_at, p.id) < (t.created_at, t.id) ORDER BY p.created_at DESC, p.id DESC LIMIT 1),
				(SELECT p.id::text FROM comments p WHERE p.cve_id = $1 AND p.parent_id IS NULL
					AND (p.status <> 'deleted' OR EXISTS (SELECT 1 FROM comments x WHERE x.parent_id = p.id AND x.status <> 'deleted'))
					AND (p.created_at, p.id) < (t.created_at, t.id) ORDER BY p.created_at DESC, p.id DESC LIMIT 1),
				(SELECT r.created_at FROM comments r WHERE me.parent_id IS NOT NULL AND r.parent_id = me.parent_id AND r.status <> 'deleted'
					AND (r.created_at, r.id) < (me.created_at, me.id) ORDER BY r.created_at DESC, r.id DESC LIMIT 1),
				(SELECT r.id::text FROM comments r WHERE me.parent_id IS NOT NULL AND r.parent_id = me.parent_id AND r.status <> 'deleted'
					AND (r.created_at, r.id) < (me.created_at, me.id) ORDER BY r.created_at DESC, r.id DESC LIMIT 1)
			FROM me JOIN t ON true`, cve, id).Scan(&parent, &top, &pAt, &pID, &rAt, &rID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.ThreadID = *top
	p.Reply = parent != nil
	if pAt != nil && pID != nil {
		p.PageCursor = encodeCursor(&Cursor{At: pAt.UTC(), ID: *pID})
	}
	if rAt != nil && rID != nil {
		p.ReplyCursor = encodeCursor(&Cursor{At: rAt.UTC(), ID: *rID})
	}
	return &p, nil
}
