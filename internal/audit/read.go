package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnSource hands out a connection for the duration of fn (*dbpool.Pool
// implements it). Reads only: the admin pages pass the site's read-only pool.
type ConnSource interface {
	WithConn(ctx context.Context, fn func(*pgx.Conn) error) error
}

// Row is a stored entry.
type Row struct {
	ID          int64
	At          time.Time
	ActorID     *string
	ActorHandle *string
	ActorRole   string
	Action      string
	TargetType  string
	TargetID    string
	TargetLabel *string
	Reason      *string
	Details     map[string]any
	Source      string
	ClientAddr  *string
	CFRay       *string
}

// Filter narrows List. Empty fields match everything.
type Filter struct {
	Action      string // exact action code
	ActorHandle string // case-insensitive exact handle ("cli" matches commands)
	TargetID    string // exact target id
	TargetType  string // exact target type
}

// MaxPage is the largest page List returns.
const MaxPage = 200

// List returns entries newest first, older than before (0 = from the
// newest), at most limit (1..MaxPage); next is the id to continue from (0 =
// no more).
func List(ctx context.Context, db ConnSource, f Filter, before int64, limit int) (rows []Row, next int64, err error) {
	if limit <= 0 || limit > MaxPage {
		limit = MaxPage
	}
	var where []string
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if before > 0 {
		add("id < $?", before)
	}
	if f.Action != "" {
		add("action = $?", f.Action)
	}
	if f.ActorHandle != "" {
		if strings.EqualFold(f.ActorHandle, "cli") {
			where = append(where, "actor_role = 'cli'")
		} else {
			add("lower(actor_handle) = lower($?)", f.ActorHandle)
		}
	}
	if f.TargetID != "" {
		add("target_id = lower($?)", f.TargetID)
	}
	if f.TargetType != "" {
		add("target_type = $?", f.TargetType)
	}
	q := `SELECT id, at, actor_id::text, actor_handle, actor_role, action, target_type, target_id, target_label, reason,
		details, source, client_addr, cf_ray FROM admin_audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit+1)
	q += " ORDER BY id DESC LIMIT $" + strconv.Itoa(len(args))
	err = db.WithConn(ctx, func(c *pgx.Conn) error {
		rs, err := c.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r Row
			var dj []byte
			if err := rs.Scan(&r.ID, &r.At, &r.ActorID, &r.ActorHandle, &r.ActorRole, &r.Action, &r.TargetType, &r.TargetID,
				&r.TargetLabel, &r.Reason, &dj, &r.Source, &r.ClientAddr, &r.CFRay); err != nil {
				return err
			}
			r.At = r.At.UTC()
			_ = json.Unmarshal(dj, &r.Details)
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[len(rows)-1].ID
	}
	return rows, next, nil
}
