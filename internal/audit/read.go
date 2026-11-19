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
	rows, err = Query(ctx, db, f, Span{Before: before}, limit+1)
	if err != nil {
		return nil, 0, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[len(rows)-1].ID
	}
	return rows, next, nil
}

// Span is the part of the log Query reads: ids below Before (0 = no
// bound) newest first, or with After > 0 the ids above After oldest first;
// Offset rows of that order are skipped.
type Span struct {
	Before, After int64
	Offset        int
}

// Query returns at most limit (1..MaxPage+1) entries matching f in span.
func Query(ctx context.Context, db ConnSource, f Filter, span Span, limit int) (rows []Row, err error) {
	if limit <= 0 || limit > MaxPage+1 {
		limit = MaxPage + 1
	}
	where, args := filterSQL(f)
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	order := "DESC"
	if span.After > 0 {
		add("id > $?", span.After)
		order = "ASC"
	} else if span.Before > 0 {
		add("id < $?", span.Before)
	}
	q := `SELECT id, at, actor_id::text, actor_handle, actor_role, action, target_type, target_id, target_label, reason,
		details, source, client_addr, cf_ray FROM admin_audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit, max(span.Offset, 0))
	q += " ORDER BY id " + order + " LIMIT $" + strconv.Itoa(len(args)-1) + " OFFSET $" + strconv.Itoa(len(args))
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
		return nil, err
	}
	return rows, nil
}

// Count is the number of entries matching f, counted exactly. The audit
// page counts its list on every view (staff only, never cached): the log
// grows by staff actions only, the action and actor filters have indexes
// (admin_audit_action_idx, admin_audit_actor_idx) and the whole log is one
// pass over a table of small rows (CountSQL; TestAuditCountPlans).
func Count(ctx context.Context, db ConnSource, f Filter) (n int, err error) {
	q, args := CountSQL(f)
	err = db.WithConn(ctx, func(c *pgx.Conn) error { return c.QueryRow(ctx, q, args...).Scan(&n) })
	return n, err
}

// CountSQL is Count's query for f, with its arguments.
func CountSQL(f Filter) (string, []any) {
	where, args := filterSQL(f)
	q := `SELECT count(*)::int FROM admin_audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	return q, args
}

// filterSQL is f as conditions with their arguments ($1…).
func filterSQL(f Filter) (where []string, args []any) {
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
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
	return where, args
}
