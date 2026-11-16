package auth

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
)

// Staff (admin back office) store methods: read-only listings for the
// admin pages, and the web actions on other accounts. See docs/admin.md.
//
// Every web action is one transaction holding the target's row lock, whose
// writing statement repeats every condition (the actor is an active admin,
// the target is not the actor and not an admin, the change is one the web
// may make), followed by the audit row. There is no check-then-write gap:
// a concurrent `nday auth-role <x> admin` either commits first (the web
// statement then matches no row) or waits for the lock.

// Errors of the staff actions.
var (
	// ErrSelf: staff may not act on their own account on the web.
	ErrSelf = errors.New("you cannot do this to your own account")
	// ErrProtected: the target is an admin; admins are changed only by
	// commands on the server.
	ErrProtected = errors.New("admin accounts can only be changed with the server CLI")
	// ErrNoChange: the account is already in the requested state.
	ErrNoChange = errors.New("nothing to change")
	// ErrNotAdmin: the acting account is no longer an active admin.
	ErrNotAdmin = errors.New("the acting account is not an active admin")
)

// UserRow is one line of the user list.
type UserRow struct {
	User
	Effective string // EffectiveStatus at query time
}

// UserPageMax is the largest page of SearchUsers.
const UserPageMax = 100

// UserCursor is a position in the user list (newest first).
type UserCursor struct {
	CreatedAt time.Time
	ID        UserID
}

// likeEscape escapes LIKE wildcards (backslash is the default escape).
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// SearchUsers lists accounts newest first. q (trimmed, at most 64 runes)
// matches an exact user id, a handle prefix (case-insensitive) or a part of
// the display name (case-insensitive); "" lists everyone. after continues a
// previous page.
func (s *Store) SearchUsers(ctx context.Context, q string, after *UserCursor, limit int) ([]UserRow, *UserCursor, error) {
	if limit <= 0 || limit > UserPageMax {
		limit = UserPageMax
	}
	q = strings.TrimSpace(q)
	if utf8.RuneCountInString(q) > 64 {
		q = string([]rune(q)[:64])
	}
	cur := UserCursor{CreatedAt: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}
	if after != nil {
		cur = *after
	}
	now := s.now()
	var out []UserRow
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+userCols+` FROM users u
			WHERE (u.created_at, u.id) < ($1, $2::uuid)
			  AND ($3 = '' OR u.id::text = lower($3) OR u.handle_key LIKE lower($4) || '%'
			       OR lower(u.display_name) LIKE '%' || lower($4) || '%')
			ORDER BY u.created_at DESC, u.id DESC LIMIT $5`, cur.CreatedAt, cur.ID, q, likeEscape(q), limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return err
			}
			out = append(out, UserRow{User: *u, Effective: u.EffectiveStatus(now)})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	var next *UserCursor
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = &UserCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return out, next, nil
}

// IdentitySummary is a linked sign-in method as the admin pages show it:
// never a token, and the provider subject only shortened.
type IdentitySummary struct {
	Provider     string
	Handle       *string // what the provider called the account (display only)
	SubjectShort string  // first 4 and last 2 characters of the subject
	LinkedAt     time.Time
	LastUsedAt   time.Time
}

// UserSummary is the account-level counts of the admin user page.
type UserSummary struct {
	Identities     []IdentitySummary
	Passkeys       int
	ActiveSessions int // not expired and not idle for longer than idle
}

// ShortSubject shortens a provider subject for display: "1234…89".
func ShortSubject(sub string) string {
	r := []rune(sub)
	if len(r) <= 8 {
		if len(r) <= 2 {
			return "…"
		}
		return string(r[:1]) + "…" + string(r[len(r)-1:])
	}
	return string(r[:4]) + "…" + string(r[len(r)-2:])
}

// Summary returns the identities (shortened), the passkey count and the
// number of live sessions of a user (sessions idle for longer than idle do
// not count).
func (s *Store) Summary(ctx context.Context, id UserID, idle time.Duration) (*UserSummary, error) {
	now := s.now()
	sum := &UserSummary{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT provider, subject, handle, linked_at, last_used_at FROM identities
			WHERE user_id = $1 ORDER BY linked_at, provider`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var i IdentitySummary
			var sub string
			if err := rows.Scan(&i.Provider, &sub, &i.Handle, &i.LinkedAt, &i.LastUsedAt); err != nil {
				rows.Close()
				return err
			}
			i.SubjectShort = ShortSubject(sub)
			sum.Identities = append(sum.Identities, i)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT (SELECT count(*) FROM passkeys WHERE user_id = $1),
			(SELECT count(*) FROM sessions WHERE user_id = $1 AND expires_at > $2 AND last_seen_at > $3)`,
			id, now, now.Add(-idle)).Scan(&sum.Passkeys, &sum.ActiveSessions)
	})
	return sum, err
}

// ---- web actions (admin only; the HTTP layer also checks recent sign-in) ----

// StaffResult is the target after a web action.
type StaffResult struct {
	User    *User
	Revoked int64 // sessions revoked (StaffSignOutAll)
}

// staffChange runs one web action: in one transaction, lock the target
// row, run upd — a conditional statement over users u that must repeat
// every rule (use $1 = target, $2 = actor and the args from $3; it may only
// touch the target row) — then append the audit row. When upd changes no
// row, the reason is diagnosed from the locked rows.
func (s *Store) staffChange(ctx context.Context, actor, target UserID, upd string, args []any,
	entry func(old *User, n int64) audit.Entry) (*StaffResult, error) {
	res := &StaffResult{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			old, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = $1 FOR UPDATE`, target))
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, upd, append([]any{target, actor}, args...)...)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return s.diagnose(ctx, tx, actor, old)
			}
			e := entry(old, tag.RowsAffected())
			e.ActorID = &actor
			e.TargetType, e.TargetID = audit.TargetUser, old.ID
			if old.Handle != nil {
				e.TargetLabel = *old.Handle
			}
			if err := audit.Write(ctx, tx, e); err != nil {
				return err
			}
			if res.User, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = $1`, target)); err != nil {
				return err
			}
			if e.Action == audit.UserSignOut {
				res.Revoked = tag.RowsAffected()
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// actorIsAdmin is the SQL condition "$2 is an active admin" (an elapsed
// suspension counts as active, as in EffectiveStatus).
const actorIsAdmin = `EXISTS (SELECT 1 FROM users a WHERE a.id = $2::uuid AND a.role = 'admin'
	AND (a.status = 'active' OR (a.suspended_until IS NOT NULL AND a.suspended_until <= now())))`

// diagnose explains why a staff statement matched no row.
func (s *Store) diagnose(ctx context.Context, tx pgx.Tx, actor UserID, target *User) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT `+strings.ReplaceAll(actorIsAdmin, "$2", "$1"), actor).Scan(&ok); err != nil {
		return err
	}
	switch {
	case !ok:
		return ErrNotAdmin
	case strings.EqualFold(target.ID, actor):
		return ErrSelf
	case target.Role == RoleAdmin:
		return ErrProtected
	}
	return ErrNoChange
}

// StaffSetRole moves target between user and moderator — and nothing else:
// the statement refuses an admin target, an admin role, the actor itself and
// a no-op (ErrProtected, ErrSelf, ErrNoChange; ErrNotAdmin when the actor
// is no longer an active admin).
func (s *Store) StaffSetRole(ctx context.Context, actor, target UserID, role string) (*StaffResult, error) {
	if role != RoleUser && role != RoleModerator {
		return nil, ErrProtected
	}
	return s.staffChange(ctx, actor, target, `UPDATE users u SET role = $3
		WHERE u.id = $1 AND u.id <> $2::uuid AND u.role IN ('user', 'moderator') AND u.role <> $3
		  AND $3 IN ('user', 'moderator') AND `+actorIsAdmin, []any{role},
		func(old *User, _ int64) audit.Entry {
			return audit.Entry{Action: audit.UserRole, Details: map[string]any{"from": old.Role, "to": role}}
		})
}

// MaxSuspendReason is the longest suspension reason (characters).
const MaxSuspendReason = 500

// StaffSuspend suspends target (until nil = until lifted) with a reason.
// Admin targets, the actor itself and an account that is already suspended
// (until a later or the same time) are refused.
func (s *Store) StaffSuspend(ctx context.Context, actor, target UserID, until *time.Time, reason string) (*StaffResult, error) {
	return s.staffChange(ctx, actor, target, `UPDATE users u SET status = 'suspended', suspended_until = $3, status_reason = $4
		WHERE u.id = $1 AND u.id <> $2::uuid AND u.role <> 'admin' AND `+actorIsAdmin+`
		  AND NOT (u.status = 'suspended' AND u.suspended_until IS NOT DISTINCT FROM $3 AND u.status_reason IS NOT DISTINCT FROM $4)`,
		[]any{until, nullable(reason)},
		func(old *User, _ int64) audit.Entry {
			d := map[string]any{"until": nil, "was": old.EffectiveStatus(s.now())}
			if until != nil {
				d["until"] = until.UTC().Format(time.RFC3339)
			}
			return audit.Entry{Action: audit.UserSuspend, Reason: reason, Details: d}
		})
}

// StaffUnsuspend lifts a suspension (ErrNoChange when not suspended).
func (s *Store) StaffUnsuspend(ctx context.Context, actor, target UserID) (*StaffResult, error) {
	return s.staffChange(ctx, actor, target, `UPDATE users u SET status = 'active', suspended_until = NULL, status_reason = NULL
		WHERE u.id = $1 AND u.id <> $2::uuid AND u.role <> 'admin' AND u.status = 'suspended' AND `+actorIsAdmin, nil,
		func(old *User, _ int64) audit.Entry {
			d := map[string]any{"until": nil}
			if old.SuspendedUntil != nil {
				d["until"] = old.SuspendedUntil.UTC().Format(time.RFC3339)
			}
			return audit.Entry{Action: audit.UserUnsuspend, Details: d}
		})
}

// StaffSignOutAll revokes every session of target (ErrNoChange when it has
// none). The DELETE repeats the target conditions through users u.
func (s *Store) StaffSignOutAll(ctx context.Context, actor, target UserID) (*StaffResult, error) {
	return s.staffChange(ctx, actor, target, `DELETE FROM sessions s USING users u
		WHERE s.user_id = $1 AND u.id = s.user_id AND u.id <> $2::uuid AND u.role <> 'admin' AND `+actorIsAdmin, nil,
		func(_ *User, n int64) audit.Entry {
			return audit.Entry{Action: audit.UserSignOut, Details: map[string]any{"revoked_sessions": n}}
		})
}
