package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/audit"
)

// ConnSource hands out a connection for the duration of fn (*dbpool.Pool
// implements it; SingleConn adapts one connection).
type ConnSource interface {
	WithConn(ctx context.Context, fn func(*pgx.Conn) error) error
}

// SingleConn adapts one connection (serialised by a mutex) to ConnSource.
func SingleConn(c *pgx.Conn) ConnSource { return &single{c: c} }

type single struct {
	mu sync.Mutex
	c  *pgx.Conn
}

func (s *single) WithConn(_ context.Context, fn func(*pgx.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.c)
}

// UserID is the type other packages use for a user reference: the
// users.id UUID in its canonical text form. Store it in a column
//
//	author_id uuid REFERENCES users (id) ON DELETE SET NULL
//
// so that deleting an account anonymises rather than deletes what the user
// wrote (see docs/auth.md).
type UserID = string

// User is an account row.
type User struct {
	ID              UserID     `json:"id"`
	DisplayName     *string    `json:"display_name"`
	Handle          *string    `json:"handle"`
	HandleChangedAt *time.Time `json:"handle_changed_at"`
	Locale          *string    `json:"locale"`
	Role            string     `json:"role"`
	Status          string     `json:"status"`
	SuspendedUntil  *time.Time `json:"suspended_until"`
	StatusReason    *string    `json:"status_reason"`
	TermsVersion    *string    `json:"terms_version"`
	TermsAcceptedAt *time.Time `json:"terms_accepted_at"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
}

// Roles, in increasing order of privilege.
const (
	RoleUser      = "user"
	RoleModerator = "moderator"
	RoleAdmin     = "admin"
)

var roleRank = map[string]int{RoleUser: 0, RoleModerator: 1, RoleAdmin: 2}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleRank[r]; return ok }

// HasRole reports whether the user's role is at least min.
func (u *User) HasRole(min string) bool {
	r, ok := roleRank[min]
	return ok && roleRank[u.Role] >= r
}

// Statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// EffectiveStatus is Status with an elapsed suspension counted as active.
func (u *User) EffectiveStatus(now time.Time) string {
	if u.Status == StatusSuspended && u.SuspendedUntil != nil && !now.Before(*u.SuspendedUntil) {
		return StatusActive
	}
	return u.Status
}

// Identity is a linked provider account.
type Identity struct {
	Provider   string    `json:"provider"`
	Subject    string    `json:"-"`
	Handle     *string   `json:"handle"`
	LinkedAt   time.Time `json:"linked_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// Store is the auth database layer. All times come from Now (tests).
type Store struct {
	DB  ConnSource
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
	ErrNotFound       = errors.New("not found")
	ErrLastIdentity   = errors.New("cannot unlink the last sign-in method")
	ErrNotLinked      = errors.New("provider not linked")
	ErrHandleTaken    = errors.New("this handle is taken")
	ErrHandleTooSoon  = errors.New("the handle was changed less than 30 days ago")
	ErrIdentityOwned  = errors.New("identity belongs to another account")
	ErrProviderLinked = errors.New("another account of this provider is already linked")
	// ErrIdentitySuspended: the identity belonged to an account that was
	// deleted while suspended, and that suspension has not ended yet.
	ErrIdentitySuspended = errors.New("identity belongs to a suspended account")
	// ErrNoUsableMethod: other sign-in methods exist but none can be used
	// today (their provider is switched off, or passkeys are), so removing
	// this one would lock the account.
	ErrNoUsableMethod = errors.New("your other sign-in methods are currently unavailable; keep this one")
)

// HandleChangeInterval is the minimum time between two handle changes.
const HandleChangeInterval = 30 * 24 * time.Hour

func isUnique(err error, constraint string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505" && (constraint == "" || pe.ConstraintName == constraint)
}

const userCols = `u.id::text, u.display_name, u.handle, u.handle_changed_at, u.locale, u.role, u.status,
	u.suspended_until, u.status_reason, u.terms_version, u.terms_accepted_at, u.created_at, u.last_seen_at`

func scanUser(row pgx.Row, extra ...any) (*User, error) {
	u := &User{}
	dst := append([]any{&u.ID, &u.DisplayName, &u.Handle, &u.HandleChangedAt, &u.Locale, &u.Role, &u.Status,
		&u.SuspendedUntil, &u.StatusReason, &u.TermsVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.LastSeenAt}, extra...)
	if err := row.Scan(dst...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// IdentityHashes returns the keyed hashes of a provider identity, one per
// configured server secret, current secret first. The Service supplies it;
// it is how suspended_identities rows are written and found.
type IdentityHashes func(provider, subject string) [][]byte

// SignIn returns the user owning (provider, subject), creating the user and
// identity on first sign-in. handle is the provider-side handle (display
// only), displayName the sanitised provider display name ("" = none).
//
// A new user whose identity left a live suspended_identities row (see
// DeleteUser) starts out suspended until the same time; the row is used up,
// so it never touches the account again.
func (s *Store) SignIn(ctx context.Context, provider, subject, handle, displayName string, hash IdentityHashes) (id UserID, created bool, err error) {
	now := s.now()
	for attempt := 0; attempt < 2; attempt++ {
		err = s.DB.WithConn(ctx, func(c *pgx.Conn) error {
			return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
				err := tx.QueryRow(ctx, `UPDATE identities SET last_used_at = $3, handle = $4
					WHERE provider = $1 AND subject = $2 RETURNING user_id::text`,
					provider, subject, now, nullable(handle)).Scan(&id)
				if err == nil {
					created = false
					_, err = tx.Exec(ctx, `UPDATE users SET last_seen_at = $2 WHERE id = $1`, id, now)
					return err
				}
				if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				status, until, err := takeSuspension(ctx, tx, provider, subject, hash, now)
				if err != nil {
					return err
				}
				if err := tx.QueryRow(ctx, `INSERT INTO users (display_name, created_at, last_seen_at, status, suspended_until)
					VALUES ($1, $2, $2, $3, $4) RETURNING id::text`, nullable(displayName), now, status, until).Scan(&id); err != nil {
					return err
				}
				created = true
				_, err = tx.Exec(ctx, `INSERT INTO identities (provider, subject, user_id, handle, linked_at, last_used_at)
					VALUES ($1, $2, $3, $4, $5, $5)`, provider, subject, id, nullable(handle), now)
				return err
			})
		})
		if isUnique(err, "identities_pkey") {
			continue // a concurrent first sign-in created it: look it up again
		}
		return id, created, err
	}
	return id, created, err
}

// takeSuspension looks for live suspended_identities rows of (provider,
// subject), deletes them and returns the status a new account for that
// identity starts with. With several rows (one per server secret it was
// hashed under) the longest suspension wins.
func takeSuspension(ctx context.Context, tx pgx.Tx, provider, subject string, hash IdentityHashes, now time.Time) (string, *time.Time, error) {
	if hash == nil {
		return StatusActive, nil, nil
	}
	var until *time.Time
	err := tx.QueryRow(ctx, `WITH used AS (
			DELETE FROM suspended_identities
			WHERE provider = $1 AND subject_hash = ANY($2) AND (suspended_until IS NULL OR suspended_until > $3)
			RETURNING suspended_until)
		SELECT suspended_until FROM used ORDER BY suspended_until DESC NULLS FIRST LIMIT 1`,
		provider, hash(provider, subject), now).Scan(&until)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return StatusActive, nil, nil
	case err != nil:
		return "", nil, err
	}
	return StatusSuspended, until, nil
}

// Link attaches (provider, subject) to user. It returns nil when linked
// (or already linked to this user), ErrIdentityOwned when the identity
// belongs to another user, ErrProviderLinked when the user already has a
// different identity of that provider, ErrIdentitySuspended when the
// identity belonged to an account deleted while suspended and that
// suspension is still running (otherwise the suspended person could just
// attach it to a fresh passkey account).
func (s *Store) Link(ctx context.Context, user UserID, provider, subject, handle string, hash IdentityHashes) error {
	now := s.now()
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		err := pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var owner string
			err := tx.QueryRow(ctx, `SELECT user_id::text FROM identities WHERE provider = $1 AND subject = $2`,
				provider, subject).Scan(&owner)
			switch {
			case err == nil && owner == user:
				_, err = tx.Exec(ctx, `UPDATE identities SET last_used_at = $3, handle = $4 WHERE provider = $1 AND subject = $2`,
					provider, subject, now, nullable(handle))
				return err
			case err == nil:
				return ErrIdentityOwned
			case !errors.Is(err, pgx.ErrNoRows):
				return err
			}
			if hash != nil {
				var live bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM suspended_identities
					WHERE provider = $1 AND subject_hash = ANY($2) AND (suspended_until IS NULL OR suspended_until > $3))`,
					provider, hash(provider, subject), now).Scan(&live); err != nil {
					return err
				}
				if live {
					return ErrIdentitySuspended
				}
			}
			_, err = tx.Exec(ctx, `INSERT INTO identities (provider, subject, user_id, handle, linked_at, last_used_at)
				VALUES ($1, $2, $3, $4, $5, $5)`, provider, subject, user, nullable(handle), now)
			return err
		})
		switch {
		case isUnique(err, "identities_one_per_provider"):
			return ErrProviderLinked
		case isUnique(err, "identities_pkey"):
			return ErrIdentityOwned // raced with someone else's sign-in
		}
		return err
	})
}

// Unlink removes the user's identity of provider unless no other USABLE
// sign-in method would remain: identities of the providers in usable, and
// passkeys when passkeysOn. ErrLastIdentity: nothing else at all;
// ErrNoUsableMethod: only unusable methods would remain.
func (s *Store) Unlink(ctx context.Context, user UserID, provider string, usable []string, passkeysOn bool) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			// Lock the user row so two concurrent unlinks cannot both pass the count.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, user); err != nil {
				return err
			}
			var this, otherIDs, usableIDs, pks int
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE provider = $2),
					count(*) FILTER (WHERE provider <> $2),
					count(*) FILTER (WHERE provider <> $2 AND provider = ANY($3)),
					(SELECT count(*) FROM passkeys WHERE user_id = $1)
				FROM identities WHERE user_id = $1`, user, provider, usable).Scan(&this, &otherIDs, &usableIDs, &pks); err != nil {
				return err
			}
			if this == 0 {
				return ErrNotLinked
			}
			if err := lastMethod(otherIDs+pks, usableIDs, pks, passkeysOn, ErrLastIdentity); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM identities WHERE user_id = $1 AND provider = $2`, user, provider)
			return err
		})
	})
}

// lastMethod applies the last-method rule to what would remain.
func lastMethod(others, usableIDs, pks int, passkeysOn bool, none error) error {
	usable := usableIDs
	if passkeysOn {
		usable += pks
	}
	switch {
	case others == 0:
		return none
	case usable == 0:
		return ErrNoUsableMethod
	}
	return nil
}

// IdentityOwner returns the user owning (provider, subject), ErrNotFound if
// nobody does.
func (s *Store) IdentityOwner(ctx context.Context, provider, subject string) (UserID, error) {
	var id UserID
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT user_id::text FROM identities WHERE provider = $1 AND subject = $2`,
			provider, subject).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// Identities lists the user's linked identities (oldest first).
func (s *Store) Identities(ctx context.Context, user UserID) ([]Identity, error) {
	var out []Identity
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT provider, subject, handle, linked_at, last_used_at FROM identities
			WHERE user_id = $1 ORDER BY linked_at, provider`, user)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Identity, error) {
			var i Identity
			return i, r.Scan(&i.Provider, &i.Subject, &i.Handle, &i.LinkedAt, &i.LastUsedAt)
		})
		return err
	})
	return out, err
}

// DeleteUser deletes the account: user row, identities and sessions
// (CASCADE); rows of other tables that reference the user via ON DELETE
// SET NULL keep their content, anonymised. The handle's namespace entry is
// held for hold (deleted at once when hold is 0) so nobody can take over the
// name immediately.
//
// If the account's suspension is in effect, each identity first leaves a
// suspended_identities row (provider, hash(provider, subject), end of the
// suspension), so signing in again with it doesn't give the person a fresh
// active account. hash may be nil only for accounts that aren't suspended.
func (s *Store) DeleteUser(ctx context.Context, user UserID, hold time.Duration, hash IdentityHashes) error {
	now := s.now()
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var key *string
			u := User{}
			if err := tx.QueryRow(ctx, `SELECT handle_key, status, suspended_until FROM users WHERE id = $1 FOR UPDATE`,
				user).Scan(&key, &u.Status, &u.SuspendedUntil); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if u.EffectiveStatus(now) == StatusSuspended {
				if err := rememberSuspension(ctx, tx, user, u.SuspendedUntil, hash, now); err != nil {
					return err
				}
			}
			if key != nil {
				if _, err := tx.Exec(ctx, `UPDATE users SET handle = NULL, handle_key = NULL WHERE id = $1`, user); err != nil {
					return err
				}
				if err := releaseName(ctx, tx, *key, nil, now, hold); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, user)
			return err
		})
	})
}

// rememberSuspension writes one suspended_identities row per identity of
// user, hashed with the current secret.
func rememberSuspension(ctx context.Context, tx pgx.Tx, user UserID, until *time.Time, hash IdentityHashes, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT provider, subject FROM identities WHERE user_id = $1`, user)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var p [2]string
		return p, r.Scan(&p[0], &p[1])
	})
	if err != nil {
		return err
	}
	if len(ids) > 0 && hash == nil {
		return errors.New("auth: deleting a suspended account needs the identity hash")
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `INSERT INTO suspended_identities (provider, subject_hash, suspended_until, created_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (provider, subject_hash) DO UPDATE SET suspended_until = EXCLUDED.suspended_until, created_at = EXCLUDED.created_at`,
			id[0], hash(id[0], id[1])[0], until, now); err != nil {
			return err
		}
	}
	return nil
}

func releaseName(ctx context.Context, tx pgx.Tx, key string, heldFor *string, now time.Time, hold time.Duration) error {
	if hold <= 0 {
		_, err := tx.Exec(ctx, `DELETE FROM namespaces WHERE name = $1 AND kind = 'user'`, key)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE namespaces SET kind = 'held', held_until = $2, held_for = $3
		WHERE name = $1 AND kind = 'user'`, key, now.Add(hold), heldFor)
	return err
}

// SetHandle sets or changes the user's public handle. key must come from
// CanonicalHandle(handle). A first handle can be set at any time; changing
// it is allowed once per HandleChangeInterval (a change of letter case only
// is always allowed). The previous name is held for hold; the same user may
// take it back while it is held.
func (s *Store) SetHandle(ctx context.Context, user UserID, handle, key string, hold time.Duration) (retryAt time.Time, err error) {
	now := s.now()
	err = s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var cur, curKey *string
			var changed *time.Time
			if err := tx.QueryRow(ctx, `SELECT handle, handle_key, handle_changed_at FROM users WHERE id = $1 FOR UPDATE`,
				user).Scan(&cur, &curKey, &changed); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if curKey != nil && *curKey == key {
				if *cur != handle {
					_, err := tx.Exec(ctx, `UPDATE users SET handle = $2 WHERE id = $1`, user, handle)
					return err
				}
				return nil
			}
			if curKey != nil && changed != nil && now.Before(changed.Add(HandleChangeInterval)) {
				retryAt = changed.Add(HandleChangeInterval)
				return ErrHandleTooSoon
			}
			// Free an expired hold, or the user's own held name.
			if _, err := tx.Exec(ctx, `DELETE FROM namespaces WHERE name = $1 AND kind = 'held'
				AND (held_until <= $2 OR held_for = $3)`, key, now, user); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO namespaces (name, kind, created_at) VALUES ($1, 'user', $2)
				ON CONFLICT (name) DO NOTHING`, key, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return ErrHandleTaken
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET handle = $2, handle_key = $3, handle_changed_at = $4 WHERE id = $1`,
				user, handle, key, now); err != nil {
				return err
			}
			if curKey != nil {
				return releaseName(ctx, tx, *curKey, &user, now, hold)
			}
			return nil
		})
	})
	return retryAt, err
}

// SetLocale sets (or clears, with "") the preferred locale.
func (s *Store) SetLocale(ctx context.Context, user UserID, locale string) error {
	return s.exec(ctx, `UPDATE users SET locale = $2 WHERE id = $1`, user, nullable(locale))
}

// AcceptTerms records acceptance of a terms version.
func (s *Store) AcceptTerms(ctx context.Context, user UserID, version string) error {
	return s.exec(ctx, `UPDATE users SET terms_version = $2, terms_accepted_at = $3 WHERE id = $1`, user, version, s.now())
}

func (s *Store) exec(ctx context.Context, sql string, args ...any) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		tag, err := c.Exec(ctx, sql, args...)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// Session is a server-side session row.
type Session struct {
	TokenHash  []byte
	UserID     UserID
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateSession stores a new session (hash of the token only).
func (s *Store) CreateSession(ctx context.Context, user UserID, tokenHash []byte, maxAge time.Duration) (*Session, error) {
	now := s.now()
	ss := &Session{TokenHash: tokenHash, UserID: user, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(maxAge)}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)
			VALUES ($1, $2, $3, $3, $4)`, tokenHash, user, now, ss.ExpiresAt)
		return err
	})
	return ss, err
}

// touchEvery throttles last-seen writes.
const touchEvery = 5 * time.Minute

// LoadSession returns the session and its user if the session is neither
// past its absolute expiry nor idle for longer than idle. Activity is
// recorded at most every touchEvery.
func (s *Store) LoadSession(ctx context.Context, tokenHash []byte, idle time.Duration) (*Session, *User, error) {
	now := s.now()
	var ss Session
	var u *User
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		u, err = scanUser(c.QueryRow(ctx, `SELECT `+userCols+`, s.created_at, s.last_seen_at, s.expires_at
			FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = $1 AND s.expires_at > $2 AND s.last_seen_at > $3`, tokenHash, now, now.Add(-idle)),
			&ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt)
		if err != nil {
			return err
		}
		if now.Sub(ss.LastSeenAt) >= touchEvery {
			if _, err := c.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1`, tokenHash, now); err != nil {
				return err
			}
			if _, err := c.Exec(ctx, `UPDATE users SET last_seen_at = $2 WHERE id = $1`, u.ID, now); err != nil {
				return err
			}
			ss.LastSeenAt = now
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	ss.TokenHash, ss.UserID = tokenHash, u.ID
	return &ss, u, nil
}

// DeleteSession revokes one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
		return err
	})
}

// DeleteUserSessions revokes every session of the user; it returns how many.
func (s *Store) DeleteUserSessions(ctx context.Context, user UserID) (int64, error) {
	var n int64
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		tag, err := c.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, user)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// UseState records that a sign-in state reached the callback. It returns
// false if it had been used before (replay).
func (s *Store) UseState(ctx context.Context, stateHash []byte, expires time.Time) (bool, error) {
	fresh := false
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		tag, err := c.Exec(ctx, `INSERT INTO auth_flow_used (state_hash, expires_at) VALUES ($1, $2)
			ON CONFLICT (state_hash) DO NOTHING`, stateHash, expires)
		fresh = tag.RowsAffected() == 1
		return err
	})
	return fresh, err
}

// FindUser resolves a user id (UUID) or a handle (any casing).
func (s *Store) FindUser(ctx context.Context, ref string) (*User, error) {
	var u *User
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		u, err = scanUser(c.QueryRow(ctx, `SELECT `+userCols+` FROM users u
			WHERE u.id::text = lower($1) OR u.handle_key = lower($1)`, ref))
		return err
	})
	return u, err
}

// User loads a user by id.
func (s *Store) User(ctx context.Context, id UserID) (*User, error) { return s.FindUser(ctx, id) }

// SetRole changes a user's role (CLI only: `nday auth-role`). The change
// and its audit row (actor "cli", docs/admin.md) are one transaction.
func (s *Store) SetRole(ctx context.Context, id UserID, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("unknown role %q (user, moderator, admin)", role)
	}
	return s.cliChange(ctx, id, `UPDATE users SET role = $2 WHERE id = $1`, []any{role}, func(old *User) audit.Entry {
		return audit.Entry{Action: audit.UserRole, Details: map[string]any{"from": old.Role, "to": role}}
	})
}

// Suspend suspends a user (until nil = indefinitely) and revokes nothing:
// a suspended user can still sign in, sign out and delete the account. CLI
// only (`nday auth-suspend`); written to the audit log in the same
// transaction.
func (s *Store) Suspend(ctx context.Context, id UserID, until *time.Time, reason string) error {
	return s.cliChange(ctx, id, `UPDATE users SET status = 'suspended', suspended_until = $2, status_reason = $3 WHERE id = $1`,
		[]any{until, nullable(reason)}, func(*User) audit.Entry {
			d := map[string]any{"until": nil}
			if until != nil {
				d["until"] = until.UTC().Format(time.RFC3339)
			}
			return audit.Entry{Action: audit.UserSuspend, Reason: reason, Details: d}
		})
}

// Unsuspend makes a user active again (CLI only: `nday auth-unsuspend`;
// audited like Suspend).
func (s *Store) Unsuspend(ctx context.Context, id UserID) error {
	return s.cliChange(ctx, id, `UPDATE users SET status = 'active', suspended_until = NULL, status_reason = NULL WHERE id = $1`,
		nil, func(*User) audit.Entry { return audit.Entry{Action: audit.UserUnsuspend} })
}

// cliChange runs a server-side (CLI) change of one user row and its audit
// row in one transaction: lock the row (ErrNotFound when it does not exist,
// as before), run upd ($1 = id, then args), append entry(old row) with
// actor "cli" and the user as target.
func (s *Store) cliChange(ctx context.Context, id UserID, upd string, args []any, entry func(old *User) audit.Entry) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			old, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = $1 FOR UPDATE`, id))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, upd, append([]any{id}, args...)...); err != nil {
				return err
			}
			e := entry(old)
			e.TargetType, e.TargetID = audit.TargetUser, old.ID
			if old.Handle != nil {
				e.TargetLabel = *old.Handle
			}
			return audit.Write(ctx, tx, e)
		})
	})
}

// GCResult counts what housekeeping removed or changed.
type GCResult struct {
	Sessions, Flows, Names, Unsuspended, SuspendedIdentities int64
}

// GC deletes expired and idle sessions, used-state markers past their
// expiry, held names past their hold and suspended_identities rows past
// their end, and lifts elapsed suspensions.
func (s *Store) GC(ctx context.Context, idle time.Duration) (GCResult, error) {
	now := s.now()
	var r GCResult
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		for _, q := range []struct {
			n    *int64
			sql  string
			args []any
		}{
			{&r.Sessions, `DELETE FROM sessions WHERE expires_at <= $1 OR last_seen_at <= $2`, []any{now, now.Add(-idle)}},
			{&r.Flows, `DELETE FROM auth_flow_used WHERE expires_at <= $1`, []any{now}},
			{&r.Names, `DELETE FROM namespaces WHERE kind = 'held' AND held_until <= $1`, []any{now}},
			{&r.Unsuspended, `UPDATE users SET status = 'active', suspended_until = NULL, status_reason = NULL
				WHERE status = 'suspended' AND suspended_until <= $1`, []any{now}},
			{&r.SuspendedIdentities, `DELETE FROM suspended_identities WHERE suspended_until <= $1`, []any{now}},
		} {
			tag, err := c.Exec(ctx, q.sql, q.args...)
			if err != nil {
				return err
			}
			*q.n = tag.RowsAffected()
		}
		return nil
	})
	return r, err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
