package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// API token and feed key errors.
var (
	ErrTokenLimit = errors.New("you have the maximum number of API tokens; revoke one first")
)

// MaxAPITokens is the number of live (not revoked) API tokens per user.
const MaxAPITokens = 5

// RevokedTokenHistory is how many revoked tokens per user are kept (the
// oldest beyond it are deleted when a token is created).
const RevokedTokenHistory = 20

// MaxAPITokenName is the longest token name (characters, after trimming).
const MaxAPITokenName = 64

// APIToken is a personal access token row (the hash is never exposed).
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// tokenTouchEvery throttles last_used_at writes of an API token.
const tokenTouchEvery = time.Minute

// CreateAPIToken stores a new token (SHA-256 of the secret only) unless the
// user already has max live tokens (ErrTokenLimit).
func (s *Store) CreateAPIToken(ctx context.Context, user UserID, name string, hash []byte, max int) (*APIToken, error) {
	t := &APIToken{Name: name, CreatedAt: s.now()}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			// the user row lock serialises concurrent creations
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, user); err != nil {
				return err
			}
			// keep only the newest RevokedTokenHistory revoked rows, so
			// create/revoke loops cannot grow the table without bound (a
			// deleted row is refused like a revoked one: not found)
			if _, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL AND id NOT IN (
					SELECT id FROM api_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL
					ORDER BY revoked_at DESC, id DESC LIMIT $2)`, user, RevokedTokenHistory); err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, user).Scan(&n); err != nil {
				return err
			}
			if n >= max {
				return ErrTokenLimit
			}
			return tx.QueryRow(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, created_at) VALUES ($1, $2, $3, $4)
				RETURNING id::text`, user, name, hash, t.CreatedAt).Scan(&t.ID)
		})
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// APITokens lists the user's live tokens, oldest first.
func (s *Store) APITokens(ctx context.Context, user UserID) ([]APIToken, error) {
	out := []APIToken{}
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT id::text, name, created_at, last_used_at FROM api_tokens
			WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, id`, user)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIToken, error) {
			var t APIToken
			err := r.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt)
			t.CreatedAt = t.CreatedAt.UTC()
			if t.LastUsedAt != nil {
				u := t.LastUsedAt.UTC()
				t.LastUsedAt = &u
			}
			return t, err
		})
		return err
	})
	return out, err
}

// RevokeAPIToken revokes one of the user's tokens. Revoking a token that is
// already revoked succeeds and keeps the first revocation time; a token of
// another user (or none) is ErrNotFound.
func (s *Store) RevokeAPIToken(ctx context.Context, user UserID, id string) error {
	return s.exec(ctx, `UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, $3) WHERE id::text = $2 AND user_id = $1`,
		user, id, s.now())
}

// LoadAPIToken returns the owner of the live token with this hash
// (ErrNotFound when there is none or it is revoked) and records its use at
// most every tokenTouchEvery.
func (s *Store) LoadAPIToken(ctx context.Context, hash []byte) (*User, error) {
	now := s.now()
	var u *User
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var id string
		var last *time.Time
		var err error
		u, err = scanUser(c.QueryRow(ctx, `SELECT `+userCols+`, t.id::text, t.last_used_at
			FROM api_tokens t JOIN users u ON u.id = t.user_id
			WHERE t.token_hash = $1 AND t.revoked_at IS NULL`, hash), &id, &last)
		if err != nil {
			return err
		}
		if last == nil || now.Sub(*last) >= tokenTouchEvery {
			_, err = c.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2 WHERE id = $1::uuid
				AND (last_used_at IS NULL OR last_used_at <= $3)`, id, now, now.Add(-tokenTouchEvery))
		}
		return err
	})
	return u, err
}

// feedSaltLen is the length of a feed key salt.
const feedSaltLen = 16

// FeedSalt returns the user's feed key salt, creating it first when create
// is set (ErrNotFound when there is none and create is false).
func (s *Store) FeedSalt(ctx context.Context, user UserID, create bool) ([]byte, error) {
	var salt []byte
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		if create {
			fresh := make([]byte, feedSaltLen)
			_, _ = rand.Read(fresh)
			if _, err := c.Exec(ctx, `INSERT INTO feed_keys (user_id, salt, created_at) VALUES ($1, $2, $3)
				ON CONFLICT (user_id) DO NOTHING`, user, fresh, s.now()); err != nil {
				return err
			}
		}
		return c.QueryRow(ctx, `SELECT salt FROM feed_keys WHERE user_id = $1`, user).Scan(&salt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return salt, err
}

// RotateFeedSalt gives the user a new feed key salt (the old address stops
// working) and returns it.
func (s *Store) RotateFeedSalt(ctx context.Context, user UserID) ([]byte, error) {
	fresh := make([]byte, feedSaltLen)
	_, _ = rand.Read(fresh)
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, `INSERT INTO feed_keys (user_id, salt, created_at) VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO UPDATE SET salt = EXCLUDED.salt, created_at = EXCLUDED.created_at`, user, fresh, s.now())
		return err
	})
	return fresh, err
}

// FeedKeyOwner returns the user and feed key salt of user id (ErrNotFound
// when the user or the salt does not exist).
func (s *Store) FeedKeyOwner(ctx context.Context, user UserID) (*User, []byte, error) {
	var u *User
	var salt []byte
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		u, err = scanUser(c.QueryRow(ctx, `SELECT `+userCols+`, f.salt FROM feed_keys f JOIN users u ON u.id = f.user_id
			WHERE f.user_id = $1::uuid`, user), &salt)
		return err
	})
	return u, salt, err
}
