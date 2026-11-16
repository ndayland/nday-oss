package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth/webauthn"
)

// Passkey errors.
var (
	ErrCredentialExists = errors.New("this passkey is already registered")
	ErrLastMethod       = errors.New("cannot remove the last sign-in method")
	ErrPasskeyLimit     = errors.New("you have the maximum number of passkeys; delete one first")
)

// Passkey is a stored WebAuthn credential (key material excluded from JSON).
type Passkey struct {
	ID             string     `json:"id"`
	UserID         UserID     `json:"-"`
	CredentialID   []byte     `json:"-"`
	PublicKey      []byte     `json:"-"`
	Algorithm      int        `json:"-"`
	SignCount      uint32     `json:"-"`
	BackupEligible bool       `json:"-"`
	BackedUp       bool       `json:"backed_up"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	UserHandle     []byte     `json:"-"` // the owner's users.webauthn_id
}

// WebAuthnID returns the user's WebAuthn user handle, creating it (32
// random bytes) on first use.
func (s *Store) WebAuthnID(ctx context.Context, user UserID) ([]byte, error) {
	fresh := make([]byte, 32)
	_, _ = rand.Read(fresh)
	var h []byte
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `UPDATE users SET webauthn_id = COALESCE(webauthn_id, $2) WHERE id = $1 RETURNING webauthn_id`,
			user, fresh).Scan(&h)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return h, err
}

// CredentialIDs lists the user's credential ids (excludeCredentials).
func (s *Store) CredentialIDs(ctx context.Context, user UserID) ([][]byte, error) {
	var out [][]byte
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT credential_id FROM passkeys WHERE user_id = $1 ORDER BY created_at`, user)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[[]byte])
		return err
	})
	return out, err
}

func insertPasskey(ctx context.Context, tx pgx.Tx, user UserID, cr *webauthn.Credential, transports []string, name string, now time.Time) (string, error) {
	var aaguid any
	if len(cr.AAGUID) == 16 {
		aaguid = cr.AAGUID
	}
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO passkeys (user_id, credential_id, public_key, algorithm, sign_count, aaguid,
			transports, backup_eligible, backed_up, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6::uuid, $7, $8, $9, $10, $11) RETURNING id::text`,
		user, cr.ID, cr.PublicKey, cr.Alg, int64(cr.SignCount), aaguidText(aaguid), transports, cr.BE, cr.BS, name, now).Scan(&id)
	if isUnique(err, "passkeys_credential_id_key") {
		return "", ErrCredentialExists
	}
	return id, err
}

// aaguidText renders a 16-byte AAGUID as a UUID string (nil stays nil).
func aaguidText(v any) any {
	b, ok := v.([]byte)
	if !ok {
		return nil
	}
	const hx = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hx[c>>4], hx[c&15])
	}
	return string(out)
}

// AddPasskey stores a verified credential for user unless the user already
// has max passkeys (ErrPasskeyLimit).
func (s *Store) AddPasskey(ctx context.Context, user UserID, cr *webauthn.Credential, transports []string, name string, max int) (string, error) {
	var id string
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			// the user row lock serialises concurrent registrations
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, user); err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM passkeys WHERE user_id = $1`, user).Scan(&n); err != nil {
				return err
			}
			if n >= max {
				return ErrPasskeyLimit
			}
			var err error
			id, err = insertPasskey(ctx, tx, user, cr, transports, name, s.now())
			return err
		})
	})
	return id, err
}

// SignUpWithPasskey creates a user that has only a passkey.
func (s *Store) SignUpWithPasskey(ctx context.Context, webauthnID []byte, displayName string, cr *webauthn.Credential,
	transports []string, name string) (UserID, error) {
	now := s.now()
	var id UserID
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `INSERT INTO users (display_name, webauthn_id, created_at, last_seen_at)
				VALUES ($1, $2, $3, $3) RETURNING id::text`, nullable(displayName), webauthnID, now).Scan(&id); err != nil {
				return err
			}
			_, err := insertPasskey(ctx, tx, id, cr, transports, name, now)
			return err
		})
	})
	return id, err
}

const passkeyCols = `p.id::text, p.user_id::text, p.credential_id, p.public_key, p.algorithm, p.sign_count, p.backup_eligible,
	p.backed_up, p.name, p.created_at, p.last_used_at`

func scanPasskey(row pgx.Row, extra ...any) (*Passkey, error) {
	p := &Passkey{}
	var cnt int64
	err := row.Scan(append([]any{&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.Algorithm, &cnt, &p.BackupEligible,
		&p.BackedUp, &p.Name, &p.CreatedAt, &p.LastUsedAt}, extra...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	p.SignCount = uint32(cnt)
	p.CreatedAt = p.CreatedAt.UTC()
	if p.LastUsedAt != nil {
		t := p.LastUsedAt.UTC()
		p.LastUsedAt = &t
	}
	return p, err
}

// PasskeyByCredentialID finds a credential (with its owner's user handle).
func (s *Store) PasskeyByCredentialID(ctx context.Context, credID []byte) (*Passkey, error) {
	var p *Passkey
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		var uh []byte
		p, err = scanPasskey(c.QueryRow(ctx, `SELECT `+passkeyCols+`, u.webauthn_id FROM passkeys p JOIN users u ON u.id = p.user_id
			WHERE p.credential_id = $1`, credID), &uh)
		if p != nil {
			p.UserHandle = uh
		}
		return err
	})
	return p, err
}

// Passkeys lists the user's passkeys (oldest first).
func (s *Store) Passkeys(ctx context.Context, user UserID) ([]Passkey, error) {
	var out []Passkey
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+passkeyCols+` FROM passkeys p WHERE p.user_id = $1 ORDER BY p.created_at, p.id`, user)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Passkey, error) {
			p, err := scanPasskey(r)
			if err != nil {
				return Passkey{}, err
			}
			return *p, nil
		})
		return err
	})
	return out, err
}

// PasskeyUsed records a successful assertion (counter and backup state,
// WebAuthn L3 §7.2 step 24). The counter check is part of the UPDATE, so it
// is atomic: it reports false, and changes
// nothing, unless signCount is greater than the stored value or both are 0
// (synced passkeys without a counter).
func (s *Store) PasskeyUsed(ctx context.Context, id string, signCount uint32, backedUp bool) (bool, error) {
	var ok bool
	err := s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		tag, err := c.Exec(ctx, `UPDATE passkeys SET sign_count = $2, backed_up = $3, last_used_at = $4
			WHERE id = $1 AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`, id, int64(signCount), backedUp, s.now())
		ok = tag.RowsAffected() == 1
		return err
	})
	return ok, err
}

// PasskeyCounterRegression records a refused assertion whose counter did
// not increase.
func (s *Store) PasskeyCounterRegression(ctx context.Context, id string) error {
	return s.exec(ctx, `UPDATE passkeys SET counter_regressions = counter_regressions + 1, last_regression_at = $2 WHERE id = $1`,
		id, s.now())
}

// RenamePasskey renames one of the user's passkeys.
func (s *Store) RenamePasskey(ctx context.Context, user UserID, id, name string) error {
	return s.exec(ctx, `UPDATE passkeys SET name = $3 WHERE id::text = $2 AND user_id = $1`, user, id, name)
}

// DeletePasskey removes one of the user's passkeys unless no other usable
// sign-in method would remain (other passkeys, identities of the providers
// in usable): ErrLastMethod when nothing else exists, ErrNoUsableMethod
// when only identities of disabled providers would remain. Passkeys are on
// whenever this is reachable.
func (s *Store) DeletePasskey(ctx context.Context, user UserID, id string, usable []string) error {
	return s.DB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, user); err != nil {
				return err
			}
			var mine, otherPks, ids, usableIDs int
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE id::text = $2), count(*) FILTER (WHERE id::text <> $2),
					(SELECT count(*) FROM identities WHERE user_id = $1),
					(SELECT count(*) FROM identities WHERE user_id = $1 AND provider = ANY($3))
				FROM passkeys WHERE user_id = $1`, user, id, usable).Scan(&mine, &otherPks, &ids, &usableIDs); err != nil {
				return err
			}
			if mine == 0 {
				return ErrNotFound
			}
			if err := lastMethod(otherPks+ids, usableIDs, otherPks, true, ErrLastMethod); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM passkeys WHERE id::text = $2 AND user_id = $1`, user, id)
			return err
		})
	})
}
