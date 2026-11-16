package site

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Readers' corrections (migrations/0017_corrections.sql,
// docs/corrections.md). What is PUBLIC about them is exactly what
// Corrections returns for ACCEPTED rows: when it was accepted, its
// category, the note the editor wrote and the submitter's current public
// handle (none while the submitter is suspended). Pending and rejected
// corrections, the submitter's own text and evidence link, the internal note and who decided are never read here;
// they reach the submitter (GET /api/corrections/mine) and staff
// (/admin/corrections) only.

// SuspendedNowSQL is auth.User.EffectiveStatus(now) == auth.StatusSuspended
// as an SQL condition on the users row aliased u, with now the SQL
// expression of the time (a parameter such as "$3"): status 'suspended'
// and no end or an end after now (an elapsed suspension counts as active,
// whether or not the housekeeping has lifted it yet). It is never NULL: a
// missing row (an unmatched LEFT JOIN) is not suspended. It lives here
// because internal/auth imports this package.
func SuspendedNowSQL(u, now string) string {
	return "coalesce(" + u + ".status = 'suspended' AND (" + u + ".suspended_until IS NULL OR " + u + ".suspended_until > " +
		now + "), false)"
}

// MaxPublicCorrections caps the revision log of a vulnerability page.
const MaxPublicCorrections = 100

// PublicCorrection is one accepted correction as the vulnerability page
// shows it.
type PublicCorrection struct {
	AcceptedAt time.Time
	Category   string
	Note       string // written by an editor; plain text
	// Handle is the submitter's public handle; nil: account deleted, no
	// handle, or suspended now (auth.User.EffectiveStatus: an elapsed
	// suspension counts as active).
	Handle *string
	// Deleted: the submitter deleted the account (Handle is nil).
	Deleted bool
}

// Corrections lists the accepted corrections of cve, most recently
// accepted first (at most MaxPublicCorrections).
func (s *Store) Corrections(ctx context.Context, cve string) ([]PublicCorrection, error) {
	out := []PublicCorrection{}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, `SELECT c.decided_at, c.category, c.public_note,
	CASE WHEN NOT `+SuspendedNowSQL("u", "$3")+` THEN u.handle END, c.submitter_id IS NULL
FROM vuln_corrections c LEFT JOIN users u ON u.id = c.submitter_id
WHERE c.cve_id = $1 AND c.status = 'accepted'
ORDER BY c.decided_at DESC, c.id DESC
LIMIT $2`, cve, MaxPublicCorrections, s.now().UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PublicCorrection
			if err := rows.Scan(&p.AcceptedAt, &p.Category, &p.Note, &p.Handle, &p.Deleted); err != nil {
				return err
			}
			p.AcceptedAt = p.AcceptedAt.UTC()
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
