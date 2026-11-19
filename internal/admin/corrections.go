package admin

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The corrections module (/admin/corrections; docs/corrections.md): the
// open queue of readers' corrections (oldest first) and the decided ones
// (most recently decided first). Read-only queries on ReadDB; the decisions
// are the endpoints of internal/corrections.

// CorrectionsPage is the page size of both lists.
const CorrectionsPage = ListPage

// Correction is a correction as the staff page shows it. Body, EvidenceURL
// and the notes are user or staff input: show them as text (and the link
// only through a safe-link check).
type Correction struct {
	ID           string
	CVE          string
	Category     string
	Body         string
	EvidenceURL  *string
	Status       string
	CreatedAt    time.Time
	SubmitterID  *string
	Submitter    *string // handle (nil: none, or account deleted)
	DecidedAt    *time.Time
	DeciderID    *string
	Decider      *string
	PublicNote   *string
	InternalNote *string
}

const corrCols = `c.id::text, c.cve_id, c.category, c.body, c.evidence_url, c.status, c.created_at,
	c.submitter_id::text, su.handle, c.decided_at, c.decided_by::text, du.handle, c.public_note, c.internal_note
	FROM vuln_corrections c LEFT JOIN users su ON su.id = c.submitter_id LEFT JOIN users du ON du.id = c.decided_by `

func scanCorrection(row pgx.Row) (*Correction, error) {
	x := &Correction{}
	if err := row.Scan(&x.ID, &x.CVE, &x.Category, &x.Body, &x.EvidenceURL, &x.Status, &x.CreatedAt,
		&x.SubmitterID, &x.Submitter, &x.DecidedAt, &x.DeciderID, &x.Decider, &x.PublicNote, &x.InternalNote); err != nil {
		return nil, err
	}
	x.CreatedAt = x.CreatedAt.UTC()
	if x.DecidedAt != nil {
		t := x.DecidedAt.UTC()
		x.DecidedAt = &t
	}
	return x, nil
}

// Corrections lists one page of the pending corrections oldest first
// (decided=false) or of the decided ones most recently decided first
// (numbered: the table is small), plus the number of pending ones.
func (s *Service) Corrections(ctx context.Context, decided bool, page int) ([]*Correction, Window, int, error) {
	var out []*Correction
	var w Window
	pending := 0
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var all int
		if err := c.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'pending')::int, count(*)::int FROM vuln_corrections`).
			Scan(&pending, &all); err != nil {
			return err
		}
		cond, order, total := `c.status = 'pending'`, `c.created_at, c.id`, pending
		if decided {
			cond, order, total = `c.status <> 'pending'`, `c.decided_at DESC, c.id DESC`, all-pending
		}
		w = window(total, page)
		rows, err := c.Query(ctx, `SELECT `+corrCols+`WHERE `+cond+` ORDER BY `+order+` LIMIT $1 OFFSET $2`, CorrectionsPage, w.Offset())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scanCorrection(rows)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, Window{}, 0, err
	}
	return out, w, pending, nil
}
