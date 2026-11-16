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
const CorrectionsPage = 30

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

// Corrections lists pending corrections oldest first (decided=false) or
// decided ones most recently decided first, after cursor, plus the number
// of pending ones.
func (s *Service) Corrections(ctx context.Context, decided bool, after *Cursor) ([]*Correction, *Cursor, int, error) {
	var out []*Correction
	pending := 0
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		if err := c.QueryRow(ctx, `SELECT count(*)::int FROM vuln_corrections WHERE status = 'pending'`).Scan(&pending); err != nil {
			return err
		}
		var rows pgx.Rows
		var err error
		if decided {
			cur := Cursor{At: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}
			if after != nil {
				cur = *after
			}
			rows, err = c.Query(ctx, `SELECT `+corrCols+`WHERE c.status <> 'pending' AND (c.decided_at, c.id) < ($1, $2::uuid)
				ORDER BY c.decided_at DESC, c.id DESC LIMIT $3`, cur.At, cur.ID, CorrectionsPage+1)
		} else {
			cur := Cursor{At: time.Unix(0, 0).UTC(), ID: "00000000-0000-0000-0000-000000000000"}
			if after != nil {
				cur = *after
			}
			rows, err = c.Query(ctx, `SELECT `+corrCols+`WHERE c.status = 'pending' AND (c.created_at, c.id) > ($1, $2::uuid)
				ORDER BY c.created_at, c.id LIMIT $3`, cur.At, cur.ID, CorrectionsPage+1)
		}
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
		return nil, nil, 0, err
	}
	var next *Cursor
	if len(out) > CorrectionsPage {
		out = out[:CorrectionsPage]
		last := out[len(out)-1]
		next = &Cursor{At: last.CreatedAt, ID: last.ID}
		if decided && last.DecidedAt != nil {
			next.At = *last.DecidedAt
		}
	}
	return out, next, pending, nil
}
