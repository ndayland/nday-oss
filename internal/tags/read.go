package tags

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Querier is satisfied by *pgx.Conn, pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// View is one visible tag of a CVE (public JSON: vuln.tags[]).
type View struct {
	Slug        string          `json:"slug"`
	Dimension   string          `json:"dimension"`
	Origin      string          `json:"origin"` // rule (nday's derivation) | staff (later phase)
	Basis       json.RawMessage `json:"basis"`
	RuleVersion *int            `json:"rule_version"`
}

// Decoded returns the basis as a Basis (rule rows; staff rows may carry
// other fields, which are ignored).
func (v View) Decoded() Basis {
	var b Basis
	_ = json.Unmarshal(v.Basis, &b)
	return b
}

// ForMany returns the visible tags of every given CVE (vuln_tag_visible:
// suppressed rule tags are left out), only slugs of the current vocabulary,
// in vocabulary order then origin (rule first). CVEs without tags are
// absent from the map.
func ForMany(ctx context.Context, q Querier, ids []string) (map[string][]View, error) {
	out := map[string][]View{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT cve_id, tag, origin, basis::text, rule_version FROM vuln_tag_visible
        WHERE cve_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cve, slug, origin, basis string
		var ver *int
		if err := rows.Scan(&cve, &slug, &origin, &basis, &ver); err != nil {
			return nil, err
		}
		t, ok := Lookup(slug)
		if !ok {
			continue // retired slug, until the next --all removes it
		}
		out[cve] = append(out[cve], View{Slug: slug, Dimension: t.Dim, Origin: origin, Basis: json.RawMessage(basis), RuleVersion: ver})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, vs := range out {
		sortViews(vs)
	}
	return out, nil
}

func sortViews(vs []View) {
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0 && viewLess(vs[j], vs[j-1]); j-- {
			vs[j], vs[j-1] = vs[j-1], vs[j]
		}
	}
}

func viewLess(a, b View) bool {
	if oa, ob := Order(a.Slug), Order(b.Slug); oa != ob {
		return oa < ob
	}
	return a.Origin > b.Origin // "rule" before "staff"
}

// SlugsMany returns, per CVE, its distinct visible slugs in vocabulary
// order (list rows).
func SlugsMany(ctx context.Context, q Querier, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT DISTINCT cve_id, tag FROM vuln_tag_visible WHERE cve_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cve, slug string
		if err := rows.Scan(&cve, &slug); err != nil {
			return nil, err
		}
		if Valid(slug) {
			out[cve] = append(out[cve], slug)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, s := range out {
		Sort(s)
	}
	return out, nil
}

// CountsReport is the precomputed number of CVEs per tag.
type CountsReport struct {
	// Counts by slug (vocabulary slugs only; a tag no CVE has is absent).
	Counts map[string]int64
	// RefreshedAt: when vuln_tag_count was last rebuilt (nil: never).
	RefreshedAt *time.Time
}

// Counts reads vuln_tag_count (cheap: one row per tag).
func Counts(ctx context.Context, q Querier) (*CountsReport, error) {
	r := &CountsReport{Counts: map[string]int64{}}
	rows, err := q.Query(ctx, `SELECT tag, n FROM vuln_tag_count`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var slug string
		var n int64
		if err := rows.Scan(&slug, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if Valid(slug) {
			r.Counts[slug] = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT counts_refreshed_at FROM tag_run WHERE id = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&r.RefreshedAt); err != nil {
			return nil, err
		}
	}
	if r.RefreshedAt != nil {
		t := r.RefreshedAt.UTC()
		r.RefreshedAt = &t
	}
	return r, rows.Err()
}
