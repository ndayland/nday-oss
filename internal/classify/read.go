package classify

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Querier is satisfied by *pgx.Conn, pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Provenance names where a fact came from.
type Provenance struct {
	Source    string `json:"source"`     // cve-cna | cve-adp | nvd-primary | nvd-secondary | ghsa
	SourceOrg string `json:"source_org"` // CNA/ADP short name, NVD source identifier, GHSA id
}

// CWEEntry is one CWE id with every source that states it.
type CWEEntry struct {
	ID      string       `json:"id"`
	Sources []Provenance `json:"sources"`
}

// CVSSEntry is one stored vector.
type CVSSEntry struct {
	Version   string   `json:"version"`
	Vector    string   `json:"vector"`
	BaseScore *float64 `json:"base_score"`
	Severity  *string  `json:"severity"`
	Source    string   `json:"source"`
	SourceOrg string   `json:"source_org"`
}

// Input is the raw record version a source's rows were derived from.
type Input struct {
	Source       string    `json:"source"` // cvelist | nvd | ghsa
	SourceKey    string    `json:"source_key"`
	ContentHash  string    `json:"content_hash"`
	Rejected     bool      `json:"rejected"`
	ClassifiedAt time.Time `json:"classified_at"`
}

// Classification of one CVE. CWE: by numeric id, sources by Precedence then
// source_org. CVSS: by version (newest first), then Precedence, then
// source_org. Inputs (Go only, not in the public JSON): what was looked at;
// a source with Rejected=true contributed no rows because it marks the CVE
// rejected. A CVE without any Input has not been classified (yet).
type Classification struct {
	CVEID  string      `json:"-"`
	CWE    []CWEEntry  `json:"cwe"`
	CVSS   []CVSSEntry `json:"cvss"`
	Inputs []Input     `json:"-"`
}

func newClassification(id string) *Classification {
	return &Classification{CVEID: id, CWE: []CWEEntry{}, CVSS: []CVSSEntry{}, Inputs: []Input{}}
}

// RejectedBy lists the raw sources that mark the CVE rejected.
func (c *Classification) RejectedBy() []string {
	var out []string
	for _, in := range c.Inputs {
		if in.Rejected && !containsStr(out, in.Source) {
			out = append(out, in.Source)
		}
	}
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// manySQL returns every row of the three tables for a list of CVEs in one
// statement.
const manySQL = `
SELECT 1 AS kind, cve_id, cwe AS a, '' AS b, NULL::float8 AS score, NULL::text AS severity, source, source_org,
       false AS rejected, NULL::timestamptz AS at
FROM vuln_cwe WHERE cve_id = ANY($1)
UNION ALL
SELECT 2, cve_id, version, vector, base_score::float8, severity, source, source_org, false, NULL
FROM vuln_cvss WHERE cve_id = ANY($1)
UNION ALL
SELECT 3, cve_id, source_key, content_hash, NULL, NULL, source, '', rejected, classified_at
FROM vuln_classify_input WHERE cve_id = ANY($1)`

// For returns the classification of one CVE (empty lists when none).
func For(ctx context.Context, q Querier, cveID string) (*Classification, error) {
	m, err := ForMany(ctx, q, []string{cveID})
	if err != nil {
		return nil, err
	}
	return m[cveID], nil
}

// ForMany returns the classification of every given CVE (each id present in
// the map, possibly empty) with one query.
func ForMany(ctx context.Context, q Querier, ids []string) (map[string]*Classification, error) {
	out := make(map[string]*Classification, len(ids))
	for _, id := range ids {
		out[id] = newClassification(id)
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, manySQL, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cwes := map[string]map[string]*CWEEntry{}
	for rows.Next() {
		var kind int
		var cve, a, b, source, org string
		var score *float64
		var sev *string
		var rejected bool
		var at *time.Time
		if err := rows.Scan(&kind, &cve, &a, &b, &score, &sev, &source, &org, &rejected, &at); err != nil {
			return nil, err
		}
		c := out[cve]
		if c == nil {
			continue
		}
		switch kind {
		case 1:
			m := cwes[cve]
			if m == nil {
				m = map[string]*CWEEntry{}
				cwes[cve] = m
			}
			e := m[a]
			if e == nil {
				e = &CWEEntry{ID: a}
				m[a] = e
			}
			e.Sources = append(e.Sources, Provenance{Source: source, SourceOrg: org})
		case 2:
			c.CVSS = append(c.CVSS, CVSSEntry{Version: a, Vector: b, BaseScore: score, Severity: sev, Source: source, SourceOrg: org})
		case 3:
			in := Input{Source: source, SourceKey: a, ContentHash: b, Rejected: rejected}
			if at != nil {
				in.ClassifiedAt = at.UTC()
			}
			c.Inputs = append(c.Inputs, in)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for cve, m := range cwes {
		c := out[cve]
		for _, e := range m {
			sort.Slice(e.Sources, func(i, j int) bool { return provLess(e.Sources[i], e.Sources[j]) })
			c.CWE = append(c.CWE, *e)
		}
		sort.Slice(c.CWE, func(i, j int) bool { return cweLess(c.CWE[i].ID, c.CWE[j].ID) })
	}
	for _, c := range out {
		sort.Slice(c.CVSS, func(i, j int) bool {
			a, b := c.CVSS[i], c.CVSS[j]
			if a.Version != b.Version {
				return a.Version > b.Version // "4.0" > "3.1" > "3.0" > "2.0"
			}
			return provLess(Provenance{a.Source, a.SourceOrg}, Provenance{b.Source, b.SourceOrg})
		})
		sort.Slice(c.Inputs, func(i, j int) bool {
			a, b := c.Inputs[i], c.Inputs[j]
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			return a.SourceKey < b.SourceKey
		})
	}
	return out, nil
}

func provLess(a, b Provenance) bool {
	pa, pb := rank(a.Source), rank(b.Source)
	if pa != pb {
		return pa < pb
	}
	return a.SourceOrg < b.SourceOrg
}

func rank(source string) int {
	if r, ok := Precedence[source]; ok {
		return r
	}
	return len(Precedence) + 1
}

func cweLess(a, b string) bool {
	na, _ := strconv.Atoi(strings.TrimPrefix(a, "CWE-"))
	nb, _ := strconv.Atoi(strings.TrimPrefix(b, "CWE-"))
	if na != nb {
		return na < nb
	}
	return a < b
}

// BestCVSS returns, per version, the entry of the highest-precedence source
// (cve-cna > cve-adp > nvd-primary > nvd-secondary > ghsa; ties: lowest
// source_org).
func (c *Classification) BestCVSS() map[string]CVSSEntry {
	out := map[string]CVSSEntry{}
	for _, e := range c.CVSS {
		cur, ok := out[e.Version]
		if !ok || provLess(Provenance{e.Source, e.SourceOrg}, Provenance{cur.Source, cur.SourceOrg}) {
			out[e.Version] = e
		}
	}
	return out
}

// bestManySQL is BestCVSS for many CVEs in one query.
const bestManySQL = `
SELECT DISTINCT ON (cve_id, version) cve_id, version, vector, base_score::float8, severity, source, source_org
FROM vuln_cvss WHERE cve_id = ANY($1)
ORDER BY cve_id, version,
         CASE source WHEN 'cve-cna' THEN 1 WHEN 'cve-adp' THEN 2 WHEN 'nvd-primary' THEN 3
                     WHEN 'nvd-secondary' THEN 4 WHEN 'ghsa' THEN 5 ELSE 6 END,
         source_org COLLATE "C"`

// BestCVSSMany returns BestCVSS for every given CVE (absent: no vector) in
// one query.
func BestCVSSMany(ctx context.Context, q Querier, ids []string) (map[string]map[string]CVSSEntry, error) {
	out := map[string]map[string]CVSSEntry{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, bestManySQL, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cve string
		var e CVSSEntry
		if err := rows.Scan(&cve, &e.Version, &e.Vector, &e.BaseScore, &e.Severity, &e.Source, &e.SourceOrg); err != nil {
			return nil, err
		}
		if out[cve] == nil {
			out[cve] = map[string]CVSSEntry{}
		}
		out[cve][e.Version] = e
	}
	return out, rows.Err()
}
