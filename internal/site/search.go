package site

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Search limits.
const (
	MaxQueryRunes      = 100
	MinTextQueryRunes  = 2
	DefaultSearchLimit = 20
	MaxSearchLimit     = 50
)

// Search kinds (SearchResult.Kind).
const (
	SearchCVE      = "cve_id"    // exact/prefix match on the CVE id
	SearchAlias    = "alias"     // exact GHSA id: the vuln keyed by it, then CVEs with it as alias
	SearchText     = "text"      // substring of title, title_zh, vendor, product
	SearchTooShort = "too_short" // fewer than 2 characters: nothing searched
	SearchEmpty    = "empty"     // blank query
	SearchTags     = "tags"      // blank query with a tag filter: every CVE with the tags
)

// SearchRow is one search hit.
type SearchRow struct {
	CVEID   string  `json:"cve_id"`
	Title   *string `json:"title"`
	TitleZh *string `json:"title_zh"`
	// the effective title and its origin (titles.go)
	TitleInfo
	Products         []Product  `json:"products"` // up to 2
	ProductCount     int        `json:"product_count"`
	Stage            *string    `json:"stage"` // nil if the vuln has no events
	StageCode        *string    `json:"stage_code"`
	LastTransitionAt *time.Time `json:"last_transition_at"`
	IsRejected       bool       `json:"is_rejected"`
	Tags             []string   `json:"tags"` // the CVE's tags (slugs, vocabulary order)
}

// SearchResult is the answer to Search.
type SearchResult struct {
	Query     string      `json:"query"` // normalised query
	Kind      string      `json:"kind"`
	Tags      []string    `json:"tags"`     // the tag filter (AND)
	CVSSMin   *float64    `json:"cvss_min"` // the score filter's bounds (cvss.go); nil when not set
	CVSSMax   *float64    `json:"cvss_max"`
	Rows      []SearchRow `json:"rows"`
	Truncated bool        `json:"truncated"` // more matches than returned
}

var (
	// "CVE-2026-1028", "cve2026", "cve-2026-", "2026-1028"
	cvePrefixRe = regexp.MustCompile(`^(?i:cve)[-_ ]?([0-9]{1,4})(-([0-9]{0,19}))?$|^([0-9]{4})-([0-9]{0,19})$`)
	ghsaRe      = regexp.MustCompile(`^(?i)ghsa(-[0-9a-z]{4}){3}$`) // any alphabet, unlike ParseGHSAID
	spaceRe     = regexp.MustCompile(`\s+`)
)

// MaxGHSALookup is how many CVE ids VulnsByGHSA returns at most: enough to
// tell none, one and several apart.
const MaxGHSALookup = 3

// VulnsByGHSA returns the CVE ids (sorted) that have the GHSA id as an alias,
// at most MaxGHSALookup. Only CVEs the vuln table holds, which is what the
// detail page and search show. id is case-insensitive; one that is not a GHSA
// id is an *InputError.
func (s *Store) VulnsByGHSA(ctx context.Context, id string) ([]string, error) {
	g, ok := ParseGHSAID(id)
	if !ok {
		return nil, &InputError{Param: "ghsa", Msg: "not a GHSA id (expected GHSA-xxxx-xxxx-xxxx)"}
	}
	out := []string{}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, `SELECT DISTINCT a.cve_id FROM vuln_alias a JOIN vuln v USING (cve_id)
WHERE a.alias_type = 'ghsa' AND a.alias = $1 ORDER BY a.cve_id LIMIT $2`, g, MaxGHSALookup)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// NormalizeQuery trims and collapses whitespace; an over-long query is an
// *InputError.
func NormalizeQuery(q string) (string, error) {
	q = strings.TrimSpace(spaceRe.ReplaceAllString(q, " "))
	if !utf8.ValidString(q) {
		return "", &InputError{Param: "q", Msg: "not valid UTF-8"}
	}
	if utf8.RuneCountInString(q) > MaxQueryRunes {
		return "", &InputError{Param: "q", Msg: fmt.Sprintf("longer than %d characters", MaxQueryRunes)}
	}
	if strings.ContainsRune(q, 0) {
		return "", &InputError{Param: "q", Msg: "contains NUL"}
	}
	return q, nil
}

// EscapeLike escapes LIKE metacharacters (\ % _) for use with ESCAPE '\'.
func EscapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// cvePrefix maps an id-like query to an upper-case CVE id prefix.
func cvePrefix(q string) (string, bool) {
	m := cvePrefixRe.FindStringSubmatch(q)
	switch {
	case m == nil:
		return "", false
	case m[4] != "": // "2026-1028"
		return "CVE-" + m[4] + "-" + m[5], true
	case m[2] != "": // "cve-2026-1028", "cve-2026-"
		if len(m[1]) < 4 {
			return "", false // "cve-20-1": year incomplete
		}
		return "CVE-" + m[1] + "-" + m[3], true
	default: // "cve-20", "CVE2026"
		return "CVE-" + m[1], true
	}
}

const searchCols = `
SELECT v.cve_id, v.title, v.title_zh, s.stage, s.last_transition_at, COALESCE(s.is_rejected, false),
       COALESCE(af.n, 0), COALESCE(af.vendors, '{}'), COALESCE(af.products, '{}'), ` + titleCols

const searchFrom = `
LEFT JOIN vuln_state_mat s USING (cve_id)
LEFT JOIN LATERAL (` + productsLateral + `) af ON true` + titleJoinV

// Prefix scan on vuln_cve_id_c_idx: bytewise range [prefix, prefix+1).
// The exact id sorts first (shortest), then longer ids with that prefix.
const searchCVESQL = `
WITH m AS (
    SELECT cve_id FROM vuln
    WHERE cve_id COLLATE "C" >= $1 AND cve_id COLLATE "C" < $2%s
    ORDER BY cve_id COLLATE "C"
    LIMIT $3)` + searchCols + `
FROM m JOIN vuln v USING (cve_id)` + searchFrom + `
ORDER BY length(v.cve_id), v.cve_id COLLATE "C"`

// GHSA id: the vulnerability keyed by it (first), then the CVEs that have
// it as an alias.
const searchAliasSQL = `
WITH m AS (
    SELECT DISTINCT a.cve_id FROM (
        SELECT cve_id FROM vuln_alias WHERE alias_type = 'ghsa' AND alias = $1
        UNION SELECT cve_id FROM vuln WHERE cve_id = $1) a
    WHERE true%s
    LIMIT $2)` + searchCols + `
FROM m JOIN vuln v USING (cve_id)` + searchFrom + `
ORDER BY v.cve_id = $1 DESC, v.cve_id`

// idOrderDesc is the ORDER BY tail "newest id first" on the id column of
// table alias t: CVE ids by year, then sequence number, numerically
// (CVE-2026-100000 before CVE-2026-99999); GHSA ids, which carry no order,
// after them, by text. The casts only run on CVE ids.
func idOrderDesc(t string) string {
	c := t + ".cve_id"
	isCVE := "left(" + c + ", 4) = 'CVE-'" // no "%": the SQL goes through fmt.Sprintf
	return "CASE WHEN " + isCVE + " THEN split_part(" + c + ", '-', 2)::int END DESC NULLS LAST, " +
		"CASE WHEN " + isCVE + " THEN split_part(" + c + ", '-', 3)::numeric END DESC NULLS LAST, " + c + " DESC"
}

// Text: ILIKE with escaped pattern (trigram indexes from migrations 0003
// and 0031 when pg_trgm is available) on the record's titles, the composed
// and staff titles (vuln_title), vendors and products. Most recently
// active first.
var searchTextSQL = `
WITH m AS (
    SELECT cve_id FROM vuln WHERE title ILIKE $1 ESCAPE '\' OR title_zh ILIKE $1 ESCAPE '\'
    UNION
    SELECT cve_id FROM vuln_title WHERE composed_en ILIKE $1 ESCAPE '\' OR staff_title ILIKE $1 ESCAPE '\'
    UNION
    SELECT cve_id FROM affected WHERE vendor ILIKE $1 ESCAPE '\' OR product ILIKE $1 ESCAPE '\'),
r AS (
    SELECT m.cve_id FROM m LEFT JOIN vuln_state_mat s USING (cve_id)
    WHERE true%s
    ORDER BY s.last_transition_at DESC NULLS LAST,
             ` + idOrderDesc("m") + `
    LIMIT $2)` + searchCols + `
FROM r JOIN vuln v USING (cve_id)` + searchFrom + `
ORDER BY s.last_transition_at DESC NULLS LAST,
         ` + idOrderDesc("v")

// Tags only (blank query): every CVE with all the tags, most recently
// active first, like the text search.
var searchTagsSQL = `
WITH r AS (
    SELECT v.cve_id FROM vuln v LEFT JOIN vuln_state_mat s USING (cve_id)
    WHERE true%s
    ORDER BY s.last_transition_at DESC NULLS LAST,
             ` + idOrderDesc("v") + `
    LIMIT $1)` + searchCols + `
FROM r JOIN vuln v USING (cve_id)` + searchFrom + `
ORDER BY s.last_transition_at DESC NULLS LAST,
         ` + idOrderDesc("v")

// Search is SearchTagged without a tag filter.
func (s *Store) Search(ctx context.Context, q string, limit int) (*SearchResult, error) {
	return s.SearchTagged(ctx, q, nil, limit)
}

// SearchFilter narrows a search: Tags as SearchTagged's tagSlugs, and the
// displayed CVSS score within CVSSMin..CVSSMax (cvss.go; "" = no bound).
type SearchFilter struct {
	Tags             []string
	CVSSMin, CVSSMax string
}

// SearchTagged is SearchFiltered with a tag filter only.
func (s *Store) SearchTagged(ctx context.Context, q string, tagSlugs []string, limit int) (*SearchResult, error) {
	return s.SearchFiltered(ctx, q, SearchFilter{Tags: tagSlugs}, limit)
}

// SearchFiltered finds up to limit vulnerabilities (default 20, max 50): a query
// that looks like a CVE id (with or without "CVE-", any case) is an exact
// or prefix match on the id; a GHSA id matches the vulnerability keyed by it
// and the CVEs that have it as an alias; anything else is a
// case-insensitive substring match on title, title_zh, vendor and product.
// f.Tags (validated by NormalizeTags) restrict every kind to CVEs with all
// the tags; a blank query with tags lists every CVE with them (kind "tags").
// The CVSS bounds (NormalizeCVSS) restrict every kind the same way; a blank
// query with only a score filter searches nothing (kind "empty": the
// catalogue lists by score).
func (s *Store) SearchFiltered(ctx context.Context, q string, f SearchFilter, limit int) (*SearchResult, error) {
	q, err := NormalizeQuery(q)
	if err != nil {
		return nil, err
	}
	tagSlugs := f.Tags
	if tagSlugs, err = NormalizeTags(tagSlugs); err != nil {
		return nil, err
	}
	cvssMin, cvssMax, err := NormalizeCVSS(f.CVSSMin, f.CVSSMax)
	if err != nil {
		return nil, err
	}
	if tagSlugs == nil {
		tagSlugs = []string{}
	}
	if limit == 0 {
		limit = DefaultSearchLimit
	}
	if limit < 1 || limit > MaxSearchLimit {
		return nil, &InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", MaxSearchLimit)}
	}
	res := &SearchResult{Query: q, Tags: tagSlugs, Rows: []SearchRow{}, CVSSMin: cvssBound(cvssMin), CVSSMax: cvssBound(cvssMax)}
	var sql string
	var args []any
	var col string // CVE id column the tag filter applies to
	switch {
	case q == "" && len(tagSlugs) == 0:
		res.Kind = SearchEmpty
		return res, nil
	case q == "":
		res.Kind = SearchTags
		sql, args, col = searchTagsSQL, []any{limit + 1}, "v.cve_id"
	case ghsaRe.MatchString(q):
		res.Kind = SearchAlias
		res.Query = "GHSA" + strings.ToLower(q[4:])
		sql, args, col = searchAliasSQL, []any{res.Query, limit + 1}, "a.cve_id"
	default:
		if p, ok := cvePrefix(q); ok {
			res.Kind = SearchCVE
			res.Query = p
			hi := p[:len(p)-1] + string(p[len(p)-1]+1) // prefix chars are [A-Z0-9-]: +1 stays ASCII
			sql, args, col = searchCVESQL, []any{p, hi, limit + 1}, "vuln.cve_id"
			break
		}
		if utf8.RuneCountInString(q) < MinTextQueryRunes {
			res.Kind = SearchTooShort
			return res, nil
		}
		res.Kind = SearchText
		sql, args, col = searchTextSQL, []any{"%" + EscapeLike(q) + "%", limit + 1}, "m.cve_id"
	}
	tf, targs := tagFilterSQL(col, tagSlugs, len(args)+1)
	if c := cvssFilterSQL(col, cvssMin, cvssMax); c != "" {
		tf += "\n        AND " + c
	}
	sql = fmt.Sprintf(sql, tf)
	args = append(args, targs...)
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		res.Rows, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SearchRow, error) {
			x := SearchRow{Tags: []string{}}
			var vendors, products []string
			var ts titleScan
			err := r.Scan(append([]any{&x.CVEID, &x.Title, &x.TitleZh, &x.Stage, &x.LastTransitionAt, &x.IsRejected,
				&x.ProductCount, &vendors, &products}, ts.dest()...)...)
			x.TitleInfo = ts.info(x.Title)
			x.Products = make([]Product, 0, 2)
			for i := range vendors {
				if i < len(products) {
					x.Products = append(x.Products, Product{Vendor: vendors[i], Product: products[i]})
				}
			}
			if x.Stage != nil {
				c := StageCode(*x.Stage)
				x.StageCode = &c
			}
			x.LastTransitionAt = utcPtr(x.LastTransitionAt)
			return x, err
		})
		if err != nil {
			return err
		}
		ids := make([]string, len(res.Rows))
		for i, r := range res.Rows {
			ids[i] = r.CVEID
		}
		ts, err := rowSlugs(ctx, conn, ids)
		for i := range res.Rows {
			if t := ts[res.Rows[i].CVEID]; t != nil {
				res.Rows[i].Tags = t
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(res.Rows) > limit {
		res.Rows, res.Truncated = res.Rows[:limit], true
	}
	return res, nil
}
