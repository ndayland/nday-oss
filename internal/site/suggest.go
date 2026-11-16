package site

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Suggest limits.
const (
	MinSuggestRunes     = 3
	DefaultSuggestLimit = 8
	MaxSuggestLimit     = 20
)

// Suggest kinds (SuggestRow.Kind).
const (
	SuggestVendor  = "vendor"  // the name occurs as a vendor (maybe also as a product)
	SuggestProduct = "product" // the name occurs only as a product
)

// SuggestRow is one vendor or product name.
type SuggestRow struct {
	// Name is the most frequent spelling of the name (names are grouped
	// case-insensitively; a tie goes to the first in byte order, so upper
	// case wins).
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Count is the number of vulnerabilities with an affected row whose
	// vendor or product equals the name case-insensitively: what following
	// the name matches (docs/follows.md).
	Count int `json:"count"`
}

// SuggestResult is the answer to Suggest.
type SuggestResult struct {
	Query string `json:"query"` // normalised query (NormalizeSuggestQuery)
	// Kind is SearchText when the names were searched, SearchTooShort for a
	// query of fewer than MinSuggestRunes characters and SearchEmpty for a
	// blank one (the last two never query the database; rows is []).
	Kind string       `json:"kind"`
	Rows []SuggestRow `json:"rows"`
}

// NormalizeSuggestQuery is NormalizeQuery (trim, collapse white space,
// length and UTF-8 checks) plus lower case: the matching is case-insensitive,
// so "Forti" and "forti " are the same query (and the same cache entry).
func NormalizeSuggestQuery(q string) (string, error) {
	q, err := NormalizeQuery(q)
	return strings.ToLower(q), err
}

// The affected table is public data (the vulnerability page and search show
// every row; only the public collectors write it, see public.go), so no
// non-public filter applies. The ILIKE filters on the raw columns come first
// (the trigram GIN indexes affected_vendor_trgm_idx/affected_product_trgm_idx
// of migration 0003 serve them when pg_trgm is available); only the matching
// rows are grouped by lower(name).
//
// count is the number of distinct CVEs among the matching rows of a name.
// It equals what following that name matches (lower(vendor) = term OR
// lower(product) = term): a row whose vendor or product lowers to the name
// contains the query case-insensitively exactly when the name does, so every
// such row passed the filter (tested in internal/web).
const suggestSQL = `
WITH n AS (
    SELECT vendor AS name, true AS is_vendor, cve_id FROM affected WHERE vendor ILIKE $1 ESCAPE '\'
    UNION ALL
    SELECT product, false, cve_id FROM affected WHERE product ILIKE $1 ESCAPE '\')
SELECT mode() WITHIN GROUP (ORDER BY name COLLATE "C") AS name, bool_or(is_vendor), count(DISTINCT cve_id)::int AS c
FROM n
GROUP BY lower(name)
ORDER BY c DESC, lower(name)
LIMIT $2`

// Suggest finds up to limit (default 8, max 20) vendor and product names
// containing q (case-insensitive substring), most affected vulnerabilities
// first. A query shorter than MinSuggestRunes returns no rows without a
// database query.
func (s *Store) Suggest(ctx context.Context, q string, limit int) (*SuggestResult, error) {
	q, err := NormalizeSuggestQuery(q)
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = DefaultSuggestLimit
	}
	if limit < 1 || limit > MaxSuggestLimit {
		return nil, &InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", MaxSuggestLimit)}
	}
	res := &SuggestResult{Query: q, Kind: SearchText, Rows: []SuggestRow{}}
	switch {
	case q == "":
		res.Kind = SearchEmpty
		return res, nil
	case utf8.RuneCountInString(q) < MinSuggestRunes:
		res.Kind = SearchTooShort
		return res, nil
	}
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, suggestSQL, "%"+EscapeLike(q)+"%", limit)
		if err != nil {
			return err
		}
		res.Rows, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SuggestRow, error) {
			var x SuggestRow
			var vendor bool
			err := r.Scan(&x.Name, &vendor, &x.Count)
			x.Kind = SuggestProduct
			if vendor {
				x.Kind = SuggestVendor
			}
			return x, err
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if res.Rows == nil {
		res.Rows = []SuggestRow{}
	}
	return res, nil
}
