package site

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/tags"
)

// Tag filters (HotParams.Tags, Search tags): slugs of the fixed vocabulary
// (internal/tags), AND across tags. Lists read vuln_tag_visible, the single
// definition of a public tag (suppressed rule tags are neither shown nor
// filterable).

// NormalizeTags validates tag filter slugs for the API: an unknown slug or
// more than tags.MaxFilterTags distinct slugs is an *InputError; the result
// is canonical (lower case, deduplicated, vocabulary order).
func NormalizeTags(raw []string) ([]string, error) {
	slugs, bad := tags.ParseFilter(raw)
	if len(bad) > 0 {
		return nil, &InputError{Param: "tag", Msg: fmt.Sprintf("unknown tag %q (see /tags for the vocabulary)", truncParam(bad[0]))}
	}
	n := 0
	seen := map[string]bool{}
	for _, r := range raw {
		s := strings.ToLower(strings.TrimSpace(r))
		if s != "" && !seen[s] {
			seen[s] = true
			n++
		}
	}
	if n > tags.MaxFilterTags {
		return nil, &InputError{Param: "tag", Msg: fmt.Sprintf("at most %d tags", tags.MaxFilterTags)}
	}
	return slugs, nil
}

func truncParam(s string) string {
	if r := []rune(s); len(r) > 40 {
		return string(r[:40]) + "…"
	}
	return s
}

// tagFilterSQL renders "AND EXISTS (... tag = $n)" for each slug, binding
// the slugs as arguments starting at placeholder next; col is the CVE id
// column of the outer query.
func tagFilterSQL(col string, slugs []string, next int) (string, []any) {
	var b strings.Builder
	args := make([]any, 0, len(slugs))
	for i, s := range slugs {
		fmt.Fprintf(&b, "\n        AND EXISTS (SELECT 1 FROM vuln_tag_visible t WHERE t.cve_id = %s AND t.tag = $%d)", col, next+i)
		args = append(args, s)
	}
	return b.String(), args
}

// TagInfo is one vocabulary entry with its count (GET /api/tags).
type TagInfo struct {
	Slug      string `json:"slug"`
	Dimension string `json:"dimension"`
	Label     string `json:"label"` // English
	Rule      string `json:"rule"`  // English, how nday assigns it
	// ProductTypes: for a product tag, the product-type slugs it assigns.
	ProductTypes []string `json:"product_types,omitempty"`
	// Count: CVEs with this tag (precomputed; see TagsReport.CountsAt).
	Count int64 `json:"count"`
}

// TagsReport is the tag vocabulary with counts.
type TagsReport struct {
	// Note says what a tag is (constant English text).
	Note        string    `json:"note"`
	RuleVersion int       `json:"rule_version"`
	Dimensions  []string  `json:"dimensions"`
	Tags        []TagInfo `json:"tags"`
	// CountsAt: when the counts were computed (nil: never); they are rebuilt
	// after every tag run that changed tags (at most one collector run behind).
	CountsAt *time.Time `json:"counts_at"`
}

// CountsOf is the count of one slug (0 when absent).
func (r *TagsReport) CountsOf(slug string) int64 {
	for _, t := range r.Tags {
		if t.Slug == slug {
			return t.Count
		}
	}
	return 0
}

// TagsNote is TagsReport.Note.
const TagsNote = "Tags are nday's own derivation from CWE ids, CVSS vectors, CISA KEV, Exploit-DB, Metasploit, " +
	"nuclei and GitHub advisory data, the affected products of the CVE record and the CPE names NVD's analysts give; " +
	"each assignment carries its basis and provenance. They are not assigned by NVD, the CNA or any other source."

// Tags returns the vocabulary with the precomputed counts.
func (s *Store) Tags(ctx context.Context) (*TagsReport, error) {
	var cr *tags.CountsReport
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var err error
		cr, err = tags.Counts(ctx, conn)
		return err
	})
	if err != nil {
		return nil, err
	}
	r := &TagsReport{Note: TagsNote, RuleVersion: tags.RuleVersion, Dimensions: tags.Dimensions, Tags: []TagInfo{},
		CountsAt: cr.RefreshedAt}
	for _, t := range tags.Vocabulary {
		r.Tags = append(r.Tags, TagInfo{Slug: t.Slug, Dimension: t.Dim, Label: t.Label, Rule: t.Rule, ProductTypes: t.ProductTypes,
			Count: cr.Counts[t.Slug]})
	}
	return r, nil
}

// rowSlugs fills the Tags of list rows (one query for the page).
func rowSlugs(ctx context.Context, conn *pgx.Conn, ids []string) (map[string][]string, error) {
	return tags.SlugsMany(ctx, conn, ids)
}
