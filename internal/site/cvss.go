package site

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The CVSS score filter of the catalogue and search: the CVSS base score a
// vulnerability's page shows (VulnDetail.CVSS: the CVE record's, else the
// first GitHub advisory score; assemble, ghsaScore), materialized per
// vulnerability in vuln_score_mat (migrations/0037_vuln_score.sql) and
// refreshed with vuln_state_mat. Both bounds are inclusive and optional; a
// vulnerability without a score never matches.
//
// A bound is a score 0..10 with at most one decimal, written plainly: "9",
// "9.8", "10", "10.0". Anything else (negative, above 10, two decimals,
// exponent form, a comma, signs, spaces, NaN) is an *InputError naming the
// parameter (cvss_min / cvss_max).

// CVSS severity bands (CVSS v3/v4 qualitative ratings), as score ranges:
// the page's quick filters.
var CVSSBands = []struct{ Name, Min, Max string }{
	{"critical", "9", "10"},
	{"high", "7", "8.9"},
	{"medium", "4", "6.9"},
	{"low", "0.1", "3.9"},
}

var cvssScoreRe = regexp.MustCompile(`^(?:10(?:\.0)?|[0-9](?:\.[0-9])?)$`)

// ParseCVSSScore parses a score bound into tenths of a point (0..100).
func ParseCVSSScore(s string) (tenths int, ok bool) {
	if len(s) > 4 || !cvssScoreRe.MatchString(s) {
		return 0, false
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, _ := strconv.Atoi(whole)
	tenths = w * 10
	if frac != "" {
		tenths += int(frac[0] - '0')
	}
	return tenths, true
}

// formatCVSSTenths is the canonical form of a bound: "9", "9.8", "10".
func formatCVSSTenths(t int) string {
	if t%10 == 0 {
		return strconv.Itoa(t / 10)
	}
	return fmt.Sprintf("%d.%d", t/10, t%10)
}

// NormalizeCVSS validates a score filter (either bound may be "" = none) and
// returns its canonical bounds.
func NormalizeCVSS(min, max string) (string, string, error) {
	lo, hi := -1, -1
	if min != "" {
		t, ok := ParseCVSSScore(min)
		if !ok {
			return min, max, &InputError{Param: "cvss_min", Msg: "must be a score 0..10 with at most one decimal (e.g. 7 or 9.8)"}
		}
		lo, min = t, formatCVSSTenths(t)
	}
	if max != "" {
		t, ok := ParseCVSSScore(max)
		if !ok {
			return min, max, &InputError{Param: "cvss_max", Msg: "must be a score 0..10 with at most one decimal (e.g. 7 or 9.8)"}
		}
		hi, max = t, formatCVSSTenths(t)
	}
	if lo >= 0 && hi >= 0 && lo > hi {
		return min, max, &InputError{Param: "cvss_max", Msg: "less than cvss_min"}
	}
	return min, max, nil
}

// cvssBound is a canonical bound as a JSON number; nil for "".
func cvssBound(s string) *float64 {
	if s == "" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &f
}

// cvssFilterSQL is the condition "the vulnerability in column col has a
// displayed score within the bounds", "" without bounds. The bounds are
// canonical (NormalizeCVSS) and inlined as numeric literals, as the
// catalogue inlines stage and year, so the planner sees the actual range;
// each literal is re-rendered from its parsed value (an invalid bound, which
// Normalize would have rejected, matches nothing).
func cvssFilterSQL(col, min, max string) string {
	var c []string
	for _, b := range []struct{ v, op string }{{min, ">="}, {max, "<="}} {
		if b.v == "" {
			continue
		}
		t, ok := ParseCVSSScore(b.v)
		if !ok {
			return "false"
		}
		c = append(c, "sc.score "+b.op+" "+formatCVSSTenths(t))
	}
	if len(c) == 0 {
		return ""
	}
	return "EXISTS (SELECT 1 FROM vuln_score_mat sc WHERE sc.cve_id = " + col + " AND " + strings.Join(c, " AND ") + ")"
}
