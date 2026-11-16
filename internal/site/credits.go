package site

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Credits: the people, organisations and tools that the upstream records of
// a vulnerability name as finder, reporter, analyst, ... — read at request
// time from the latest stored raw records (no derived table):
//
//   - cvelist: containers.cna.credits[] of the latest CVE record,
//     {"lang", "value", "type"} (CVE JSON 5; "user" is a CVE-registry UUID and
//     is not read);
//   - ghsa: credits[] of the latest version of every GitHub advisory whose
//     latest version names this CVE and is not withdrawn, {"type", "user":
//     {...}}; only user.login is read (creditsSQL projects it), never the
//     profile URLs or ids.
//
// Upstream text is untrusted: values are trimmed, whitespace and control
// characters collapse to one space, empty values are dropped, a value is cut
// to MaxCreditRunes, identical (role, name) pairs of one source are kept
// once, and at most MaxCreditsPerSource entries are kept per source. The same
// name in two sources stays two entries, each with its source.

// Credit roles: a fixed set of keys. CVE JSON 5 credit types (schema enum
// "finder", "reporter", "analyst", "coordinator", "remediation developer",
// "remediation reviewer", "remediation verifier", "tool", "sponsor",
// "other") and GHSA's (the same words joined with "_") map to the key of the
// same name; "other", unknown and missing types map to CreditRoleCredit.
const (
	CreditRoleFinder              = "finder"
	CreditRoleReporter            = "reporter"
	CreditRoleAnalyst             = "analyst"
	CreditRoleCoordinator         = "coordinator"
	CreditRoleRemediationDev      = "remediation_developer"
	CreditRoleRemediationReviewer = "remediation_reviewer"
	CreditRoleRemediationVerifier = "remediation_verifier"
	CreditRoleTool                = "tool"
	CreditRoleSponsor             = "sponsor"
	CreditRoleCredit              = "credit"
)

// CreditRoles lists every role key, in display order of the reference.
var CreditRoles = []string{CreditRoleFinder, CreditRoleReporter, CreditRoleAnalyst, CreditRoleCoordinator,
	CreditRoleRemediationDev, CreditRoleRemediationReviewer, CreditRoleRemediationVerifier,
	CreditRoleTool, CreditRoleSponsor, CreditRoleCredit}

const (
	// MaxCreditRunes caps one name (longer values end in "…"). The longest
	// CNA credit in the local data set is 310 characters (a sentence listing
	// fifteen people).
	MaxCreditRunes = 256
	// MaxCreditsPerSource caps the entries of one source (local data: at most
	// 22 in one CVE record, 5 in one GitHub advisory).
	MaxCreditsPerSource = 25
	maxCreditTypeRunes  = 64
)

// Credit is one credited person, organisation or tool, as the source wrote it.
type Credit struct {
	Role string `json:"role"` // one of CreditRoles
	// Type: the upstream type string as given (trimmed, cut to 64
	// characters); nil when the source gave none.
	Type   *string `json:"type"`
	Name   string  `json:"name"`
	Source string  `json:"source"` // "cvelist" | "ghsa"
	// Key: the raw record it comes from (CVE id or GHSA id; see raw_records).
	Key string `json:"key"`
}

// creditsSQL: credits of the latest cvelist record of the CVE, then those of
// the latest version of each GHSA advisory whose latest version names the
// CVE and is not withdrawn (as internal/classify identifies them), by
// advisory id (buildCredits sorts). Both legs are index scans (raw_record_latest_idx,
// raw_record_ghsa_cve_idx). GHSA credits are projected to {type, login}.
// Both sources are public (public.go).
const creditsSQL = `
SELECT 'cvelist', c.source_key, coalesce(c.payload #> '{containers,cna,credits}', 'null')::text
FROM (SELECT source_key, payload FROM raw_record WHERE source = 'cvelist' AND source_key = $1
      ORDER BY fetched_at DESC, id DESC LIMIT 1) c
UNION ALL
SELECT 'ghsa', g.source_key, coalesce((
         SELECT jsonb_agg(jsonb_build_object('type', x->'type', 'login', x #> '{user,login}') ORDER BY o)
         FROM jsonb_array_elements(CASE WHEN jsonb_typeof(g.payload->'credits') = 'array'
                                        THEN g.payload->'credits' ELSE '[]' END) WITH ORDINALITY AS e(x, o)
       ), 'null')::text
FROM (SELECT * FROM (
          SELECT DISTINCT ON (r.source_key) r.source_key, r.payload FROM raw_record r
          WHERE r.source = 'ghsa' AND r.source_key IN (
              SELECT source_key FROM raw_record WHERE source = 'ghsa' AND payload->>'cve_id' = $1)
          ORDER BY r.source_key, r.fetched_at DESC, r.id DESC) l
      WHERE l.payload->>'cve_id' = $1 AND coalesce(l.payload->>'withdrawn_at', '') = '') g`

// creditRecord is one row of creditsSQL.
type creditRecord struct {
	Source, Key string
	JSON        []byte // the credits array (cvelist as stored; ghsa projected)
}

// buildCredits turns the credit arrays of the records into the normalised
// list: cvelist first, then GHSA advisories by id, each in upstream order.
// Never nil.
func buildCredits(recs []creditRecord) []Credit {
	sort.SliceStable(recs, func(a, b int) bool {
		if recs[a].Source != recs[b].Source {
			return recs[a].Source == "cvelist"
		}
		return recs[a].Key < recs[b].Key
	})
	out := []Credit{}
	seen := map[string]map[[2]string]bool{}
	count := map[string]int{}
	for _, r := range recs {
		if !IsPublicSource(r.Source) {
			continue
		}
		var list []json.RawMessage
		if json.Unmarshal(r.JSON, &list) != nil {
			continue // null, not an array, malformed
		}
		if seen[r.Source] == nil {
			seen[r.Source] = map[[2]string]bool{}
		}
		for _, item := range list {
			var m map[string]any
			if json.Unmarshal(item, &m) != nil || m == nil {
				continue
			}
			var name any
			switch r.Source {
			case "cvelist":
				name = m["value"]
			case "ghsa":
				name = m["login"]
			default:
				continue
			}
			s, _ := name.(string)
			s = cleanCreditText(s, MaxCreditRunes)
			if s == "" {
				continue
			}
			var typ *string
			if ts, _ := m["type"].(string); cleanCreditText(ts, maxCreditTypeRunes) != "" {
				t := cleanCreditText(ts, maxCreditTypeRunes)
				typ = &t
			}
			role := CreditRole(typ)
			k := [2]string{role, s}
			if seen[r.Source][k] || count[r.Source] >= MaxCreditsPerSource {
				continue
			}
			seen[r.Source][k] = true
			count[r.Source]++
			out = append(out, Credit{Role: role, Type: typ, Name: s, Source: r.Source, Key: r.Key})
		}
	}
	return out
}

// CreditRole maps an upstream credit type (CVE JSON 5 "remediation
// developer", GHSA "remediation_developer", any case) to a role key; nil,
// "other" and unknown types give CreditRoleCredit.
func CreditRole(typ *string) string {
	if typ == nil {
		return CreditRoleCredit
	}
	t := strings.ToLower(strings.Join(strings.FieldsFunc(*typ, func(r rune) bool {
		return r == '_' || r == '-' || unicode.IsSpace(r)
	}), "_"))
	for _, r := range CreditRoles {
		if r == t && r != CreditRoleCredit {
			return r
		}
	}
	return CreditRoleCredit
}

// cleanCreditText trims s, collapses runs of whitespace and control
// characters to one space, drops invalid UTF-8 and cuts it to max runes
// (the last one replaced by "…" when cut).
func cleanCreditText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) > max {
		rs := []rune(out)
		out = strings.TrimRightFunc(string(rs[:max-1]), unicode.IsSpace) + "…"
	}
	return out
}
