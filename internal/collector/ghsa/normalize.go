package ghsa

import (
	"regexp"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// Regular expressions. Python's re.fullmatch(p, s) is RE2 `^(?:p)$` (Go's `$`
// without (?m) only matches at the very end, like \Z); NOT_FIX_RE.match is
// `^(?:p)`. Membership tests are language questions, so backtracking vs RE2
// does not matter. The Unicode-dependent pieces are spelled out explicitly:
//   - `\s` (str pattern) = str.isspace(): reSpace, not Go's ASCII `\s`;
//   - `\d` (str pattern) = Unicode 15.1 Nd: reDecimal, not Go's ASCII `\d` and
//     not Go's \p{Nd} (Unicode 17 has more digits);
//   - re.IGNORECASE folds 'i' with U+0130/U+0131 and 's' with U+017F; Go's
//     (?i) folds 's'/'ſ' but not 'i'/'İ'/'ı', so every letter of NOT_FIX_RE is
//     written as an explicit class of exactly the characters Python accepts
//     (enumerated over all code points with the project interpreter).
var (
	// models.CVE_ID_RE = r"CVE-\d{4}-\d{4,}" (fullmatch) with Python's \d. Not
	// model.IsValidCVEID: that uses Go's \p{Nd} (Unicode 17), which also
	// accepts digits added after Unicode 15.1 (e.g. U+10D40), where Python
	// raises NormalizeError("bad cve_id"). Every id accepted here is also
	// accepted by model.IsValidCVEID (Normalized.Validate).
	cveIDRe = regexp.MustCompile(`^CVE-` + dig + `{4}-` + dig + `{4,}$`)

	// GHSA_RE = r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}" (ASCII only), fullmatch.
	ghsaRe = regexp.MustCompile(`^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$`)

	nsp = `[^/` + reSpace + `]` // Python [^/\s]
	dig = `[` + reDecimal + `]` // Python \d

	fixURLRes = []*regexp.Regexp{
		// github.com/<owner>/<repo>/commit/<sha>
		regexp.MustCompile(`^https?://github\.com/` + nsp + `+/` + nsp + `+/commit/[0-9a-fA-F]{7,40}(?:[/?#].*)?$`),
		// github.com/<owner>/<repo>/pull/<n>[/...]
		regexp.MustCompile(`^https?://github\.com/` + nsp + `+/` + nsp + `+/pull/` + dig + `+(?:[/?#].*)?$`),
		// GitLab .../-/commit/<sha>, .../-/merge_requests/<n>
		regexp.MustCompile(`^https?://` + nsp + `*gitlab` + nsp + `*/(?:` + nsp + `+/)+-/commit/[0-9a-fA-F]{7,40}(?:[/?#].*)?$`),
		regexp.MustCompile(`^https?://` + nsp + `*gitlab` + nsp + `*/(?:` + nsp + `+/)+-/merge_requests/` + dig + `+(?:[/?#].*)?$`),
		// bitbucket.org/<owner>/<repo>/commits/<sha>
		regexp.MustCompile(`^https?://bitbucket\.org/` + nsp + `+/` + nsp + `+/commits?/[0-9a-fA-F]{7,40}(?:[/?#].*)?$`),
	}

	// NOT_FIX_RE = re.compile(r"https?://github\.com/github/advisory-database/", re.I), .match
	notFixRe = regexp.MustCompile(`^` + foldPy("http") + `[sSſ]?://` + foldPy("github") + `\.` + foldPy("com") + `/` +
		foldPy("github") + `/` + foldPy("advisory") + `-` + foldPy("database") + `/`)
)

// foldPy spells a lowercase ASCII word as Python re.IGNORECASE matches it.
func foldPy(word string) string {
	out := ""
	for _, r := range word {
		switch r {
		case 'i':
			out += `[iI\x{130}\x{131}]`
		case 's':
			out += `[sS\x{17F}]`
		case 'k':
			out += `[kK\x{212A}]`
		default:
			if r >= 'a' && r <= 'z' {
				out += "[" + string(r) + string(r-32) + "]"
			} else {
				out += regexp.QuoteMeta(string(r))
			}
		}
	}
	return out
}

// FixCommitURLs is ghsa.py's fix_commit_urls: reference URLs (stripped) that
// are commit / PR / MR links on a code host, deduplicated, in upstream order.
func FixCommitURLs(references any) []any {
	out := []any{}
	refs, _ := references.([]any)
	seen := map[string]bool{}
	for _, ref := range refs {
		u := collector.Text(ref)
		if u == nil || seen[*u] || notFixRe.MatchString(*u) {
			continue
		}
		for _, re := range fixURLRes {
			if re.MatchString(*u) {
				seen[*u] = true
				out = append(out, *u)
				break
			}
		}
	}
	return out
}

// patchedVersion is _patched_version: a string, or legacy {"identifier": ...}.
func patchedVersion(v any) *string {
	if o, ok := v.(*pyjson.Object); ok {
		v = o.Get("identifier")
	}
	return collector.Text(v)
}

// Normalize is GhsaCollector.normalize (pure).
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, ok := rec.Payload.(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload is not a JSON object")
	}
	g := collector.Text(p.Get("ghsa_id"))
	if g == nil || !ghsaRe.MatchString(*g) {
		return nil, collector.NormalizeErrorf("bad ghsa_id: %s", pyRepr(p.Get("ghsa_id")))
	}
	gid := *g
	if gid != rec.SourceKey {
		return nil, collector.NormalizeErrorf("ghsa_id %s != source_key %s", gid, rec.SourceKey)
	}
	for _, key := range []string{"published_at", "updated_at"} {
		if _, ok := parseTS(p.Get(key)); !ok {
			return nil, collector.NormalizeErrorf("%s: bad %s: %s", gid, key, pyRepr(p.Get(key)))
		}
	}
	vulns := p.Get("vulnerabilities")
	vlist, isList := vulns.([]any)
	if vulns != nil && !isList {
		return nil, collector.NormalizeErrorf("%s: vulnerabilities is not a list", gid)
	}
	refs := p.Get("references")
	if _, isList := refs.([]any); refs != nil && !isList {
		return nil, collector.NormalizeErrorf("%s: references is not a list", gid)
	}

	cve := collector.Text(p.Get("cve_id"))
	if cve == nil {
		return &model.Normalized{}, nil // vuln table is keyed by CVE; raw is kept
	}
	if !cveIDRe.MatchString(*cve) {
		return nil, collector.NormalizeErrorf("%s: bad cve_id %s", gid, pyStrRepr(*cve))
	}
	out := &model.Normalized{Aliases: []model.Alias{{CVEID: *cve, Alias: gid, AliasType: "ghsa"}}}
	if collector.Text(p.Get("withdrawn_at")) != nil {
		return out, nil
	}
	out.Vulns = append(out.Vulns, model.VulnUpsert{
		CVEID:         *cve,
		Title:         collector.Text(p.Get("summary")),
		Description:   collector.Text(p.Get("description")),
		Authoritative: false,
	})
	packages := []any{}
	anyPatched := false
	for _, v := range vlist {
		vo, ok := v.(*pyjson.Object)
		if !ok {
			return nil, collector.NormalizeErrorf("%s: vulnerability entry is not an object", gid)
		}
		pkg, _ := vo.Get("package").(*pyjson.Object) // non-dict -> {} (Get on nil is nil)
		fpv := patchedVersion(vo.Get("first_patched_version"))
		entry := pyjson.NewObject()
		entry.Set("ecosystem", pkg.Get("ecosystem"))
		entry.Set("name", pkg.Get("name"))
		entry.Set("vulnerable_version_range", vo.Get("vulnerable_version_range"))
		if fpv != nil {
			entry.Set("first_patched_version", *fpv)
			anyPatched = true
		} else {
			entry.Set("first_patched_version", nil)
		}
		packages = append(packages, entry)
	}
	if !anyPatched {
		return out, nil // no fix known yet: alias + stub only
	}

	cvss := p.Get("cvss_severities")
	if cvss == nil {
		if v, ok := p.Lookup("cvss"); ok {
			cvss = v
		}
	}
	cwes := p.Get("cwes")
	if !truthy(cwes) {
		cwes = []any{}
	}
	references := refs
	if !truthy(references) {
		references = []any{}
	}
	detail := map[string]any{
		"ghsa_id":               gid,
		"advisory_published_at": p.Get("published_at"),
		"advisory_updated_at":   p.Get("updated_at"),
		"github_reviewed_at":    p.Get("github_reviewed_at"),
		"severity":              p.Get("severity"),
		"cvss":                  cvss,
		"cwes":                  cwes,
		"packages":              packages,
		"fix_commit_urls":       FixCommitURLs(refs),
		"source_code_location":  p.Get("source_code_location"),
		"references":            references,
	}
	out.Events = append(out.Events, model.Event{
		CVEID:      *cve,
		Type:       model.EventPatchReleased,
		Source:     Name,
		OccurredAt: nil,
		URL:        collector.Text(p.Get("html_url")),
		Detail:     detail,
		DedupeKey:  gid,
	})
	return out, nil
}
