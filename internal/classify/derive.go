package classify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"nday.land/nday/internal/model"
)

// Row sources (vuln_cwe.source / vuln_cvss.source), see migrations/0009_classify.sql.
const (
	SrcCNA          = "cve-cna"
	SrcADP          = "cve-adp"
	SrcNVDPrimary   = "nvd-primary"
	SrcNVDSecondary = "nvd-secondary"
	SrcGHSA         = "ghsa"
)

// Raw sources the rows are derived from (vuln_classify_input.source).
const (
	FamCVEList = "cvelist"
	FamNVD     = "nvd"
	FamGHSA    = "ghsa"
)

// Families lists the raw sources in derivation order.
var Families = []string{FamCVEList, FamNVD, FamGHSA}

// familySources: which row sources a raw source owns. Rows of a family are
// always replaced together.
var familySources = map[string][]string{
	FamCVEList: {SrcCNA, SrcADP},
	FamNVD:     {SrcNVDPrimary, SrcNVDSecondary},
	FamGHSA:    {SrcGHSA},
}

// Precedence ranks row sources for "best CVSS" (lower wins): the CVE
// record's own data first, then NVD's analysts, then what NVD republishes,
// then GitHub.
var Precedence = map[string]int{SrcCNA: 1, SrcADP: 2, SrcNVDPrimary: 3, SrcNVDSecondary: 4, SrcGHSA: 5}

// NVDOwnSource is the NVD source identifier of NVD's own analysts.
const NVDOwnSource = "nvd@nist.gov"

// CWERow is one vuln_cwe row.
type CWERow struct {
	CVEID, CWE, Source, SourceOrg string
}

// CVSSRow is one vuln_cvss row.
type CVSSRow struct {
	CVEID, Version, Vector string
	BaseScore              *float64 // rounded to one decimal (numeric(3,1))
	Severity               *string
	Source, SourceOrg      string
}

// Derived is what one raw record contributes.
type Derived struct {
	CVEID    string
	Rejected bool
	CWEs     []CWERow
	CVSS     []CVSSRow
	// CWESkipped: weakness entries that are not a CWE id (NVD-CWE-noinfo,
	// NVD-CWE-Other, free text, "n/a"). CVSSSkipped: CVSS entries with an
	// invalid or missing vector for their version, or a second, different
	// vector for an already taken (version, source, source_org).
	CWESkipped, CVSSSkipped int
}

func (d *Derived) addCWE(raw, source, org string) {
	id := NormalizeCWE(raw)
	if id == "" {
		d.CWESkipped++
		return
	}
	for _, r := range d.CWEs {
		if r.CWE == id && r.Source == source && r.SourceOrg == org {
			return // same fact listed twice (e.g. in two languages)
		}
	}
	d.CWEs = append(d.CWEs, CWERow{CVEID: d.CVEID, CWE: id, Source: source, SourceOrg: org})
}

// addCVSS adds a vector delivered for slot version (from the container key);
// declared is the version the entry itself states ("" if none).
func (d *Derived) addCVSS(version, declared, vector string, score any, severity any, source, org string) {
	if declared != "" && declared != version || !ValidVector(version, vector) {
		d.CVSSSkipped++
		return
	}
	for _, r := range d.CVSS {
		if r.Version == version && r.Source == source && r.SourceOrg == org {
			if r.Vector != vector {
				d.CVSSSkipped++
			}
			return
		}
	}
	d.CVSS = append(d.CVSS, CVSSRow{CVEID: d.CVEID, Version: version, Vector: vector,
		BaseScore: scoreOf(score), Severity: strOf(severity), Source: source, SourceOrg: org})
}

// sortRows gives derived rows a canonical order (comparison with stored rows).
func (d *Derived) sortRows() {
	sort.Slice(d.CWEs, func(i, j int) bool { return d.CWEs[i].key() < d.CWEs[j].key() })
	sort.Slice(d.CVSS, func(i, j int) bool { return d.CVSS[i].key() < d.CVSS[j].key() })
}

func (r CWERow) key() string { return r.CWE + "\x00" + r.Source + "\x00" + r.SourceOrg }

func (r CVSSRow) key() string {
	s := "-"
	if r.BaseScore != nil {
		s = fmt.Sprintf("%.1f", *r.BaseScore)
	}
	sev := "\x01"
	if r.Severity != nil {
		sev = *r.Severity
	}
	return r.Version + "\x00" + r.Source + "\x00" + r.SourceOrg + "\x00" + r.Vector + "\x00" + s + "\x00" + sev
}

// ------------------------------------------------------------------ helpers

func decodeObj(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload is not a JSON object")
	}
	return m, nil
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func str(v any) string         { s, _ := v.(string); return s }

func strOf(v any) *string {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// scoreOf: a JSON number (or numeric string) in 0..10, rounded to one
// decimal like numeric(3,1); anything else is nil. Never computed.
func scoreOf(v any) *float64 {
	var f float64
	switch x := v.(type) {
	case json.Number:
		var err error
		if f, err = x.Float64(); err != nil {
			return nil
		}
	case float64:
		f = x
	default:
		return nil
	}
	if math.IsNaN(f) || f < 0 || f > 10 {
		return nil
	}
	f = math.Round(f*10) / 10
	return &f
}

// --------------------------------------------------------------- CVE JSON 5

// cve5Keys maps CVE JSON 5 metric keys to versions.
var cve5Keys = []struct{ key, version string }{
	{"cvssV2_0", V2}, {"cvssV3_0", V30}, {"cvssV3_1", V31}, {"cvssV4_0", V40},
}

// leadingCWE finds a CWE id at the start of a problem type description
// ("CWE-79 Improper Neutralization ..." / "CWE-79: ...").
var leadingCWE = regexp.MustCompile(`^\s*(?i:cwe)-([0-9]{1,9})\b`)

// DeriveCVE5 derives the cve-cna / cve-adp rows of a CVE List record
// (CVE JSON 5). Rules:
//   - state REJECTED: no rows, Rejected; any other state but PUBLISHED: no rows;
//   - CWE: each problemTypes[].descriptions[] entry; its cweId when that is
//     a CWE id, else a CWE id at the start of its description; otherwise
//     (n/a, free text) skipped and counted;
//   - CVSS: each metrics[] entry's cvssV2_0 / cvssV3_0 / cvssV3_1 /
//     cvssV4_0 object (vectorString, baseScore, baseSeverity);
//   - provenance: the CNA container -> cve-cna, source_org = its
//     providerMetadata.shortName (else cveMetadata.assignerShortName);
//     each ADP container -> cve-adp, source_org = its shortName.
func DeriveCVE5(cveID string, payload []byte) (*Derived, error) {
	p, err := decodeObj(payload)
	if err != nil {
		return nil, err
	}
	d := &Derived{CVEID: cveID}
	meta := obj(p["cveMetadata"])
	switch str(meta["state"]) {
	case "REJECTED":
		d.Rejected = true
		return d, nil
	case "PUBLISHED":
	default:
		return d, nil
	}
	cont := obj(p["containers"])
	cna := obj(cont["cna"])
	org := str(obj(cna["providerMetadata"])["shortName"])
	if org == "" {
		org = str(meta["assignerShortName"])
	}
	cve5Container(d, cna, SrcCNA, org)
	for _, a := range arr(cont["adp"]) {
		ao := obj(a)
		if ao == nil {
			continue
		}
		cve5Container(d, ao, SrcADP, str(obj(ao["providerMetadata"])["shortName"]))
	}
	d.sortRows()
	return d, nil
}

func cve5Container(d *Derived, c map[string]any, source, org string) {
	if c == nil {
		return
	}
	for _, pt := range arr(c["problemTypes"]) {
		for _, desc := range arr(obj(pt)["descriptions"]) {
			do := obj(desc)
			if do == nil {
				continue
			}
			if id := NormalizeCWE(str(do["cweId"])); id != "" {
				d.addCWE(id, source, org)
				continue
			}
			if m := leadingCWE.FindStringSubmatch(str(do["description"])); m != nil {
				d.addCWE("CWE-"+m[1], source, org)
				continue
			}
			d.CWESkipped++
		}
	}
	for _, m := range arr(c["metrics"]) {
		mo := obj(m)
		for _, k := range cve5Keys {
			cv, ok := mo[k.key]
			if !ok {
				continue
			}
			co := obj(cv)
			declared := str(co["version"])
			if n, ok := co["version"].(json.Number); ok {
				declared = n.String()
			}
			d.addCVSS(k.version, declared, str(co["vectorString"]), co["baseScore"], co["baseSeverity"], source, org)
		}
	}
}

// ---------------------------------------------------------------------- NVD

var nvdKeys = []struct{ key, version string }{
	{"cvssMetricV2", V2}, {"cvssMetricV30", V30}, {"cvssMetricV31", V31}, {"cvssMetricV40", V40},
}

// DeriveNVD derives the nvd-primary / nvd-secondary rows of an NVD CVE 2.0
// record (the "cve" object of a feed entry). Rules:
//   - vulnStatus Rejected: no rows, Rejected;
//   - provenance: an entry whose source is nvd@nist.gov is NVD's own
//     analysis (nvd-primary); every other entry is republished CNA/ADP data
//     (nvd-secondary); source_org = the entry's source. The entry's "type"
//     (Primary/Secondary) is NOT used: in the feeds it is relative to the
//     record (a CNA's entry is "Primary" when NVD has not analysed the CVE),
//     see docs/nvd.md;
//   - CWE: weaknesses[].description[].value; NVD-CWE-noinfo, NVD-CWE-Other
//     and anything else that is not CWE-<n> are skipped and counted;
//   - CVSS: metrics.cvssMetricV2/V30/V31/V40[].cvssData.vectorString,
//     baseScore, baseSeverity (for v2 the entry's baseSeverity).
//
// configurations (CPE) and references stay in the raw record only.
func DeriveNVD(cveID string, payload []byte) (*Derived, error) {
	p, err := decodeObj(payload)
	if err != nil {
		return nil, err
	}
	d := &Derived{CVEID: cveID}
	if str(p["vulnStatus"]) == "Rejected" {
		d.Rejected = true
		return d, nil
	}
	nvdSource := func(s string) string {
		if s == NVDOwnSource {
			return SrcNVDPrimary
		}
		return SrcNVDSecondary
	}
	for _, w := range arr(p["weaknesses"]) {
		wo := obj(w)
		src := str(wo["source"])
		for _, desc := range arr(wo["description"]) {
			d.addCWE(str(obj(desc)["value"]), nvdSource(src), src)
		}
	}
	metrics := obj(p["metrics"])
	for _, k := range nvdKeys {
		for _, m := range arr(metrics[k.key]) {
			mo := obj(m)
			if mo == nil {
				continue
			}
			src := str(mo["source"])
			cd := obj(mo["cvssData"])
			sev := cd["baseSeverity"]
			if sev == nil {
				sev = mo["baseSeverity"] // v2 keeps it beside cvssData
			}
			d.addCVSS(k.version, str(cd["version"]), str(cd["vectorString"]), cd["baseScore"], sev, nvdSource(src), src)
		}
	}
	d.sortRows()
	return d, nil
}

// --------------------------------------------------------------------- GHSA

// DeriveGHSA derives the ghsa rows of a stored GitHub advisory (the REST
// API object). It returns the id of the vuln the rows belong to: the
// advisory's CVE id, or its GHSA id when it has no CVE (the vuln is then
// keyed by the GHSA id, docs/ghsa.md); "" when it has neither.
// Rules: withdrawn_at set -> no rows, Rejected; CWE from cwes[].cwe_id;
// CVSS from cvss_severities.cvss_v3 / cvss_v4 and the legacy cvss object
// (vector_string; score as delivered; GitHub gives no per-vector severity,
// so severity is NULL); the version comes from the vector's "CVSS:x.y/"
// prefix. An entry without a vector (GitHub sends score 0 and a null
// vector for "none") is absent, not skipped. source_org = the GHSA id.
func DeriveGHSA(payload []byte) (cveID string, d *Derived, err error) {
	p, err := decodeObj(payload)
	if err != nil {
		return "", nil, err
	}
	cveID = strings.TrimSpace(str(p["cve_id"]))
	org := str(p["ghsa_id"])
	if cveID == "" && model.IsGHSAID(org) {
		cveID = org
	}
	d = &Derived{CVEID: cveID}
	if strOf(p["withdrawn_at"]) != nil {
		d.Rejected = true
		return cveID, d, nil
	}
	for _, c := range arr(p["cwes"]) {
		d.addCWE(str(obj(c)["cwe_id"]), SrcGHSA, org)
	}
	sev := obj(p["cvss_severities"])
	for _, c := range []map[string]any{obj(sev["cvss_v4"]), obj(sev["cvss_v3"]), obj(p["cvss"])} {
		vec := str(c["vector_string"])
		if c == nil || vec == "" {
			continue
		}
		ver := VersionOfVector(vec)
		if ver == "" {
			d.CVSSSkipped++
			continue
		}
		d.addCVSS(ver, "", vec, c["score"], nil, SrcGHSA, org)
	}
	d.sortRows()
	return cveID, d, nil
}
