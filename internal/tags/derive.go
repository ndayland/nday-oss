package tags

import (
	"encoding/json"
	"sort"
	"strings"

	"nday.land/nday/internal/classify"
)

// Event sources the exploit dimension reads (public collectors only; the
// non-public xposts source never appears here, see internal/site/public.go).
const (
	SrcKEV        = "kev"
	SrcExploitDB  = "exploitdb"
	SrcMetasploit = "metasploit"
	SrcNuclei     = "nuclei"
)

var exploitSources = map[string]string{SrcMetasploit: "metasploit", SrcExploitDB: "exploit-db", SrcNuclei: "nuclei"}

// maxBasisItems bounds the lists stored in a basis (event keys, packages).
const maxBasisItems = 10

// EventFact is one public lifecycle event the exploit dimension reads.
type EventFact struct {
	Type   string // kev_added | poc_published
	Source string // kev | exploitdb | metasploit | nuclei
	Key    string // dedupe key: EDB id, module full name, template id ("" for KEV)
	// Ransomware: the KEV entry's knownRansomwareCampaignUse ("Known",
	// "Unknown", or "" when absent).
	Ransomware string
}

// Package is one package of a GitHub advisory.
type Package struct {
	Ecosystem string // GitHub's value: npm, pip, maven, go, nuget, rubygems, composer, rust, erlang, pub, swift, actions, other
	Name      string
}

// Advisory is the classified version of one GitHub advisory of the CVE.
type Advisory struct {
	ID       string // GHSA id
	Packages []Package
	hash     string // raw_record content hash of the classified version
}

// Input is everything the derivation of one CVE reads.
type Input struct {
	CVEID string
	// Rejected: the CVE record is REJECTED (latest cvelist disclosed event,
	// as vuln_state says; for a GHSA-keyed vuln the advisory's disclosed
	// event, REJECTED once withdrawn) or the classification layer's cvelist /
	// nvd input marks it rejected. A rejected CVE gets no rule tags.
	Rejected   bool
	CWE        []classify.CWEEntry
	CVSS       []classify.CVSSEntry // every stored vector; the best is chosen here
	Events     []EventFact
	Advisories []Advisory
	// Affected: the CVE's affected rows (vendor, product as stored).
	Affected []AffectedRow
	// CPEs: the vulnerable CPE names of the classified NVD record
	// (vulnerable = true, not in a negated node), deduplicated.
	CPEs []CPE
	// Suppressed rule tags (vuln_tag_suppress): never assigned.
	Suppressed []string
}

// Basis is what an assignment rests on (stored as vuln_tag.basis, shown on
// the vulnerability page and in the API). One part is set per dimension,
// except product and product-type tags, which carry the affected rows and
// the CPE names that matched (either or both, each with its total count) and,
// for a product-type tag, which products and type rules gave it. Upstream
// strings (CNA names, module names, package names, affected vendor and
// product, CPE components) are data: renderers escape them.
type Basis struct {
	CWE        []BasisCWE      `json:"cwe,omitempty"`        // type
	CVSS       *BasisCVSS      `json:"cvss,omitempty"`       // access
	Events     []BasisEvent    `json:"events,omitempty"`     // exploit
	Advisories []BasisAdvisory `json:"advisories,omitempty"` // ecosystem
	// product, product-type: matched affected rows (sorted, at most 10) and
	// how many matched in all
	Affected      []BasisAffected `json:"affected,omitempty"`
	AffectedCount int             `json:"affected_count,omitempty"`
	// product, product-type: matched vulnerable CPE names given by NVD's
	// analysts (part, vendor, product; sorted, at most 10) and the total
	CPE      []BasisCPE `json:"cpe,omitempty"`
	CPECount int        `json:"cpe_count,omitempty"`
	// product-type: the product slugs and type rule ids that gave it
	Products  []string `json:"products,omitempty"`
	TypeRules []string `json:"type_rules,omitempty"`
}

// BasisCWE is a CWE id with every source that states it.
type BasisCWE struct {
	ID      string                `json:"id"`
	Sources []classify.Provenance `json:"sources"`
}

// BasisCVSS is the vector an access tag was read from.
type BasisCVSS struct {
	Version   string `json:"version"`
	Vector    string `json:"vector"`
	Source    string `json:"source"`
	SourceOrg string `json:"source_org"`
	// Metrics: the metric values that assign the tag ("AV:N", "PR:N", ...).
	Metrics []string `json:"metrics"`
}

// BasisEvent summarises the events of one source.
type BasisEvent struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	// Keys: dedupe keys (EDB ids, module names, template ids), sorted, at
	// most 10; Count: how many events in all.
	Keys  []string `json:"keys,omitempty"`
	Count int      `json:"count"`
	// KnownRansomwareCampaignUse: the KEV field (ransomware tag only).
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use,omitempty"`
}

// BasisAdvisory is one advisory and its packages in the tag's ecosystem.
type BasisAdvisory struct {
	ID        string   `json:"id"`
	Ecosystem string   `json:"ecosystem"`
	Packages  []string `json:"packages"`
}

// Assigned is one derived tag.
type Assigned struct {
	Slug  string
	Basis Basis
}

// Canonical returns the basis as canonical JSON (object keys sorted): equal
// bases give equal strings, whatever produced them (Go structs or jsonb).
func (b Basis) Canonical() string {
	raw, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	c, _ := CanonicalJSON(raw)
	return c
}

// CanonicalJSON re-encodes a JSON document with sorted object keys (jsonb
// text and Go encodings of the same value compare equal).
func CanonicalJSON(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

// Derive computes the rule tags of one CVE (pure). The result is in
// vocabulary order; suppressed tags and every tag of a rejected CVE are
// left out.
func Derive(in Input) []Assigned {
	if in.Rejected {
		return nil
	}
	got := map[string]Basis{}
	// type: CWE ids from any source
	for _, c := range in.CWE {
		for _, slug := range TagsForCWE(c.ID) {
			b := got[slug]
			srcs := append([]classify.Provenance(nil), c.Sources...)
			sort.Slice(srcs, func(i, j int) bool { return provLess(srcs[i], srcs[j]) })
			b.CWE = append(b.CWE, BasisCWE{ID: c.ID, Sources: srcs})
			got[slug] = b
		}
	}
	for slug, b := range got {
		sort.Slice(b.CWE, func(i, j int) bool { return cweLess(b.CWE[i].ID, b.CWE[j].ID) })
		got[slug] = b
	}
	// access: the best vector
	if v, ok := BestVector(in.CVSS); ok {
		for slug, metrics := range accessTags(v) {
			got[slug] = Basis{CVSS: &BasisCVSS{Version: v.Version, Vector: v.Vector, Source: v.Source, SourceOrg: v.SourceOrg,
				Metrics: metrics}}
		}
	}
	// exploit: public events
	bySrc := map[string]*BasisEvent{}
	var ransom *BasisEvent
	for _, e := range in.Events {
		switch {
		case e.Type == "kev_added" && e.Source == SrcKEV && strings.EqualFold(strings.TrimSpace(e.Ransomware), "Known"):
			if ransom == nil {
				ransom = &BasisEvent{Source: SrcKEV, Type: e.Type, KnownRansomwareCampaignUse: e.Ransomware}
			}
			ransom.Count++
		case e.Type == "poc_published" && exploitSources[e.Source] != "":
			b := bySrc[e.Source]
			if b == nil {
				b = &BasisEvent{Source: e.Source, Type: e.Type}
				bySrc[e.Source] = b
			}
			b.Count++
			if e.Key != "" {
				b.Keys = append(b.Keys, e.Key)
			}
		}
	}
	if ransom != nil {
		got["ransomware"] = Basis{Events: []BasisEvent{*ransom}}
	}
	for src, b := range bySrc {
		sort.Strings(b.Keys)
		b.Keys = dedupe(b.Keys)
		if len(b.Keys) > maxBasisItems {
			b.Keys = b.Keys[:maxBasisItems]
		}
		got[exploitSources[src]] = Basis{Events: []BasisEvent{*b}}
	}
	// ecosystem: advisory packages
	type ak struct{ slug, id string }
	pk := map[ak]*BasisAdvisory{}
	for _, a := range in.Advisories {
		for _, p := range a.Packages {
			slug, ok := ecoTags[strings.ToLower(strings.TrimSpace(p.Ecosystem))]
			if !ok {
				continue
			}
			k := ak{slug, a.ID}
			x := pk[k]
			if x == nil {
				x = &BasisAdvisory{ID: a.ID, Ecosystem: strings.ToLower(strings.TrimSpace(p.Ecosystem)), Packages: []string{}}
				pk[k] = x
			}
			if p.Name != "" {
				x.Packages = append(x.Packages, p.Name)
			}
		}
	}
	for k, x := range pk {
		sort.Strings(x.Packages)
		x.Packages = dedupe(x.Packages)
		if len(x.Packages) > maxBasisItems {
			x.Packages = x.Packages[:maxBasisItems]
		}
		b := got[k.slug]
		b.Advisories = append(b.Advisories, *x)
		got[k.slug] = b
	}
	for slug, b := range got {
		if len(b.Advisories) > 1 {
			sort.Slice(b.Advisories, func(i, j int) bool { return b.Advisories[i].ID < b.Advisories[j].ID })
			if len(b.Advisories) > maxBasisItems {
				b.Advisories = b.Advisories[:maxBasisItems]
			}
			got[slug] = b
		}
	}
	// product, product-type: affected rows and NVD CPE names
	deriveProducts(in.Affected, in.CPEs, got)
	for _, s := range in.Suppressed {
		delete(got, s)
	}
	out := make([]Assigned, 0, len(got))
	for slug, b := range got {
		out = append(out, Assigned{Slug: slug, Basis: b})
	}
	sort.Slice(out, func(i, j int) bool { return Order(out[i].Slug) < Order(out[j].Slug) })
	return out
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func rank(source string) int {
	if r, ok := classify.Precedence[source]; ok {
		return r
	}
	return len(classify.Precedence) + 1
}

func provLess(a, b classify.Provenance) bool {
	if ra, rb := rank(a.Source), rank(b.Source); ra != rb {
		return ra < rb
	}
	return a.SourceOrg < b.SourceOrg
}

func cweLess(a, b string) bool {
	na, nb := len(a), len(b)
	if na != nb {
		return na < nb // "CWE-79" < "CWE-416": numeric for the canonical form
	}
	return a < b
}

// BestVector picks the vector the access dimension reads: among the v4.0,
// v3.1 and v3.0 vectors (each version's best source, as classify.BestCVSS),
// the one from the highest-precedence source (cve-cna > cve-adp >
// nvd-primary > nvd-secondary > ghsa; ties: lowest source_org), and for the
// same source the newest version. Only when there is no v3.x/v4.0 vector at
// all, the best CVSS 2.0 vector.
func BestVector(all []classify.CVSSEntry) (classify.CVSSEntry, bool) {
	c := classify.Classification{CVSS: all}
	best := c.BestCVSS()
	var pick *classify.CVSSEntry
	for _, ver := range []string{classify.V40, classify.V31, classify.V30} {
		e, ok := best[ver]
		if !ok || !classify.ValidVector(e.Version, e.Vector) {
			continue
		}
		if pick == nil || provLess(classify.Provenance{Source: e.Source, SourceOrg: e.SourceOrg},
			classify.Provenance{Source: pick.Source, SourceOrg: pick.SourceOrg}) {
			x := e
			pick = &x
		}
	}
	if pick != nil {
		return *pick, true
	}
	if e, ok := best[classify.V2]; ok && classify.ValidVector(e.Version, e.Vector) {
		return e, true
	}
	return classify.CVSSEntry{}, false
}

// metrics parses a validated vector into metric -> value.
func metrics(v classify.CVSSEntry) map[string]string {
	body := v.Vector
	if v.Version != classify.V2 {
		_, body, _ = strings.Cut(v.Vector, "/")
	}
	m := map[string]string{}
	for _, part := range strings.Split(body, "/") {
		if k, val, ok := strings.Cut(part, ":"); ok {
			m[k] = val
		}
	}
	return m
}

// accessTags maps a vector to the access tags it assigns, each with the
// metric values that assign it.
func accessTags(v classify.CVSSEntry) map[string][]string {
	m := metrics(v)
	out := map[string][]string{}
	v2 := v.Version == classify.V2
	switch m["AV"] {
	case "N":
		out["network"] = []string{"AV:N"}
	case "A":
		out["adjacent"] = []string{"AV:A"}
	case "L":
		out["local"] = []string{"AV:L"}
	case "P":
		if !v2 {
			out["physical"] = []string{"AV:P"}
		}
	}
	if v2 {
		if m["Au"] == "N" {
			out["no-auth"] = []string{"Au:N"}
		}
		return out // CVSS 2.0 has no user-interaction metric: no no-interaction, no remote-unauth
	}
	if m["PR"] == "N" {
		out["no-auth"] = []string{"PR:N"}
	}
	if m["UI"] == "N" {
		out["no-interaction"] = []string{"UI:N"}
	}
	if m["AV"] == "N" && m["PR"] == "N" && m["UI"] == "N" {
		out["remote-unauth"] = []string{"AV:N", "PR:N", "UI:N"}
	}
	return out
}
