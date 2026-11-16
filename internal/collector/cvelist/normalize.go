package cvelist

import (
	"regexp"
	"strings"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// ghsaRe is GHSA_RE used with fullmatch.
var ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

// cvssKeys is CVSS_KEYS (preference order).
var cvssKeys = []string{"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"}

func tsPtr(v any) *time.Time {
	t, ok := parseTS(v)
	if !ok {
		return nil
	}
	u := t.Time()
	return &u
}

// englishDescription is _english_description.
func englishDescription(cna *pyjson.Object) (*string, error) {
	items, err := iterOr(cna.Get("descriptions"))
	if err != nil {
		return nil, err
	}
	var descs []*pyjson.Object
	for _, d := range items {
		if o := asObject(d); o != nil {
			descs = append(descs, o)
		}
	}
	for _, exact := range []bool{true, false} {
		for _, d := range descs {
			lang := ""
			if l := collector.Text(d.Get("lang")); l != nil {
				lang = strings.ToLower(*l)
			}
			match := lang == "en"
			if !exact {
				match = strings.HasPrefix(lang, "en")
			}
			if match {
				if v := collector.Text(d.Get("value")); v != nil {
					return v, nil
				}
			}
		}
	}
	return nil, nil
}

// cvssFrom is _cvss_from.
func cvssFrom(metrics any, source string) map[string]any {
	list, ok := metrics.([]any)
	if !ok {
		return nil
	}
	for _, key := range cvssKeys {
		for _, m := range list {
			mo := asObject(m)
			if mo == nil {
				continue
			}
			c := asObject(mo.Get(key))
			if c == nil || c.Get("baseScore") == nil {
				continue
			}
			version := c.Get("version")
			if !truthy(version) {
				version = strings.ReplaceAll(key[5:], "_", ".")
			}
			return map[string]any{
				"version":       version,
				"base_score":    c.Get("baseScore"),
				"base_severity": c.Get("baseSeverity"),
				"vector":        c.Get("vectorString"),
				"source":        source,
			}
		}
	}
	return nil
}

// extractCVSS is extract_cvss: CNA metrics first (newest CVSS version wins),
// else the first ADP container that has one.
func extractCVSS(containers *pyjson.Object) (map[string]any, error) {
	cna, err := getOrEmpty(containers.Get("cna"), "metrics")
	if err != nil {
		return nil, err
	}
	if found := cvssFrom(cna, "cna"); found != nil {
		return found, nil
	}
	adps, err := iterOr(containers.Get("adp"))
	if err != nil {
		return nil, err
	}
	for _, a := range adps {
		adp := asObject(a)
		if adp == nil {
			continue
		}
		sn, err := getOrEmpty(adp.Get("providerMetadata"), "shortName")
		if err != nil {
			return nil, err
		}
		name := "unknown"
		if s := collector.Text(sn); s != nil {
			name = *s
		}
		if found := cvssFrom(adp.Get("metrics"), "adp:"+name); found != nil {
			return found, nil
		}
	}
	return nil, nil
}

// cisaADPFacts is _cisa_adp_facts: CISA-ADP SSVC decision points and the
// KEV marker, verbatim values.
func cisaADPFacts(containers *pyjson.Object, out map[string]any) error {
	adps, err := iterOr(containers.Get("adp"))
	if err != nil {
		return err
	}
	for _, a := range adps {
		adp := asObject(a)
		if adp == nil {
			continue
		}
		sn, err := getOrEmpty(adp.Get("providerMetadata"), "shortName")
		if err != nil {
			return err
		}
		if !pyStrEq(sn, "CISA-ADP") {
			continue
		}
		metrics, err := iterOr(adp.Get("metrics"))
		if err != nil {
			return err
		}
		for _, m := range metrics {
			mo := asObject(m)
			if mo == nil {
				continue
			}
			other := asObject(mo.Get("other"))
			if other == nil {
				continue
			}
			var content any = other.Get("content")
			if !truthy(content) {
				content = pyjson.NewObject()
			}
			co := asObject(content)
			typ := other.Get("type")
			if pyStrEq(typ, "ssvc") && co != nil {
				opts := pyjson.NewObject()
				options, err := iterOr(co.Get("options"))
				if err != nil {
					return err
				}
				for _, o := range options {
					if oo := asObject(o); oo != nil {
						for _, k := range oo.Keys() {
							opts.Set(k, oo.Get(k))
						}
					}
				}
				out["ssvc"] = map[string]any{
					"exploitation":     opts.Get("Exploitation"),
					"automatable":      opts.Get("Automatable"),
					"technical_impact": opts.Get("Technical Impact"),
					"timestamp":        co.Get("timestamp"),
				}
			} else if pyStrEq(typ, "kev") && co != nil {
				out["kev"] = map[string]any{
					"date_added": co.Get("dateAdded"),
					"reference":  co.Get("reference"),
				}
			}
		}
	}
	return nil
}

// Normalize maps one CVE JSON 5 record to an authoritative vuln row, affected
// rows, an optional GHSA alias and one disclosed event (see package doc).
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p := asObject(rec.Payload)
	if p == nil {
		return nil, collector.NormalizeErrorf("payload is not a JSON object")
	}
	meta := asObject(p.Get("cveMetadata"))
	containers := p.Get("containers")
	if !pyStrEq(p.Get("dataType"), "CVE_RECORD") || meta == nil {
		return nil, collector.NormalizeErrorf("not a CVE JSON 5 record (dataType/cveMetadata)")
	}
	cve := collector.Text(meta.Get("cveId"))
	if cve == nil || !model.IsValidCVEID(*cve) {
		return nil, collector.NormalizeErrorf("bad cveId: %s", pyjson.Repr(meta.Get("cveId")))
	}
	if *cve != rec.SourceKey {
		return nil, collector.NormalizeErrorf("cveId %s != source_key %s", *cve, rec.SourceKey)
	}
	state := meta.Get("state")
	if pyStrEq(state, "RESERVED") {
		return &model.Normalized{}, nil // nothing public to say; raw is kept
	}
	if !pyStrEq(state, "PUBLISHED") && !pyStrEq(state, "REJECTED") {
		return nil, collector.NormalizeErrorf("unknown state %s", pyjson.Repr(state))
	}
	co := asObject(containers)
	if co == nil || asObject(co.Get("cna")) == nil {
		return nil, collector.NormalizeErrorf("missing containers.cna")
	}
	cna := asObject(co.Get("cna"))

	publishedAt := tsPtr(meta.Get("datePublished"))
	modifiedAt := tsPtr(meta.Get("dateUpdated"))
	out := &model.Normalized{}
	detail := map[string]any{
		"state":               state,
		"assigner_short_name": meta.Get("assignerShortName"),
		"date_published":      meta.Get("datePublished"),
	}

	if pyStrEq(state, "REJECTED") {
		out.Vulns = append(out.Vulns, model.VulnUpsert{CVEID: *cve, PublishedAt: publishedAt,
			ModifiedAt: modifiedAt, Authoritative: true})
		detail["date_rejected"] = meta.Get("dateRejected")
		reasons, err := iterOr(cna.Get("rejectedReasons"))
		if err != nil {
			return nil, err
		}
		values := []any{}
		for _, r := range reasons {
			if ro := asObject(r); ro != nil {
				values = append(values, ro.Get("value"))
			}
		}
		detail["rejected_reasons"] = values
		if truthy(cna.Get("replacedBy")) {
			detail["replaced_by"] = cna.Get("replacedBy")
		}
	} else {
		desc, err := englishDescription(cna)
		if err != nil {
			return nil, err
		}
		out.Vulns = append(out.Vulns, model.VulnUpsert{
			CVEID:         *cve,
			Title:         collector.Text(cna.Get("title")),
			Description:   desc,
			PublishedAt:   publishedAt,
			ModifiedAt:    modifiedAt,
			Authoritative: true,
		})
		affected, err := iterOr(cna.Get("affected"))
		if err != nil {
			return nil, err
		}
		type vp struct{ v, p string }
		seen := map[vp]bool{}
		for _, a := range affected {
			ao := asObject(a)
			if ao == nil {
				continue
			}
			vendor, product := collector.Text(ao.Get("vendor")), collector.Text(ao.Get("product"))
			if vendor == nil || product == nil || strings.ToLower(*vendor) == "n/a" || strings.ToLower(*product) == "n/a" {
				continue
			}
			k := vp{*vendor, *product}
			if !seen[k] {
				seen[k] = true
				out.Affected = append(out.Affected, model.Affected{CVEID: *cve, Vendor: *vendor, Product: *product})
			}
		}
		if src := asObject(cna.Get("source")); src != nil {
			if adv := collector.Text(src.Get("advisory")); adv != nil && ghsaRe.MatchString(*adv) {
				out.Aliases = append(out.Aliases, model.Alias{CVEID: *cve, Alias: *adv, AliasType: "ghsa"})
			}
		}
		cvss, err := extractCVSS(co)
		if err != nil {
			return nil, err
		}
		if cvss != nil {
			detail["cvss"] = cvss
		}
		if err := cisaADPFacts(co, detail); err != nil {
			return nil, err
		}
	}

	out.Events = append(out.Events, model.Event{
		CVEID:      *cve,
		Type:       model.EventDisclosed,
		Source:     Name,
		OccurredAt: publishedAt,
		URL:        model.Ptr(CVEOrgURL + *cve),
		Detail:     detail,
		DedupeKey:  "",
	})
	return out, nil
}
