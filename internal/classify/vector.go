package classify

import (
	"strconv"
	"strings"
)

// CVSS versions stored in vuln_cvss.version.
const (
	V2  = "2.0"
	V30 = "3.0"
	V31 = "3.1"
	V40 = "4.0"
)

// metricSet: metric name -> allowed values; base lists the mandatory metrics.
type metricSet struct {
	base    []string
	allowed map[string]string // allowed values as a string of single letters, or "|"-separated words
}

func vals(m map[string]string, keys []string, v string) {
	for _, k := range keys {
		m[k] = v
	}
}

var v2Set = metricSet{
	base: []string{"AV", "AC", "Au", "C", "I", "A"},
	allowed: map[string]string{
		"AV": "LAN", "AC": "HML", "Au": "MSN", "C": "NPC", "I": "NPC", "A": "NPC",
		// optional temporal and environmental metrics (CVSS v2 guide §2.4):
		// some CNAs (e.g. VulDB) deliver "AV:N/.../A:P/E:POC/RL:OF/RC:C"
		"E": "U|POC|F|H|ND", "RL": "OF|TF|W|U|ND", "RC": "UC|UR|C|ND",
		"CDP": "N|L|LM|MH|H|ND", "TD": "N|L|M|H|ND", "CR": "L|M|H|ND", "IR": "L|M|H|ND", "AR": "L|M|H|ND",
	},
}

var v3Set = func() metricSet {
	m := map[string]string{
		"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN",
		// temporal
		"E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
		// environmental
		"CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
		"MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
		"MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
	}
	return metricSet{base: []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}, allowed: m}
}()

var v4Set = func() metricSet {
	m := map[string]string{
		"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
		"E": "XAPU", "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
		"MSI": "XNLHS", "MSA": "XNLHS",
		"S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH",
		"U": "X|Clear|Green|Amber|Red",
	}
	vals(m, []string{"VC", "VI", "VA", "SC", "SI", "SA"}, "HLN")
	vals(m, []string{"CR", "IR", "AR"}, "XHML")
	vals(m, []string{"MVC", "MVI", "MVA", "MSC"}, "XNLH")
	return metricSet{base: []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}, allowed: m}
}()

func (s metricSet) valueOK(metric, v string) bool {
	a, ok := s.allowed[metric]
	if !ok || v == "" {
		return false
	}
	if strings.Contains(a, "|") {
		for _, w := range strings.Split(a, "|") {
			if w == v {
				return true
			}
		}
		return false
	}
	return len(v) == 1 && strings.Contains(a, v)
}

// check parses "K:V/K:V..." against s: every metric known, every value
// allowed, no metric twice, every base metric present. Order is not checked
// (the CVSS specifications define an order for producers but parsers in the
// wild accept any; a vector we would reject only for its order would still
// be a correct description of the vulnerability).
func (s metricSet) check(body string) bool {
	if body == "" {
		return false
	}
	seen := make(map[string]bool, 16)
	for _, part := range strings.Split(body, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || seen[k] || !s.valueOK(k, v) {
			return false
		}
		seen[k] = true
	}
	for _, b := range s.base {
		if !seen[b] {
			return false
		}
	}
	return true
}

// ValidVector reports whether vector is a well-formed CVSS vector of the
// given version:
//   - "2.0": the bare base vector AV:_/AC:_/Au:_/C:_/I:_/A:_ (as NVD and CVE
//     records deliver it: no "CVSS:2.0/" prefix and no parentheses), all six
//     base metrics, optional temporal/environmental metrics;
//   - "3.0" / "3.1": "CVSS:3.x/" with exactly that minor version, all eight
//     base metrics, optional temporal and environmental metrics;
//   - "4.0": "CVSS:4.0/" with all eleven base metrics, optional threat,
//     environmental and supplemental metrics.
func ValidVector(version, vector string) bool {
	switch version {
	case V2:
		return v2Set.check(vector)
	case V30, V31:
		body, ok := strings.CutPrefix(vector, "CVSS:"+version+"/")
		return ok && v3Set.check(body)
	case V40:
		body, ok := strings.CutPrefix(vector, "CVSS:4.0/")
		return ok && v4Set.check(body)
	}
	return false
}

// VersionOfVector returns the version a vector declares ("CVSS:3.1/..." ->
// "3.1"; a bare "AV:" vector -> "2.0"), or "" when it declares none we store.
func VersionOfVector(vector string) string {
	if rest, ok := strings.CutPrefix(vector, "CVSS:"); ok {
		v, _, _ := strings.Cut(rest, "/")
		switch v {
		case V30, V31, V40:
			return v
		}
		return ""
	}
	if strings.HasPrefix(vector, "AV:") {
		return V2
	}
	return ""
}

// NormalizeCWE maps "CWE-79" (any case, surrounding space, leading zeros)
// to "CWE-79"; anything else (NVD-CWE-noinfo, NVD-CWE-Other, free text,
// "n/a") returns "" and is not stored.
func NormalizeCWE(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 5 || !strings.EqualFold(s[:4], "CWE-") {
		return ""
	}
	digits := s[4:]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return ""
		}
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return ""
	}
	return "CWE-" + strconv.FormatUint(n, 10)
}
