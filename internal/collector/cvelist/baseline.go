package cvelist

import "strings"

// ZipMemberCVE reports the CVE id of a zip member name exactly like the
// collector's end-of-day zip reader (zipRecords): the name must match
// ZIP_MEMBER_RE (…/CVE-YYYY-N….json) and not be a directory. Used by the
// full-baseline importer (internal/cveimport) so it selects the same members.
func ZipMemberCVE(name string) (string, bool) {
	if strings.HasSuffix(name, "/") {
		return "", false
	}
	m := zipMemberRe.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	return m[1], true
}
