package sitetest

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// GHSA is a vulnerability keyed by its GitHub advisory id: an advisory
// without a CVE, shaped like the ghsa collector's output for one (a
// "disclosed" and a "patch_released" event, both with the GHSA id as
// dedupe key, and no vuln_alias row for its own id; docs/ghsa.md).
const GHSA = "GHSA-gpwc-27cw-rh9r"

// GHSAAlias is a GHSA id that is only an alias of CVE-2026-1004:
// what a GHSA-keyed vulnerability leaves behind once upstream gives it a CVE
// and the ingest side moves it there.
const GHSAAlias = "GHSA-2222-3333-4444"

// GHSADescription is GHSA's description, also the text of its raw record.
const GHSADescription = "qzmerge before 1.4.2 lets a crafted key pollute Object.prototype."

// SeedGHSA adds GHSA (patched Ago(3), published by the advisory at the same
// time) and the GHSAAlias alias to a database Seed has filled, then
// refreshes the state. It is separate from Seed so the counts the older
// tests check stay as they are.
func SeedGHSA(t testing.TB, conn *pgx.Conn) {
	t.Helper()
	s := Seeder{T: t, Conn: conn}
	pub := Ago(3)
	url := "https://github.com/advisories/" + GHSA
	s.Vuln(GHSA, P("Prototype pollution in qzmerge"))
	s.exec(`UPDATE vuln SET description = $2 WHERE cve_id = $1`, GHSA, GHSADescription)
	s.Affected(GHSA, "npm", "qzmerge")
	s.Event(Ev{CVE: GHSA, Type: "disclosed", Source: "ghsa", Occurred: &pub, Observed: Ago(2.9), URL: &url, Key: GHSA,
		Detail: `{"ghsa_id": "` + GHSA + `", "state": "PUBLISHED", "withdrawn_at": null}`})
	s.Event(Ev{CVE: GHSA, Type: "patch_released", Source: "ghsa", Occurred: &pub, Observed: Ago(2.9), URL: &url, Key: GHSA,
		Detail: `{"cvss": {"cvss_v3": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}},
		  "cwes": [{"name": "Prototype Pollution", "cwe_id": "CWE-1321"}],
		  "ghsa_id": "` + GHSA + `", "severity": "high",
		  "packages": [{"name": "qzmerge", "ecosystem": "npm", "first_patched_version": "1.4.2", "vulnerable_version_range": "< 1.4.2"}],
		  "fix_commit_urls": [], "advisory_published_at": "` + pub.Format("2006-01-02T15:04:05Z") + `"}`})
	s.Raw("ghsa", GHSA, "h-ghsa-own", `{"ghsa_id": "`+GHSA+`", "cve_id": null, "withdrawn_at": null,
	  "description": "`+GHSADescription+`", "credits": [{"type": "reporter", "user": {"login": "qzfinder"}}]}`, Ago(2.9))
	s.Alias("CVE-2026-1004", GHSAAlias, "ghsa")
	s.Refresh()
}
