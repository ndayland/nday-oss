package sitetest

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// CreditHostile is a credited name made of markup: pages must show it as
// text (escaped), never as HTML.
const CreditHostile = `<img src=x onerror=alert(1)>Eve`

// CreditContact is a profile URL of a credited GitHub user that the stored
// advisory carries; it must never appear in a response built from credits.
const CreditContact = "https://api.github.com/users/zq-credit-login/received_events"

// SeedCredits adds credited people to GPU's raw records (call after Seed;
// kept separate so tests that compare the existing JSON are unaffected):
//
//	cvelist GPU            a newer CVE record version with CNA credits: a
//	                       finder, the same finder again (duplicate), a
//	                       reporter, a credit without type, a hostile name;
//	                       the older version's credits are not read
//	ghsa GHSA-cred-0001    latest version names GPU: reporter (with profile
//	                       URLs) and a remediation developer
//	ghsa GHSA-cred-0002    an older version named GPU, the latest names
//	                       CVE-2026-1003: nothing for GPU
//	ghsa GHSA-cred-0003    names GPU but is withdrawn: nothing
func SeedCredits(t testing.TB, conn *pgx.Conn) {
	t.Helper()
	s := Seeder{T: t, Conn: conn}
	s.Raw("cvelist", GPU, "h-cvelist-credits-old", `{"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "`+GPU+`"},
	  "containers": {"cna": {"credits": [{"lang": "en", "type": "finder", "value": "Old Version Person"}]}}}`, Ago(30))
	s.Raw("cvelist", GPU, "h-cvelist-credits", `{"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "`+GPU+`"},
	  "containers": {"cna": {"credits": [
	    {"lang": "en", "type": "finder", "value": "Zhang Wei of Example Lab"},
	    {"lang": "en", "type": "finder", "value": " Zhang Wei  of Example Lab "},
	    {"lang": "en", "type": "reporter", "value": "Example PSIRT"},
	    {"lang": "en", "value": "Anonymous researcher"},
	    {"lang": "en", "type": "finder", "value": "`+CreditHostile+`"}]}}}`, Ago(0.5))
	user := func(login string) string {
		return `{"login": "` + login + `", "id": 1, "url": "https://api.github.com/users/` + login + `",
		  "html_url": "https://github.com/` + login + `", "received_events_url": "https://api.github.com/users/` + login + `/received_events"}`
	}
	s.Raw("ghsa", "GHSA-cred-0001", "h-cred-1", `{"ghsa_id": "GHSA-cred-0001", "cve_id": "`+GPU+`", "withdrawn_at": null,
	  "credits": [{"type": "reporter", "user": `+user("zq-credit-login")+`},
	              {"type": "remediation_developer", "user": `+user("fixer-dev")+`}]}`, Ago(0.5))
	s.Raw("ghsa", "GHSA-cred-0002", "h-cred-2a", `{"ghsa_id": "GHSA-cred-0002", "cve_id": "`+GPU+`",
	  "credits": [{"type": "finder", "user": `+user("moved-away")+`}]}`, Ago(3))
	s.Raw("ghsa", "GHSA-cred-0002", "h-cred-2b", `{"ghsa_id": "GHSA-cred-0002", "cve_id": "CVE-2026-1003",
	  "credits": [{"type": "finder", "user": `+user("moved-away")+`}]}`, Ago(1))
	s.Raw("ghsa", "GHSA-cred-0003", "h-cred-3", `{"ghsa_id": "GHSA-cred-0003", "cve_id": "`+GPU+`",
	  "withdrawn_at": "2026-11-01T00:00:00Z", "credits": [{"type": "finder", "user": `+user("withdrawn-one")+`}]}`, Ago(1))
}
