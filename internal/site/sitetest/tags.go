package sitetest

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/tags"
)

// SeedTags adds classification rows to the Seed data set and derives the
// tags (call after Seed; kept separate so tests that compare the
// classification object are unaffected):
//
//	GPU            CWE-287 (CNA, NVD analysts), CWE-290 (GHSA), CVSS 3.1
//	               AV:N/PR:N/UI:N from the CNA -> auth-bypass, remote-unauth,
//	               network, no-auth, no-interaction; Metasploit, Exploit-DB,
//	               nuclei from its events
//	CVE-2026-1002  CWE-78 and a CVSS 2.0 vector from NVD's analysts ->
//	               command-injection, network, no-auth (no no-interaction)
//	CVE-2026-1003  CWE-113 -> crlf-injection
//	CVE-2026-1008  KEV entry with known ransomware use -> ransomware
//	CVE-2026-1005  REJECTED, CWE-79 -> no tags
//	CVE-2026-1002  also: affected D-Link DIR-605L -> network-device (type
//	               rule d-link:router); the classified NVD record's vulnerable
//	               CPE o:fortinet:fortios -> fortios, firewall-vpn (its
//	               platform CPE a:microsoft:windows_10, vulnerable = false, is
//	               ignored: no windows tag)
func SeedTags(t testing.TB, conn *pgx.Conn) {
	t.Helper()
	s := Seeder{T: t, Conn: conn}
	s.exec(`INSERT INTO vuln_cwe (cve_id, cwe, source, source_org) VALUES
        ($1, 'CWE-287', 'cve-cna', 'GitHub_M'), ($1, 'CWE-287', 'nvd-primary', 'nvd@nist.gov'),
        ($1, 'CWE-290', 'ghsa', 'GHSA-gj9m-f8ph-pmhr'),
        ('CVE-2026-1002', 'CWE-78', 'nvd-primary', 'nvd@nist.gov'),
        ('CVE-2026-1003', 'CWE-113', 'cve-cna', 'GitHub_M'),
        ('CVE-2026-1005', 'CWE-79', 'cve-cna', 'mitre')`, GPU)
	s.exec(`INSERT INTO vuln_cvss (cve_id, version, vector, base_score, severity, source, source_org) VALUES
        ($1, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'CRITICAL', 'cve-cna', 'GitHub_M'),
        ('CVE-2026-1002', '2.0', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', 7.5, 'HIGH', 'nvd-primary', 'nvd@nist.gov')`, GPU)
	s.exec(`UPDATE event SET detail = detail || '{"known_ransomware_campaign_use": "Known"}'
        WHERE cve_id = 'CVE-2026-1008' AND type = 'kev_added'`)
	s.Affected("CVE-2026-1002", "D-Link", "DIR-605L")
	nvd := `{"id": "CVE-2026-1002", "vulnStatus": "Analyzed", "configurations": [{"nodes": [{"operator": "OR", "negate": false,
	  "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:7.2.0:*:*:*:*:*:*:*"},
	               {"vulnerable": false, "criteria": "cpe:2.3:a:microsoft:windows_10:-:*:*:*:*:*:*:*"}]}]}]}`
	s.exec(`INSERT INTO raw_record (source, source_key, content_hash, payload) VALUES ('nvd', 'CVE-2026-1002', 'h-nvd-1002', $1::jsonb)`, nvd)
	s.exec(`INSERT INTO vuln_classify_input (cve_id, source, source_key, content_hash, rejected) VALUES
        ('CVE-2026-1002', 'nvd', 'CVE-2026-1002', 'h-nvd-1002', false)`)
	if _, err := tags.All(context.Background(), conn, tags.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
}
