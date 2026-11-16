// Package sitetest seeds a migrated test schema with a small, realistic data
// set for the site and web tests (events shaped like each collector's
// Normalize output).
package sitetest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/state"
)

// Now is the fixture clock: every relative time below is before it.
var Now = time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)

// Ago returns Now minus days.
func Ago(days float64) time.Time { return Now.Add(-time.Duration(days * float64(24*time.Hour))) }

// Day returns 00:00Z of the given date.
func Day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// Seeder inserts rows.
type Seeder struct {
	T    testing.TB
	Conn *pgx.Conn
}

func (s Seeder) exec(sql string, args ...any) {
	s.T.Helper()
	if _, err := s.Conn.Exec(context.Background(), sql, args...); err != nil {
		s.T.Fatalf("%v\n%s", err, sql)
	}
}

// Vuln inserts a vuln row (title may be nil).
func (s Seeder) Vuln(cve string, title *string) {
	s.T.Helper()
	s.exec(`INSERT INTO vuln (cve_id, title, first_seen_at) VALUES ($1, $2, $3)`, cve, title, Ago(1))
}

// TitleZh sets title_zh.
func (s Seeder) TitleZh(cve, t string) {
	s.T.Helper()
	s.exec(`UPDATE vuln SET title_zh = $2 WHERE cve_id = $1`, cve, t)
}

// Affected inserts an affected row.
func (s Seeder) Affected(cve, vendor, product string) {
	s.T.Helper()
	s.exec(`INSERT INTO affected (cve_id, vendor, product) VALUES ($1, $2, $3)`, cve, vendor, product)
}

// Alias inserts an alias.
func (s Seeder) Alias(cve, alias, typ string) {
	s.T.Helper()
	s.exec(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, $3)`, cve, alias, typ)
}

// Ev is an event to insert.
type Ev struct {
	CVE, Type, Source string
	Occurred          *time.Time
	Observed          time.Time // zero = Ago(1)
	Backfill          bool
	URL               *string
	Detail            string // JSON; "" = {}
	Key               string
}

// Event inserts an event and returns its id.
func (s Seeder) Event(e Ev) int64 {
	s.T.Helper()
	if e.Detail == "" {
		e.Detail = "{}"
	}
	if e.Observed.IsZero() {
		e.Observed = Ago(1)
	}
	var id int64
	err := s.Conn.QueryRow(context.Background(), `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url,
            detail, is_backfill, dedupe_key) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) RETURNING id`,
		e.CVE, e.Type, e.Occurred, e.Observed, e.Source, e.URL, e.Detail, e.Backfill, e.Key).Scan(&id)
	if err != nil {
		s.T.Fatal(err)
	}
	return id
}

// Raw inserts a raw_record version.
func (s Seeder) Raw(source, key, hash, payload string, fetched time.Time) {
	s.T.Helper()
	s.exec(`INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
            VALUES ($1, $2, $3, $4, $5::jsonb)`, source, key, fetched, hash, payload)
}

// Collector inserts a collector_state row.
func (s Seeder) Collector(source, status string, run, success *time.Time, errText *string) {
	s.T.Helper()
	s.exec(`INSERT INTO collector_state (source, last_run_at, last_status, last_success_at, last_error)
            VALUES ($1, $2, $3, $4, $5)`, source, run, status, success, errText)
}

// Refresh materializes the state.
func (s Seeder) Refresh() {
	s.T.Helper()
	if _, err := state.Refresh(context.Background(), s.Conn, state.RefreshOptions{Wait: true}); err != nil {
		s.T.Fatal(err)
	}
}

func P[T any](v T) *T { return &v }

// GPU is the all-six-sources vulnerability (shaped like CVE-2026-102895).
const GPU = "CVE-2026-102895"

// Fixture ids returned by Seed.
type Fixture struct {
	GPUEvents map[string]int64 // by source
}

// Seed inserts the standard data set and refreshes the state:
//
//	GPU            all six sources: DIS exact 11-04T21:16:59Z, PAT unknown (ghsa),
//	               POC day 11-08 (exploitdb) + metasploit + nuclei, KEV day 11-09
//	               (latest) -> ITW implied
//	CVE-2026-1001  KEV day Ago(2) only, no title, no disclosure
//	CVE-2026-1002  POC observed live (metasploit, Ago(3)), disclosed Ago(10)
//	CVE-2026-1003  PAT exact Ago(4), title_zh set
//	CVE-2026-1004  disclosed only Ago(0.5)
//	CVE-2026-1005  REJECTED, PAT exact Ago(0.2)
//	CVE-2026-1006  PAT exact Ago(40) (outside 30d)
//	CVE-2026-1007/1008  KEV day at the same instant Ago(5) (tie -> cve_id desc)
//	CVE-2026-1009  ITW event with unknown time + KEV: ITW slot "unknown", not implied
//	CVE-2026-1010  vuln without any event
func Seed(t testing.TB, conn *pgx.Conn) Fixture {
	t.Helper()
	s := Seeder{T: t, Conn: conn}
	f := Fixture{GPUEvents: map[string]int64{}}

	s.Vuln(GPU, P("GPUStack: Authentication bypass via trusted loopback source"))
	s.Affected(GPU, "GPUStack", "GPUStack")
	s.Affected(GPU, "gpustack", "gpustack") // same pair, other case: deduplicated
	s.Alias(GPU, "GHSA-gj9m-f8ph-pmhr", "ghsa")
	f.GPUEvents["cvelist"] = s.Event(Ev{CVE: GPU, Type: "disclosed", Source: "cvelist",
		Occurred: P(time.Date(2026, 11, 4, 21, 16, 59, 842e6, time.UTC)), Backfill: true,
		URL: P("https://www.cve.org/CVERecord?id=" + GPU),
		Detail: `{"kev": {"reference": "https://www.cisa.gov/x", "date_added": "2026-11-09"},
		  "cvss": {"source": "cna", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1", "base_score": 9.8, "base_severity": "CRITICAL"},
		  "ssvc": {"timestamp": "2026-11-05T00:00:00+00:00", "automatable": "yes", "exploitation": "active", "technical_impact": "total"},
		  "state": "PUBLISHED", "date_published": "2026-11-04T21:16:59.842Z", "assigner_short_name": "GitHub_M"}`})
	f.GPUEvents["kev"] = s.Event(Ev{CVE: GPU, Type: "kev_added", Source: "kev", Occurred: P(Day(2026, 11, 9)), Backfill: true,
		URL: P("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
		Detail: `{"cwes": ["CWE-287", "CWE-290", "CWE-346"], "notes": "n", "product": "GPUStack", "due_date": "2026-11-12",
		  "precision": "day", "date_added": "2026-11-09", "vendor_project": "GPUStack", "forensic_triage": "Yes",
		  "required_action": "Apply mitigations", "vulnerability_name": "GPUStack Improper Authentication Vulnerability",
		  "known_ransomware_campaign_use": "Unknown"}`})
	f.GPUEvents["ghsa"] = s.Event(Ev{CVE: GPU, Type: "patch_released", Source: "ghsa", Backfill: true,
		URL: P("https://github.com/advisories/GHSA-gj9m-f8ph-pmhr"), Key: "GHSA-gj9m-f8ph-pmhr",
		Detail: `{"cvss": {"cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "cvss_v4": {"score": 0.0, "vector_string": null}},
		  "cwes": [{"name": "Improper Authentication", "cwe_id": "CWE-287"}, {"name": "Authentication Bypass by Spoofing", "cwe_id": "CWE-290"}, {"name": "Origin Validation Error", "cwe_id": "CWE-346"}, {"name": "Improper Input Validation", "cwe_id": "CWE-20"}],
		  "ghsa_id": "GHSA-gj9m-f8ph-pmhr",
		  "packages": [{"name": "gpustack", "ecosystem": "pip", "first_patched_version": "2.2.0", "vulnerable_version_range": "< 2.2.0"},
		               {"name": "gpustack-ui", "ecosystem": "npm", "first_patched_version": null, "vulnerable_version_range": "<= 1.0"}],
		  "severity": "critical", "references": [],
		  "fix_commit_urls": ["https://github.com/gpustack/gpustack/pull/5346", "https://github.com/gpustack/gpustack/commit/53f42a6"],
		  "github_reviewed_at": "2026-11-09T22:15:27Z", "advisory_updated_at": "2026-11-09T22:15:29Z",
		  "source_code_location": "https://github.com/gpustack/gpustack", "advisory_published_at": "2026-11-09T22:15:27Z"}`})
	f.GPUEvents["exploitdb"] = s.Event(Ev{CVE: GPU, Type: "poc_published", Source: "exploitdb", Occurred: P(Day(2026, 11, 8)),
		Backfill: true, URL: P("https://www.exploit-db.com/exploits/52001"), Key: "52001",
		Detail: `{"kind": "exploit", "confidence": "curated", "title": "GPUStack 2.1 - Auth Bypass", "url": "https://www.exploit-db.com/exploits/52001", "edb_id": 52001, "precision": "day"}`})
	f.GPUEvents["metasploit"] = s.Event(Ev{CVE: GPU, Type: "poc_published", Source: "metasploit", Backfill: true,
		URL:    P("https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/gpustack_rce.rb"),
		Key:    "exploit/linux/http/gpustack_rce",
		Detail: `{"kind": "msf_module", "confidence": "curated", "title": "GPUStack RCE", "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/gpustack_rce.rb", "fullname": "exploit/linux/http/gpustack_rce"}`})
	f.GPUEvents["nuclei"] = s.Event(Ev{CVE: GPU, Type: "poc_published", Source: "nuclei", Backfill: true,
		URL: P("https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-102895.yaml"),
		Key: GPU, Detail: `{"kind": "detection_template", "confidence": "curated", "title": "GPUStack - Auth Bypass", "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-102895.yaml", "template_id": "CVE-2026-102895"}`})
	s.Raw("cvelist", GPU, "h-cvelist", `{"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "`+GPU+`"}}`, Ago(1))
	s.Raw("kev", GPU, "h-kev-old", `{"cveID": "`+GPU+`", "v": 1}`, Ago(3))
	s.Raw("kev", GPU, "h-kev-new", `{"cveID": "`+GPU+`", "v": 2}`, Ago(1))
	s.Raw("ghsa", "GHSA-gj9m-f8ph-pmhr", "h-ghsa", `{"ghsa_id": "GHSA-gj9m-f8ph-pmhr"}`, Ago(1))
	s.Raw("exploitdb", "52001", "h-edb", `{"id": "52001"}`, Ago(1))
	s.Raw("metasploit", "exploit/linux/http/gpustack_rce", "h-msf", `{"fullname": "exploit/linux/http/gpustack_rce"}`, Ago(1))
	s.Raw("nuclei", GPU, "h-nuclei", `{"ID": "`+GPU+`"}`, Ago(1))

	s.Vuln("CVE-2026-1001", nil)
	s.Event(Ev{CVE: "CVE-2026-1001", Type: "kev_added", Source: "kev", Occurred: P(Ago(2).Truncate(24 * time.Hour)),
		Backfill: false, Detail: `{"precision": "day"}`})
	s.Affected("CVE-2026-1001", "Barracuda Networks", "Email Security Gateway (ESG)")
	s.Affected("CVE-2026-1001", "Barracuda Networks", "Load Balancer ADC")
	s.Affected("CVE-2026-1001", "Barracuda Networks", "Web Application Firewall")

	s.Vuln("CVE-2026-1002", P("Ruflo MCP bridge RCE"))
	s.Event(Ev{CVE: "CVE-2026-1002", Type: "disclosed", Source: "cvelist", Occurred: P(Ago(10)), Detail: `{"state": "PUBLISHED"}`})
	s.Event(Ev{CVE: "CVE-2026-1002", Type: "poc_published", Source: "metasploit", Observed: Ago(3), Backfill: false, Key: "m1"})

	s.Vuln("CVE-2026-1003", P("cowlib header splitting"))
	s.TitleZh("CVE-2026-1003", "cowlib 响应拆分")
	s.Event(Ev{CVE: "CVE-2026-1003", Type: "patch_released", Source: "ghsa", Occurred: P(Ago(4)), Key: "GHSA-aaaa-bbbb-cccc"})

	s.Vuln("CVE-2026-1004", P("only disclosed"))
	s.Event(Ev{CVE: "CVE-2026-1004", Type: "disclosed", Source: "cvelist", Occurred: P(Ago(0.5)), Detail: `{"state": "PUBLISHED"}`})

	s.Vuln("CVE-2026-1005", P("rejected one"))
	s.Event(Ev{CVE: "CVE-2026-1005", Type: "disclosed", Source: "cvelist", Occurred: P(Ago(9)),
		Detail: `{"state": "REJECTED", "date_rejected": "2026-11-12T00:00:00Z", "rejected_reasons": ["dup"], "replaced_by": ["CVE-2026-1003"]}`})
	s.Event(Ev{CVE: "CVE-2026-1005", Type: "patch_released", Source: "ghsa", Occurred: P(Ago(0.2)), Key: "GHSA-r"})

	s.Vuln("CVE-2026-1006", P("old patch"))
	s.Event(Ev{CVE: "CVE-2026-1006", Type: "patch_released", Source: "ghsa", Occurred: P(Ago(40)), Key: "GHSA-o"})

	tie := Ago(5).Truncate(24 * time.Hour)
	for _, c := range []string{"CVE-2026-1007", "CVE-2026-1008"} {
		s.Vuln(c, P("tie "+c))
		s.Event(Ev{CVE: c, Type: "kev_added", Source: "kev", Occurred: &tie, Detail: `{"precision": "day"}`})
	}

	s.Vuln("CVE-2026-1009", P("itw unknown time"))
	s.Event(Ev{CVE: "CVE-2026-1009", Type: "exploited_in_wild", Source: "x", Backfill: true})
	s.Event(Ev{CVE: "CVE-2026-1009", Type: "kev_added", Source: "kev", Occurred: P(Ago(6).Truncate(24 * time.Hour)), Detail: `{"precision": "day"}`})

	s.Vuln("CVE-2026-1010", P("no events"))

	run := Ago(0.1)
	s.Collector("cvelist", "ok", &run, &run, nil)
	s.Collector("kev", "error", P(Ago(0.05)), P(Ago(0.2)), P(longError()))
	s.Refresh()
	return f
}

func longError() string {
	b := make([]rune, 400)
	for i := range b {
		b[i] = '错'
	}
	return string(b)
}
