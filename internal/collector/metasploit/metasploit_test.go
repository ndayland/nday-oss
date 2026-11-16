package metasploit_test

// Port of tests/test_metasploit.py.

import (
	"errors"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/feed/feedtest"
	"nday.land/nday/internal/collector/metasploit"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var T0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func mod(t *testing.T, fullname string) *pyjson.Object {
	t.Helper()
	data := feedtest.Msf.Load(t).(*pyjson.Object)
	for _, k := range data.Keys() {
		if m := data.Get(k).(*pyjson.Object); m.Get("fullname") == fullname {
			return m
		}
	}
	t.Fatalf("no module %s", fullname)
	return nil
}

func normalize(p *pyjson.Object) (*model.Normalized, error) {
	c, _ := metasploit.New(feed.Options{})
	key, _ := p.Get("fullname").(string)
	return c.Normalize(model.RawRecord{Source: "metasploit", SourceKey: key, Payload: p})
}

func mustNorm(t *testing.T, p *pyjson.Object) *model.Normalized {
	t.Helper()
	n, err := normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func isNormErr(err error, msg string) bool {
	var ne *collector.NormalizeError
	return errors.As(err, &ne) && ne.Msg == msg
}

func TestNormalizeTypicalModuleOccurredAtNone(t *testing.T) {
	p := mod(t, "exploit/multi/http/langflow_unauth_rce_cve_2026_9198")
	norm := mustNorm(t, p)
	if len(norm.Vulns)+len(norm.Aliases)+len(norm.Affected) != 0 || len(norm.Events) != 1 {
		t.Fatalf("%+v", norm)
	}
	ev := norm.Events[0]
	if ev.CVEID != "CVE-2026-9198" || ev.Type != "poc_published" || ev.Source != "metasploit" || ev.DedupeKey != p.Get("fullname") {
		t.Errorf("%+v", ev)
	}
	// disclosure_date is the vuln's, mod_time is last modification: neither qualifies
	if ev.OccurredAt != nil {
		t.Error("occurred_at set")
	}
	if *ev.URL != "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/langflow_unauth_rce_cve_2026_9198.rb" {
		t.Error(*ev.URL)
	}
	d := ev.Detail
	if d["kind"] != "msf_module" || d["confidence"] != "curated" || d["url"] != *ev.URL || d["title"] != p.Get("name") ||
		d["fullname"] != p.Get("fullname") || d["module_type"] != "exploit" || d["rank"] != pyjson.Int("600") ||
		d["rank_name"] != "excellent" || d["vuln_disclosure_date"] != "2026-07-17" ||
		d["module_last_modified"] != "2026-08-21 14:02:04 +0000" || d["path"] != p.Get("path") {
		t.Errorf("detail %v", d)
	}
	for _, k := range []string{"precision", "disclosure_date", "mod_time"} {
		if _, ok := d[k]; ok {
			t.Errorf("detail has %s", k)
		}
	}
}

func TestMultiCVEModule(t *testing.T) {
	evs := mustNorm(t, mod(t, "exploit/android/browser/webview_addjavascriptinterface")).Events
	if len(evs) != 2 || evs[0].CVEID != "CVE-2012-6636" || evs[1].CVEID != "CVE-2013-4710" ||
		evs[0].OccurredAt != nil || evs[1].OccurredAt != nil {
		t.Errorf("%+v", evs)
	}
}

func TestTrailingSpaceReferenceIsStripped(t *testing.T) {
	evs := mustNorm(t, mod(t, "exploit/multi/http/uptime_file_upload_2")).Events
	if len(evs) != 1 || evs[0].CVEID != "CVE-2015-9263" {
		t.Fatalf("%+v", evs)
	}
	if _, ok := evs[0].Detail["dropped_cve_tokens"]; ok {
		t.Error("dropped_cve_tokens present")
	}
}

func TestInvalidCVERefs(t *testing.T) {
	p := mod(t, "auxiliary/admin/2wire/xslt_password_reset")
	mixed := p.Clone()
	mixed.Set("references", append(append([]any{}, p.Get("references").([]any)...), "CVE-2007-43", "cve-2008-0001"))
	evs := mustNorm(t, mixed).Events
	if len(evs) != 2 || evs[0].CVEID != "CVE-2007-4387" || evs[1].CVEID != "CVE-2008-0001" {
		t.Fatalf("%+v", evs)
	}
	if s, _ := pyjson.Canonical(evs[0].Detail["dropped_cve_tokens"]); s != `["CVE-2007-43"]` {
		t.Error(s)
	}
	bad := p.Clone()
	bad.Set("references", []any{"CVE-n/a", "URL-https://x"})
	if _, err := normalize(bad); !isNormErr(err, "auxiliary/admin/2wire/xslt_password_reset: no valid CVE id among ['CVE-n/a']") {
		t.Errorf("%v", err)
	}
	bad.Set("references", "CVE-2007-4387")
	if _, err := normalize(bad); !isNormErr(err, "auxiliary/admin/2wire/xslt_password_reset: references is not a list") {
		t.Errorf("%v", err)
	}
}

func TestOutOfScopeTypeRejectedByNormalize(t *testing.T) {
	if _, err := normalize(mod(t, "post/android/local/koffee")); !isNormErr(err, "post/android/local/koffee: out-of-scope type 'post'") {
		t.Errorf("%v", err)
	}
}

func TestParseScopeAndCounts(t *testing.T) {
	c, _ := metasploit.New(feed.Options{})
	items, extra, err := c.ParseItems(feedtest.Msf.Dump(t, feedtest.Msf.Load(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Key == "post/android/local/koffee" || len(it.Key) >= 8 && it.Key[:8] == "payload/" {
			t.Errorf("out of scope item %s", it.Key)
		}
	}
	if s, _ := pyjson.Canonical(extra); s != `{"malformed_skipped":0,"modules":8,"out_of_scope_types":2}` {
		t.Error(s)
	}
}

func TestRunSkipsNoCVEAndOutOfScope(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	srv := feedtest.NewServer(t, metasploit.FeedURL, feedtest.Msf.Dump(t, feedtest.Msf.Load(t)), `"v1"`)
	s := feedtest.Run(t, d, feedtest.New(t, feedtest.Msf, srv, 0), T0, false)
	if s.Fetched != 5 || s.RawNew != 5 || s.NormalizeErrors != 0 || s.EventInserted != 6 {
		t.Errorf("stats %+v", s)
	}
	for _, k := range feedtest.Strings(t, d, "SELECT source_key FROM raw_record") {
		if k == "exploit/android/adb/adb_server_exec" || k == "post/android/local/koffee" {
			t.Errorf("stored %s", k)
		}
	}
	lr := feedtest.Cursor(t, d).Get("last_run").(*pyjson.Object)
	if lr.Get("items_in_scope") != pyjson.Int("6") || lr.Get("items_with_cve") != pyjson.Int("5") || lr.Get("items_without_cve") != pyjson.Int("1") {
		t.Errorf("last_run %s", pyjson.Repr(lr))
	}
	if n := feedtest.Count(t, d, "SELECT count(*) FROM event WHERE occurred_at IS NOT NULL"); n != 0 {
		t.Errorf("%d events with occurred_at", n)
	}
}
