package cvelist_test

import (
	"errors"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/registry"
	"nday.land/nday/internal/testutil"
)

const (
	TYPICAL  = "CVE-2026-108262" // GitHub_M: CNA title, CVSS 3.1, GHSA advisory, CISA-ADP SSVC
	NO_TITLE = "CVE-2026-125344" // Chrome: no CNA title, CVSS only in CISA-ADP
	V4       = "CVE-2026-116081" // CNA has CVSS 3.1 and 4.0
	NA       = "CVE-2026-117373" // affected vendor/product "n/a", no metrics
	REJECTED = "CVE-2026-107922" // REJECTED, no datePublished
	KEVREC   = "CVE-2026-111793" // CISA-ADP SSVC Exploitation=active + kev marker
)

var ALL = []string{TYPICAL, NO_TITLE, V4, NA, REJECTED, KEVREC}

// rec loads a fixture record (a fresh decode each call, so tests may mutate it).
func rec(t testing.TB, cve string) *pyjson.Object {
	t.Helper()
	v, err := pyjson.Decode(testutil.ReadFile(t, "tests/fixtures/cvelist/"+cve+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*pyjson.Object)
}

func obj(v any) *pyjson.Object { return v.(*pyjson.Object) }

func plain(t testing.TB) *cvelist.Collector {
	t.Helper()
	c, err := cvelist.New(cvelist.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func norm(t *testing.T, cve string, payload *pyjson.Object) *model.Normalized {
	t.Helper()
	if payload == nil {
		payload = rec(t, cve)
	}
	n, err := plain(t).Normalize(model.RawRecord{Source: "cvelist", SourceKey: cve, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func canon(t testing.TB, v any) string {
	t.Helper()
	s, err := pyjson.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ------------------------------------------------------------ golden parity

func TestGoldenParityWithPython(t *testing.T) {
	newC := func(ft *testutil.FakeTransport) collector.Collector {
		c, err := cvelist.New(cvelist.Options{Transport: ft})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, g := range []string{"fixture_records", "edge_records"} {
		t.Run(g, func(t *testing.T) {
			testutil.CheckGolden(t, "internal/collector/cvelist/testdata/golden/"+g+".golden.json", newC)
		})
	}
}

// ------------------------------------------------------------ pure normalize

func TestRegistered(t *testing.T) {
	f, ok := registry.Collectors["cvelist"]
	if !ok {
		t.Fatal("cvelist not registered")
	}
	c, err := f(collector.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*cvelist.Collector); !ok || c.Name() != "cvelist" {
		t.Errorf("registry builds %T", c)
	}
	for _, n := range registry.PythonOnly {
		if n == "cvelist" {
			t.Error("cvelist still listed as PythonOnly")
		}
	}
}

func TestDeltaLogFixtureShapeMatchesFake(t *testing.T) {
	v, err := pyjson.Decode(testutil.ReadFile(t, "tests/fixtures/cvelist/deltaLog_excerpt.json"))
	if err != nil {
		t.Fatal(err)
	}
	real0 := obj(v.([]any)[0])
	fake := changeSet("2026-11-12T00:00:00.000Z", []string{TYPICAL}, nil)
	if canon(t, real0.Keys()) != canon(t, []any{"fetchTime", "numberOfChanges", "new", "updated", "error"}) ||
		canon(t, real0.Keys()) != canon(t, fake.Keys()) {
		t.Errorf("keys %v / %v", real0.Keys(), fake.Keys())
	}
	rn := obj(real0.Get("new").([]any)[0])
	fn := obj(fake.Get("new").([]any)[0])
	if canon(t, rn.Keys()) != canon(t, fn.Keys()) {
		t.Errorf("item keys %v / %v", rn.Keys(), fn.Keys())
	}
	if rn.Get("githubLink") != cvelist.RecordURL(rn.Get("cveId").(string)) {
		t.Errorf("githubLink %v", rn.Get("githubLink"))
	}
}

func TestNormalizeTypicalPublished(t *testing.T) {
	p := rec(t, TYPICAL)
	n := norm(t, TYPICAL, nil)
	if len(n.Vulns) != 1 {
		t.Fatal(n.Vulns)
	}
	v := n.Vulns[0]
	c := obj(obj(p.Get("containers")).Get("cna"))
	if !v.Authoritative || *v.Title != c.Get("title") ||
		*v.Description != obj(c.Get("descriptions").([]any)[0]).Get("value") {
		t.Errorf("vuln %+v", v)
	}
	if !v.PublishedAt.Equal(ts("2026-11-06T18:29:49.225+00:00")) ||
		!v.ModifiedAt.Equal(ts(obj(p.Get("cveMetadata")).Get("dateUpdated").(string))) {
		t.Errorf("dates %v %v", v.PublishedAt, v.ModifiedAt)
	}
	adv := obj(c.Get("source")).Get("advisory").(string)
	if len(n.Aliases) != 1 || n.Aliases[0] != (model.Alias{CVEID: TYPICAL, Alias: adv, AliasType: "ghsa"}) || adv[:5] != "GHSA-" {
		t.Errorf("aliases %+v", n.Aliases)
	}
	var want []model.Affected
	for _, a := range c.Get("affected").([]any) {
		want = append(want, model.Affected{CVEID: TYPICAL, Vendor: obj(a).Get("vendor").(string), Product: obj(a).Get("product").(string)})
	}
	if len(want) != len(n.Affected) {
		t.Fatalf("affected %+v", n.Affected)
	}
	for i := range want {
		if want[i] != n.Affected[i] {
			t.Errorf("affected[%d] %+v", i, n.Affected[i])
		}
	}
	if len(n.Events) != 1 {
		t.Fatal(n.Events)
	}
	e := n.Events[0]
	if e.Type != "disclosed" || e.Source != "cvelist" || e.DedupeKey != "" || !e.OccurredAt.Equal(*v.PublishedAt) ||
		*e.URL != "https://www.cve.org/CVERecord?id="+TYPICAL {
		t.Errorf("event %+v", e)
	}
	cv := e.Detail["cvss"].(map[string]any)
	ex := e.Detail["ssvc"].(map[string]any)["exploitation"]
	if e.Detail["state"] != "PUBLISHED" || e.Detail["assigner_short_name"] != "GitHub_M" || cv["source"] != "cna" ||
		cv["version"] != "3.1" || (ex != "none" && ex != "poc" && ex != "active") {
		t.Errorf("detail %v", e.Detail)
	}
}

func TestNormalizeNoCNATitleUsesADPCVSS(t *testing.T) {
	p := rec(t, NO_TITLE)
	cnaObj := obj(obj(p.Get("containers")).Get("cna"))
	if _, ok := cnaObj.Lookup("title"); ok {
		t.Fatal("fixture has a title")
	}
	n := norm(t, NO_TITLE, nil)
	if n.Vulns[0].Title != nil || n.Vulns[0].Description == nil {
		t.Errorf("vuln %+v", n.Vulns[0])
	}
	var metric *pyjson.Object
	for _, a := range obj(p.Get("containers")).Get("adp").([]any) {
		ms, _ := obj(a).Get("metrics").([]any)
		for _, m := range ms {
			if x, ok := obj(m).Lookup("cvssV3_1"); ok && metric == nil {
				metric = obj(x)
			}
		}
	}
	want := map[string]any{"version": "3.1", "base_score": metric.Get("baseScore"), "base_severity": metric.Get("baseSeverity"),
		"vector": metric.Get("vectorString"), "source": "adp:CISA-ADP"}
	if canon(t, n.Events[0].Detail["cvss"]) != canon(t, want) {
		t.Errorf("cvss %v", n.Events[0].Detail["cvss"])
	}
	if len(n.Aliases) != 0 {
		t.Error("aliases")
	}
}

func TestCVSSPrefersNewestVersionInCNA(t *testing.T) {
	p := rec(t, V4)
	n := norm(t, V4, nil)
	cv := n.Events[0].Detail["cvss"].(map[string]any)
	var v4 *pyjson.Object
	metrics := obj(obj(p.Get("containers")).Get("cna")).Get("metrics").([]any)
	for _, m := range metrics {
		if x, ok := obj(m).Lookup("cvssV4_0"); ok {
			v4 = obj(x)
		}
	}
	if cv["version"] != "4.0" || cv["source"] != "cna" || cv["base_score"] != v4.Get("baseScore") || cv["vector"] != v4.Get("vectorString") {
		t.Errorf("cvss %v", cv)
	}
	// extract_cvss({"cna": {}}) is None: a record whose CNA has no metrics and no ADP
	q := rec(t, V4)
	obj(obj(q.Get("containers")).Get("cna")).Set("metrics", []any{})
	c := obj(q.Get("containers"))
	c.Set("adp", []any{})
	if _, ok := norm(t, V4, q).Events[0].Detail["cvss"]; ok {
		t.Error("cvss without metrics")
	}
	if _, ok := norm(t, NA, nil).Events[0].Detail["cvss"]; ok {
		t.Error("NA has cvss")
	}
}

func TestAffectedSkipsNA(t *testing.T) {
	p := rec(t, NA)
	found := false
	for _, a := range obj(obj(p.Get("containers")).Get("cna")).Get("affected").([]any) {
		if obj(a).Get("vendor") == "n/a" || obj(a).Get("product") == "n/a" {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture has no n/a")
	}
	if a := norm(t, NA, nil).Affected; len(a) != 0 {
		t.Errorf("affected %+v", a)
	}
}

func TestNormalizeRejected(t *testing.T) {
	n := norm(t, REJECTED, nil)
	v := n.Vulns[0]
	if len(n.Vulns) != 1 || v.Title != nil || v.Description != nil || v.PublishedAt != nil ||
		!v.ModifiedAt.Equal(ts("2026-11-11T22:18:59.410+00:00")) {
		t.Errorf("vuln %+v", v)
	}
	if len(n.Affected)+len(n.Aliases) != 0 || len(n.Events) != 1 {
		t.Fatal("rows")
	}
	e := n.Events[0]
	_, hasCVSS := e.Detail["cvss"]
	if e.OccurredAt != nil || e.Detail["state"] != "REJECTED" || e.Detail["date_rejected"] != "2026-11-11T22:18:59.410Z" ||
		len(e.Detail["rejected_reasons"].([]any)) == 0 || hasCVSS {
		t.Errorf("event %+v", e)
	}
}

func TestNormalizeReservedEmitsNothing(t *testing.T) {
	p := rec(t, NA)
	obj(p.Get("cveMetadata")).Set("state", "RESERVED")
	n := norm(t, NA, p)
	if len(n.Vulns)+len(n.Events)+len(n.Affected)+len(n.Aliases) != 0 {
		t.Errorf("%+v", n)
	}
}

func TestADPKevAndSSVCGoToDetailOnly(t *testing.T) {
	n := norm(t, KEVREC, nil)
	if len(n.Events) != 1 || n.Events[0].Type != "disclosed" {
		t.Fatalf("events %+v", n.Events)
	}
	d := n.Events[0].Detail
	if d["ssvc"].(map[string]any)["exploitation"] != "active" || d["kev"].(map[string]any)["date_added"] != "2026-11-10" {
		t.Errorf("detail %v", d)
	}
}

func TestNormalizeMalformed(t *testing.T) {
	for name, mutate := range map[string]func(p *pyjson.Object){
		"pop cveMetadata": func(p *pyjson.Object) {
			q := pyjson.NewObject()
			for _, k := range p.Keys() {
				if k != "cveMetadata" {
					q.Set(k, p.Get(k))
				}
			}
			*p = *q
		},
		"dataType X":  func(p *pyjson.Object) { p.Set("dataType", "X") },
		"bad cveId":   func(p *pyjson.Object) { obj(p.Get("cveMetadata")).Set("cveId", "CVE-26-1") },
		"state WEIRD": func(p *pyjson.Object) { obj(p.Get("cveMetadata")).Set("state", "WEIRD") },
		"pop cna":     func(p *pyjson.Object) { p.Set("containers", pyjson.NewObject()) },
	} {
		p := rec(t, TYPICAL)
		mutate(p)
		_, err := plain(t).Normalize(model.RawRecord{Source: "cvelist", SourceKey: TYPICAL, Payload: p})
		var ne *collector.NormalizeError
		if !errors.As(err, &ne) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNormalizeRejectsKeyMismatch(t *testing.T) {
	_, err := plain(t).Normalize(model.RawRecord{Source: "cvelist", SourceKey: NA, Payload: rec(t, TYPICAL)})
	var ne *collector.NormalizeError
	if !errors.As(err, &ne) {
		t.Errorf("got %v", err)
	}
}

func TestBackfillFlagDoesNotTouchContentHash(t *testing.T) {
	p := rec(t, NA)
	a, _ := model.RawRecord{Source: "cvelist", SourceKey: NA, Payload: p}.ContentHash()
	b, _ := model.RawRecord{Source: "cvelist", SourceKey: NA, Payload: p, IsBackfill: true}.ContentHash()
	if a != b || a == "" {
		t.Error("hash differs")
	}
}

func TestSettingsFromEnv(t *testing.T) {
	env := func(m map[string]string) collector.Env {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	c, err := cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_BOOTSTRAP_DAYS": "3", "NDAY_CVELIST_MAX_FILES": "50"})})
	if err != nil || c.BootstrapDays != 3 || c.MaxFiles != 50 {
		t.Fatalf("%v %+v", err, c)
	}
	_, err = cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_BOOTSTRAP_DAYS": "31"})})
	if err == nil || err.Error() != "bootstrap_days must be 0..30, got 31" {
		t.Errorf("31: %v", err)
	}
	// from test_cvelist_backfill.py::test_retry_days_from_env
	c, err = cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_BACKFILL_RETRY_DAYS": "3", "NDAY_CVELIST_MAX_FILES": "50"})})
	if err != nil || c.WantedLimit() != 50+cvelist.MaxBackfillMissing {
		t.Fatalf("%v", err)
	}
	_, err = cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_BACKFILL_RETRY_DAYS": "-1"})})
	if err == nil || err.Error() != "backfill_retry_days must be >= 0, got -1" {
		t.Errorf("-1: %v", err)
	}
	// env_int details (Python int(): whitespace, sign, underscores, Unicode digits)
	for raw, want := range map[string]string{
		" 12 ": "12", "+5": "5", "1_0": "10", "２": "2", "": "7", "   ": "7",
	} {
		c, err := cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_BOOTSTRAP_DAYS": raw})})
		if err != nil || pyjson.IntOf(int64(c.BootstrapDays)) != pyjson.Int(want) {
			t.Errorf("%q: %v %v", raw, err, c)
		}
	}
	for raw, msg := range map[string]string{
		"x":    "NDAY_CVELIST_MAX_FILES must be an integer, got 'x'",
		"1__0": "NDAY_CVELIST_MAX_FILES must be an integer, got '1__0'",
		"_1":   "NDAY_CVELIST_MAX_FILES must be an integer, got '_1'",
		"1.0":  "NDAY_CVELIST_MAX_FILES must be an integer, got '1.0'",
		"0":    "max_files must be >= 1, got 0",
	} {
		_, err := cvelist.New(cvelist.Options{Env: env(map[string]string{"NDAY_CVELIST_MAX_FILES": raw})})
		if err == nil || err.Error() != msg {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
