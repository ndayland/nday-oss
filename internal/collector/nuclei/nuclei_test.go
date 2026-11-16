package nuclei_test

// Port of tests/test_nuclei.py.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/feed/feedtest"
	"nday.land/nday/internal/collector/nuclei"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var T0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func objs(t *testing.T) []any { return feedtest.Nuclei.Load(t).([]any) }

func obj(t *testing.T, id string) *pyjson.Object {
	t.Helper()
	for _, o := range objs(t) {
		if o.(*pyjson.Object).Get("ID") == id {
			return o.(*pyjson.Object)
		}
	}
	t.Fatalf("no %s", id)
	return nil
}

func normalize(p *pyjson.Object, key string) (*model.Normalized, error) {
	c, _ := nuclei.New(feed.Options{})
	if key == "" {
		key, _ = p.Get("ID").(string)
	}
	return c.Normalize(model.RawRecord{Source: "nuclei", SourceKey: key, Payload: p})
}

func isNormErr(err error, msg string) bool {
	var ne *collector.NormalizeError
	return errors.As(err, &ne) && ne.Msg == msg
}

func TestNormalizeTypicalTemplateOccurredAtNone(t *testing.T) {
	p := obj(t, "CVE-2021-44228")
	norm, err := normalize(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(norm.Vulns)+len(norm.Aliases)+len(norm.Affected) != 0 || len(norm.Events) != 1 {
		t.Fatalf("%+v", norm)
	}
	ev := norm.Events[0]
	if ev.CVEID != "CVE-2021-44228" || ev.Type != "poc_published" || ev.Source != "nuclei" || ev.DedupeKey != "CVE-2021-44228" {
		t.Errorf("%+v", ev)
	}
	if ev.OccurredAt != nil { // the index has no timestamps at all
		t.Error("occurred_at set")
	}
	if *ev.URL != "https://github.com/projectdiscovery/nuclei-templates/blob/main/"+p.Get("file_path").(string) {
		t.Error(*ev.URL)
	}
	info := p.Get("Info").(*pyjson.Object)
	d := ev.Detail
	if d["kind"] != "detection_template" || d["confidence"] != "curated" || d["url"] != *ev.URL ||
		d["title"] != info.Get("Name") || d["severity"] != "critical" || d["template_path"] != p.Get("file_path") ||
		d["cvss_score"] != info.Get("Classification").(*pyjson.Object).Get("CVSSScore") {
		t.Errorf("detail %v", d)
	}
}

func TestOneCVEPerTemplate(t *testing.T) {
	norm, err := normalize(obj(t, "CVE-2026-9198"), "")
	if err != nil || len(norm.Events) != 1 {
		t.Fatalf("%v %v", norm, err)
	}
}

func TestLowercaseIDNormalised(t *testing.T) {
	p := obj(t, "CVE-2026-9198").Clone()
	p.Set("ID", "cve-2026-9198")
	norm, err := normalize(p, "")
	if err != nil || norm.Events[0].CVEID != "CVE-2026-9198" {
		t.Fatalf("%v %v", norm, err)
	}
}

func TestInvalidOrMalformedTemplateIsNormalizeError(t *testing.T) {
	p := obj(t, "CVE-2026-9198")
	bad := p.Clone()
	bad.Set("ID", "CVE-2026-91")
	if _, err := normalize(bad, ""); !isNormErr(err, "CVE-2026-91: no valid CVE id among ['CVE-2026-91']") {
		t.Errorf("%v", err)
	}
	noPath := pyjson.NewObject()
	for _, k := range p.Keys() {
		if k != "file_path" {
			noPath.Set(k, p.Get(k))
		}
	}
	if _, err := normalize(noPath, ""); !isNormErr(err, "CVE-2026-9198: missing Info or file_path") {
		t.Errorf("%v", err)
	}
	if _, err := normalize(p, "CVE-2000-0114"); !isNormErr(err, "ID 'CVE-2026-9198' != source_key CVE-2000-0114") {
		t.Errorf("%v", err)
	}
}

func TestRunSkipsNonCVETemplateAndCountsIt(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	all := objs(t)
	extra := all[0].(*pyjson.Object).Clone()
	extra.Set("ID", "tech-detect-thing")
	extra.Set("file_path", "http/technologies/x.yaml")
	srv := feedtest.NewServer(t, nuclei.FeedURL, feedtest.Nuclei.Dump(t, append(all, extra)), `"v1"`)
	s := feedtest.Run(t, d, feedtest.New(t, feedtest.Nuclei, srv, 0), T0, false)
	if s.Fetched != 4 || s.RawNew != 4 || s.NormalizeErrors != 0 || s.EventInserted != 4 {
		t.Errorf("stats %+v", s)
	}
	if n := feedtest.Count(t, d, "SELECT count(*) FROM raw_record WHERE source_key = 'tech-detect-thing'"); n != 0 {
		t.Error("non-CVE template stored")
	}
	lr := feedtest.Cursor(t, d).Get("last_run").(*pyjson.Object)
	if lr.Get("lines") != pyjson.Int("5") || lr.Get("items_with_cve") != pyjson.Int("4") || lr.Get("items_without_cve") != pyjson.Int("1") {
		t.Errorf("last_run %s", pyjson.Repr(lr))
	}
	if got, _ := pyjson.Canonical(feedtest.Cursor(t, d)); got != feedtest.PyCursors["nuclei/non_cve"] {
		t.Errorf("cursor vs Python\n got  %s\n want %s", got, feedtest.PyCursors["nuclei/non_cve"])
	}
}

func TestNulCharacterIsStoredAsLiteralEscape(t *testing.T) {
	// live: CVE-2021-32030's Description contains "\u0000" (PostgreSQL rejects NUL)
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	all := objs(t)
	first := all[0].(*pyjson.Object)
	first.Get("Info").(*pyjson.Object).Set("Description", "value of '\x00' bypasses auth")
	srv := feedtest.NewServer(t, nuclei.FeedURL, feedtest.Nuclei.Dump(t, all), `"v1"`)
	s := feedtest.Run(t, d, feedtest.New(t, feedtest.Nuclei, srv, 0), T0, false)
	if s.RawNew != 4 {
		t.Errorf("stats %+v", s)
	}
	desc := feedtest.Strings(t, d, "SELECT payload->'Info'->>'Description' FROM raw_record WHERE source_key = $1", first.Get("ID"))
	if len(desc) != 1 || desc[0] != `value of '\u0000' bypasses auth` {
		t.Errorf("%q", desc)
	}
	lr := feedtest.Cursor(t, d).Get("last_run").(*pyjson.Object)
	if s, _ := pyjson.Canonical(lr.Get("items_nul_scrubbed")); s != `["`+first.Get("ID").(string)+`"]` {
		t.Error(s)
	}
	if got, _ := pyjson.Canonical(feedtest.Cursor(t, d)); got != feedtest.PyCursors["nuclei/nul"] {
		t.Errorf("cursor vs Python\n got  %s\n want %s", got, feedtest.PyCursors["nuclei/nul"])
	}
}

func TestBrokenLineFailsTheFeed(t *testing.T) {
	c, _ := nuclei.New(feed.Options{})
	if _, _, err := c.ParseItems([]byte("{\"ID\":\"CVE-2020-1234\"\n")); err == nil {
		t.Fatal("broken line accepted")
	}
	// Python splitlines() also splits on U+2028 / \x85 / \x1c..\x1e: an
	// unescaped U+2028 inside a JSON string breaks the line -> run fails.
	if _, _, err := c.ParseItems([]byte("{\"ID\":\"CVE-2020-1234\",\"x\":\"a\u2028b\"}\n")); err == nil {
		t.Fatal("U+2028 split not reproduced")
	}
	// json.loads(str) rejects a leading BOM (body.decode("utf-8") keeps it).
	if _, _, err := c.ParseItems([]byte("\xef\xbb\xbf{\"ID\":\"CVE-2020-1234\"}\n")); err == nil || !strings.Contains(err.Error(), "BOM") {
		t.Fatalf("BOM: %v", err)
	}
}
