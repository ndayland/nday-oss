package pipeline_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var (
	T0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	T1 = T0.Add(time.Hour)
	T2 = T1.Add(time.Hour)
)

// fake is a scripted collector: payload {"cve": id, "v": version, "bad": true?}.
type fake struct {
	name      string
	records   []model.RawRecord
	cursor    any
	fetchErr  error
	gotState  model.CollectorState
	wantLimit int
	fatal     bool
}

func (f *fake) Name() string { return f.name }
func (f *fake) Fetch(_ context.Context, st model.CollectorState) (*model.FetchResult, error) {
	f.gotState = st
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return &model.FetchResult{Records: f.records, Cursor: f.cursor}, nil
}
func (f *fake) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p := rec.Payload.(*pyjson.Object)
	if p.Get("bad") == true {
		if f.fatal {
			return nil, errors.New("boom")
		}
		return nil, collector.NormalizeErrorf("bad record %s", pyjson.Repr(p.Get("cve")))
	}
	cve := p.Get("cve").(string)
	return &model.Normalized{Events: []model.Event{{CVEID: cve, Type: model.EventPocPublished, Source: f.name,
		Detail: map[string]any{"v": p.Get("v")}}}}, nil
}

type wanter struct{ *fake }

func (w wanter) WantedLimit() int { return w.wantLimit }

func rec(src, cve string, v int64, backfill bool) model.RawRecord {
	o := pyjson.NewObject()
	o.Set("cve", cve)
	o.Set("v", pyjson.IntOf(v))
	return model.RawRecord{Source: src, SourceKey: cve, Payload: o, IsBackfill: backfill}
}

func badRec(src, key string) model.RawRecord {
	o := pyjson.NewObject()
	o.Set("cve", key)
	o.Set("bad", true)
	return model.RawRecord{Source: src, SourceKey: key, Payload: o}
}

func run(t *testing.T, d *testutil.TestDB, c collector.Collector, now time.Time) (*pipeline.Stats, error) {
	return pipeline.RunCollector(context.Background(), d.Conn, c, pipeline.Options{Now: func() time.Time { return now }})
}

func TestMergeVulnStubVsAuthoritative(t *testing.T) {
	s := func(v string) *string { return &v }
	existing := pipeline.VulnRow{Title: s("Real title")}
	stub := model.VulnUpsert{CVEID: "CVE-2024-1234", Title: s("KEV title"), Description: s("KEV desc")}
	m := pipeline.MergeVuln(existing, stub)
	if *m.Title != "Real title" || *m.Description != "KEV desc" {
		t.Errorf("stub merge %+v", m)
	}
	auth := model.VulnUpsert{CVEID: "CVE-2024-1234", Title: s("CVE title"), Authoritative: true}
	if m := pipeline.MergeVuln(existing, auth); *m.Title != "CVE title" || m.Description != nil {
		t.Errorf("auth merge %+v", m)
	}
	// "" never erases, even authoritative; "" existing counts as empty for a stub.
	if m := pipeline.MergeVuln(pipeline.VulnRow{Title: s("x")}, model.VulnUpsert{Title: s(""), Authoritative: true}); *m.Title != "x" {
		t.Error("empty erased")
	}
	if m := pipeline.MergeVuln(pipeline.VulnRow{Title: s("")}, model.VulnUpsert{Title: s("y")}); *m.Title != "y" {
		t.Error("empty not filled")
	}
	tm := T0
	if !(pipeline.VulnRow{PublishedAt: &tm}).Equal(pipeline.VulnRow{PublishedAt: model.Ptr(T0.In(time.FixedZone("x", 3600)))}) {
		t.Error("time equality must be by instant")
	}
}

func TestWantedMechanismAndPerRecordBackfill(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, id := range []string{"CVE-2026-99999", "CVE-2026-100000", "CVE-2025-500000", "CVE-2026-1234", "CVE-2027-0001"} {
		if _, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id) VALUES ($1)", id); err != nil {
			t.Fatal(err)
		}
	}
	// "w" already has a raw record for CVE-2027-0001 (any content counts).
	if _, err := d.Conn.Exec(ctx, `INSERT INTO raw_record (source, source_key, content_hash, payload)
                                  VALUES ('w', 'CVE-2027-0001', 'h', '{}')`); err != nil {
		t.Fatal(err)
	}
	f := &fake{name: "w", wantLimit: 3}
	if _, err := run(t, d, wanter{f}, T0); err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-100000", "CVE-2026-99999", "CVE-2026-1234"}
	if strings.Join(f.gotState.Wanted, ",") != strings.Join(want, ",") {
		t.Errorf("wanted %v, want %v", f.gotState.Wanted, want)
	}
	// Collectors that do not opt in get nothing.
	plain := &fake{name: "p"}
	if _, err := run(t, d, plain, T0); err != nil || len(plain.gotState.Wanted) != 0 {
		t.Errorf("plain collector got wanted %v (%v)", plain.gotState.Wanted, err)
	}
	// Second (incremental) run: a record flagged IsBackfill is stored as backfill.
	f.records = []model.RawRecord{rec("w", "CVE-2026-99999", 1, true), rec("w", "CVE-2026-1234", 1, false)}
	st, err := run(t, d, wanter{f}, T1)
	if err != nil || st.IsBackfill || st.EventInserted != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	for id, wantBF := range map[string]bool{"CVE-2026-99999": true, "CVE-2026-1234": false} {
		var bf bool
		_ = d.Conn.QueryRow(ctx, "SELECT is_backfill FROM event WHERE cve_id = $1", id).Scan(&bf)
		if bf != wantBF {
			t.Errorf("%s is_backfill=%v want %v", id, bf, wantBF)
		}
	}
	// Wanted is recomputed: the fetched ids are no longer missing.
	if _, err := run(t, d, wanter{f}, T2); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.gotState.Wanted, ",") != "CVE-2026-100000,CVE-2025-500000" {
		t.Errorf("wanted after fetch %v", f.gotState.Wanted)
	}
}

func TestNormalizeErrorGivesPartialStatus(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := &fake{name: "n", cursor: map[string]any{"c": pyjson.IntOf(1)}}
	f.records = []model.RawRecord{rec("n", "CVE-2024-0001", 1, false)}
	for i := 0; i < 25; i++ {
		f.records = append(f.records, badRec("n", fmt.Sprintf("k%02d", i)))
	}
	st, err := run(t, d, f, T0)
	if err != nil || st.NormalizeErrors != 25 || st.RawNew != 26 || st.EventInserted != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	var status, lastErr, cur string
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status, last_error, cursor::text FROM collector_state").Scan(&status, &lastErr, &cur)
	if status != "partial" || cur != `{"c": 1}` {
		t.Errorf("status %s cursor %s", status, cur)
	}
	parts := strings.Split(lastErr, "; ")
	if len(parts) != 20 || parts[0] != "k00: bad record 'k00'" {
		t.Errorf("last_error %q", lastErr)
	}
}

func TestFatalErrorKeepsCursorAndRollsBack(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	f := &fake{name: "x", cursor: map[string]any{"c": pyjson.IntOf(1)}, records: []model.RawRecord{rec("x", "CVE-2024-0001", 1, false)}}
	if _, err := run(t, d, f, T0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mod  func(*fake)
	}{
		{"fetch error", func(f *fake) { f.fetchErr = errors.New("network down") }},
		{"non-NormalizeError from normalize", func(f *fake) {
			f.fatal = true
			f.records = []model.RawRecord{rec("x", "CVE-2024-0002", 1, false), badRec("x", "zz")}
		}},
		{"invalid event (Python ValueError in Event())", func(f *fake) {
			f.records = []model.RawRecord{rec("x", "CVE-24-1", 1, false)}
		}},
	}
	for _, c := range cases {
		g := &fake{name: "x", cursor: map[string]any{"c": pyjson.IntOf(2)}}
		c.mod(g)
		if _, err := run(t, d, g, T1); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
		var status, cur, lastErr string
		var okAt time.Time
		_ = d.Conn.QueryRow(ctx, "SELECT last_status, cursor::text, last_success_at, last_error FROM collector_state WHERE source='x'").Scan(&status, &cur, &okAt, &lastErr)
		if status != "error" || cur != `{"c": 1}` || !okAt.Equal(T0) || lastErr == "" {
			t.Errorf("%s: state %s %s %v %q", c.name, status, cur, okAt, lastErr)
		}
		var raws int
		_ = d.Conn.QueryRow(ctx, "SELECT count(*) FROM raw_record WHERE source='x'").Scan(&raws)
		if raws != 1 {
			t.Errorf("%s: transaction not rolled back (%d raw rows)", c.name, raws)
		}
	}
}

func TestRevertedVersionOnlyBumpsFetchedAt(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	f := &fake{name: "r"}
	for i, v := range []int64{1, 2, 1} {
		f.records = []model.RawRecord{rec("r", "CVE-2024-0001", v, false)}
		st, err := run(t, d, f, T0.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		wantNew := 1
		if i == 2 {
			wantNew = 0
		}
		if st.RawNew != wantNew || st.RawUnchanged != 0 {
			t.Errorf("run %d: %+v", i, st)
		}
		if i == 2 && st.EventUpdated != 1 {
			t.Errorf("reverted version must be re-normalized: %+v", st)
		}
	}
	var n int
	var fetched time.Time
	_ = d.Conn.QueryRow(ctx, `SELECT count(*), max(fetched_at) FILTER (WHERE payload->>'v' = '1') FROM raw_record`).Scan(&n, &fetched)
	if n != 2 || !fetched.Equal(T2) {
		t.Errorf("rows %d fetched %v", n, fetched)
	}
}
