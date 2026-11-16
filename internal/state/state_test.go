package state_test

// Port of tests/test_state.py.

import (
	"context"
	"testing"
	"time"

	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
)

var NOW = time.Now().UTC().Truncate(time.Microsecond)

func d(daysAgo float64) time.Time { return NOW.Add(-time.Duration(daysAgo * float64(24*time.Hour))) }

type db struct {
	t *testing.T
	*testutil.TestDB
}

func newDB(t *testing.T) db { t.Parallel(); return db{t, testutil.NewMigratedDB(t)} }

func (x db) vuln(cve string, title ...string) {
	tl := "t"
	if len(title) > 0 {
		tl = title[0]
	}
	if _, err := x.Conn.Exec(context.Background(), "INSERT INTO vuln (cve_id, title) VALUES ($1, $2)", cve, tl); err != nil {
		x.t.Fatal(err)
	}
}

type evOpt struct {
	occ      *time.Time
	obs      *time.Time
	backfill bool
	source   string
	detail   string
	key      string
}

func (x db) ev(cve, typ string, o evOpt) {
	if o.source == "" {
		o.source = "x"
	}
	if o.detail == "" {
		o.detail = "{}"
	}
	obs := NOW
	if o.obs != nil {
		obs = *o.obs
	}
	if _, err := x.Conn.Exec(context.Background(), `INSERT INTO event (cve_id, type, occurred_at, observed_at, is_backfill, source,
                              detail, dedupe_key)
           VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, cve, typ, o.occ, obs, o.backfill, o.source, o.detail, o.key); err != nil {
		x.t.Fatal(err)
	}
}

func p(t time.Time) *time.Time { return &t }

// refresh materializes the state (Hot and StageCounts read vuln_state_mat).
func (x db) refresh() {
	if _, err := state.Refresh(context.Background(), x.Conn, state.RefreshOptions{Wait: true}); err != nil {
		x.t.Fatal(err)
	}
}

type row struct {
	stage                           string
	rank                            int
	hasPatch, hasAnalysis, hasPoc   bool
	exploited, inKev, isRejected    bool
	disclosedAt, exploitedAt, kevAt *time.Time
	pocAt, lastAt                   *time.Time
	lastType                        *string
	eventCount                      int
	dExp, dPoc                      *float64
}

func (x db) row(cve string) *row {
	var r row
	err := x.Conn.QueryRow(context.Background(), `SELECT stage, stage_rank, has_patch, has_analysis, has_poc, exploited, in_kev,
        is_rejected, disclosed_at, exploited_at, kev_at, poc_at, last_transition_at, last_transition_type, event_count,
        days_disclosed_to_exploited::float8, days_disclosed_to_poc::float8 FROM vuln_state WHERE cve_id = $1`, cve).
		Scan(&r.stage, &r.rank, &r.hasPatch, &r.hasAnalysis, &r.hasPoc, &r.exploited, &r.inKev, &r.isRejected,
			&r.disclosedAt, &r.exploitedAt, &r.kevAt, &r.pocAt, &r.lastAt, &r.lastType, &r.eventCount, &r.dExp, &r.dPoc)
	if err != nil {
		return nil
	}
	return &r
}

func eq(a *time.Time, b time.Time) bool { return a != nil && a.Equal(b) }

func TestStageRanking(t *testing.T) {
	x := newDB(t)
	types := []string{"disclosed", "patch_released", "analysis_published", "poc_published", "exploited_in_wild", "kev_added"}
	for i, typ := range types {
		cve := "CVE-2024-" + string(rune('0'+1)) + "00" + string(rune('0'+i+1))
		x.vuln(cve)
		x.ev(cve, typ, evOpt{occ: p(d(5))})
		if r := x.row(cve); r.stage != typ || r.rank != i+1 {
			t.Errorf("%s: %s/%d", typ, r.stage, r.rank)
		}
	}
	x.vuln("CVE-2024-2000")
	x.ev("CVE-2024-2000", "poc_published", evOpt{occ: p(d(1))})
	x.ev("CVE-2024-2000", "patch_released", evOpt{occ: p(d(9))})
	r := x.row("CVE-2024-2000")
	if r.stage != "poc_published" || !r.hasPoc || !r.hasPatch || r.hasAnalysis || r.exploited || r.inKev || r.eventCount != 2 {
		t.Errorf("%+v", r)
	}
}

func TestEffectiveAtRule(t *testing.T) {
	x := newDB(t)
	for _, c := range []string{"CVE-2024-3001", "CVE-2024-3002", "CVE-2024-3003"} {
		x.vuln(c)
	}
	x.ev("CVE-2024-3001", "disclosed", evOpt{occ: p(d(10)), obs: p(d(1)), backfill: true})
	x.ev("CVE-2024-3002", "disclosed", evOpt{obs: p(d(2))})
	x.ev("CVE-2024-3003", "disclosed", evOpt{obs: p(d(3)), backfill: true})
	if !eq(x.row("CVE-2024-3001").disclosedAt, d(10)) || !eq(x.row("CVE-2024-3002").disclosedAt, d(2)) {
		t.Error("effective_at")
	}
	r := x.row("CVE-2024-3003")
	if r.disclosedAt != nil || r.lastAt != nil || r.stage != "disclosed" {
		t.Errorf("%+v", r)
	}
}

func TestExploitedViaKevOnly(t *testing.T) {
	x := newDB(t)
	x.vuln("CVE-2024-4001")
	x.ev("CVE-2024-4001", "kev_added", evOpt{occ: p(d(2)), source: "kev"})
	r := x.row("CVE-2024-4001")
	if !r.exploited || !r.inKev || r.stage != "kev_added" || !eq(r.exploitedAt, d(2)) || !eq(r.kevAt, d(2)) {
		t.Errorf("%+v", r)
	}
}

func TestIsRejectedUsesLatestCvelistEvent(t *testing.T) {
	x := newDB(t)
	for _, c := range []string{"CVE-2024-5001", "CVE-2024-5002", "CVE-2024-5003"} {
		x.vuln(c)
	}
	x.ev("CVE-2024-5001", "disclosed", evOpt{occ: p(d(3)), source: "cvelist", detail: `{"state":"REJECTED"}`})
	x.ev("CVE-2024-5002", "disclosed", evOpt{occ: p(d(5)), source: "cvelist", detail: `{"state":"REJECTED"}`, key: "a"})
	x.ev("CVE-2024-5002", "disclosed", evOpt{occ: p(d(1)), source: "cvelist", detail: `{"state":"PUBLISHED"}`, key: "b"})
	x.ev("CVE-2024-5003", "disclosed", evOpt{occ: p(d(3)), source: "other"})
	if !x.row("CVE-2024-5001").isRejected || x.row("CVE-2024-5002").isRejected || x.row("CVE-2024-5003").isRejected {
		t.Error("is_rejected")
	}
}

func TestLastTransitionIgnoresRepeatSameType(t *testing.T) {
	x := newDB(t)
	x.vuln("CVE-2024-6001")
	x.ev("CVE-2024-6001", "disclosed", evOpt{occ: p(d(10))})
	x.ev("CVE-2024-6001", "poc_published", evOpt{occ: p(d(5)), source: "a"})
	x.ev("CVE-2024-6001", "poc_published", evOpt{occ: p(d(1)), source: "b"})
	r := x.row("CVE-2024-6001")
	if *r.lastType != "poc_published" || !eq(r.lastAt, d(5)) || !eq(r.pocAt, d(5)) {
		t.Errorf("%+v", r)
	}
}

func TestLastTransitionTieBreaksByRank(t *testing.T) {
	x := newDB(t)
	x.vuln("CVE-2024-7001")
	tt := d(2)
	for _, typ := range []string{"poc_published", "patch_released", "analysis_published"} {
		x.ev("CVE-2024-7001", typ, evOpt{occ: &tt})
	}
	r := x.row("CVE-2024-7001")
	if !eq(r.lastAt, tt) || *r.lastType != "poc_published" {
		t.Errorf("%+v", r)
	}
}

func TestDaysBetween(t *testing.T) {
	x := newDB(t)
	for _, c := range []string{"CVE-2024-8001", "CVE-2024-8002", "CVE-2024-8003", "CVE-2024-8004"} {
		x.vuln(c)
	}
	base := time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC)
	x.ev("CVE-2024-8001", "disclosed", evOpt{occ: p(base)})
	x.ev("CVE-2024-8001", "exploited_in_wild", evOpt{occ: p(base.Add(72 * time.Hour))})
	x.ev("CVE-2024-8001", "poc_published", evOpt{occ: p(base.Add(36 * time.Hour))})
	x.ev("CVE-2024-8002", "disclosed", evOpt{occ: p(base)})
	x.ev("CVE-2024-8002", "kev_added", evOpt{occ: p(base.Add(-96 * time.Hour))})
	x.ev("CVE-2024-8003", "disclosed", evOpt{obs: p(base), backfill: true})
	x.ev("CVE-2024-8003", "kev_added", evOpt{occ: p(base)})
	x.ev("CVE-2024-8004", "disclosed", evOpt{occ: p(base)})
	r := x.row("CVE-2024-8001")
	if *r.dExp != 3.0 || *r.dPoc != 1.5 || *x.row("CVE-2024-8002").dExp != -4.0 {
		t.Errorf("%v %v", *r.dExp, *r.dPoc)
	}
	if x.row("CVE-2024-8003").dExp != nil {
		t.Error("8003")
	}
	if r := x.row("CVE-2024-8004"); r.dExp != nil || r.dPoc != nil {
		t.Error("8004")
	}
}

func TestVulnWithoutEventsAbsent(t *testing.T) {
	x := newDB(t)
	x.vuln("CVE-2024-9001")
	if x.row("CVE-2024-9001") != nil {
		t.Error("present")
	}
}

func ids(t *testing.T) func([]state.HotRow, error) string {
	return func(rows []state.HotRow, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		s := ""
		for _, r := range rows {
			s += r.CVEID + ","
		}
		return s
	}
}

func TestHotWindowOrderAndRejected(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	x.vuln("CVE-2024-1101", "old")
	x.ev("CVE-2024-1101", "disclosed", evOpt{occ: p(d(30))})
	x.vuln("CVE-2024-1102", "mid")
	x.ev("CVE-2024-1102", "disclosed", evOpt{occ: p(d(3))})
	x.vuln("CVE-2024-1103", "new")
	x.ev("CVE-2024-1103", "disclosed", evOpt{occ: p(d(5))})
	x.ev("CVE-2024-1103", "kev_added", evOpt{occ: p(d(1))})
	x.vuln("CVE-2024-1104", "rejected")
	x.ev("CVE-2024-1104", "disclosed", evOpt{occ: p(d(0.5)), source: "cvelist", detail: `{"state":"REJECTED"}`})
	x.vuln("CVE-2024-1105", "unknown time")
	x.ev("CVE-2024-1105", "disclosed", evOpt{obs: p(d(1)), backfill: true})
	x.refresh()

	week := 7 * 24 * time.Hour
	if got := ids(t)(state.Hot(ctx, x.Conn, week, 10, false, "disclosed")); got != "CVE-2024-1103,CVE-2024-1102," {
		t.Errorf("hot %s", got)
	}
	if got := ids(t)(state.Hot(ctx, x.Conn, week, 10, true, "disclosed")); got != "CVE-2024-1104,CVE-2024-1103,CVE-2024-1102," {
		t.Errorf("hot incl rejected %s", got)
	}
	if got := ids(t)(state.Hot(ctx, x.Conn, week, 1, false, "disclosed")); got != "CVE-2024-1103," {
		t.Errorf("hot limit %s", got)
	}
	top, _ := state.Hot(ctx, x.Conn, week, 10, false, "disclosed")
	if *top[0].Title != "new" || top[0].LastTransitionType != "kev_added" {
		t.Errorf("%+v", top[0])
	}
	if got := ids(t)(state.Hot(ctx, x.Conn, week, 10, false, "patch_released")); got != "CVE-2024-1103," {
		t.Errorf("min_stage %s", got)
	}
	if got := ids(t)(state.Hot(ctx, x.Conn, week, 10, false, "kev_added")); got != "CVE-2024-1103," {
		t.Errorf("min_stage kev %s", got)
	}
}

func TestStageCounts(t *testing.T) {
	x := newDB(t)
	x.vuln("CVE-2024-1201")
	x.vuln("CVE-2024-1202")
	x.ev("CVE-2024-1201", "disclosed", evOpt{occ: p(d(1))})
	x.ev("CVE-2024-1202", "disclosed", evOpt{occ: p(d(1))})
	x.ev("CVE-2024-1202", "kev_added", evOpt{occ: p(d(1))})
	x.refresh()
	got, err := state.StageCounts(context.Background(), x.Conn)
	if err != nil || len(got) != 2 || got[0] != (state.StageCount{Stage: "disclosed", N: 1}) || got[1] != (state.StageCount{Stage: "kev_added", N: 1}) {
		t.Errorf("%v %v", got, err)
	}
}
