package stats

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func day(s string) time.Time { t, _ := ParseDay(s); return t }

func TestReader(t *testing.T) {
	d := newDB(t)
	dir := copyDir(t, "testdata/golden")
	runRollup(t, d.Conn, opts(dir))
	ctx := context.Background()
	r := NewReader(SingleConn(d.Conn))

	// Series fills the days without rows with zeros.
	pts, err := r.Series(ctx, "pv", "all", day("2026-11-10"), day("2026-11-14"))
	if err != nil {
		t.Fatal(err)
	}
	var vals []int64
	for i, p := range pts {
		if !p.Day.Equal(day("2026-11-10").AddDate(0, 0, i)) {
			t.Errorf("point %d day %v", i, p.Day)
		}
		vals = append(vals, p.Value)
	}
	if !reflect.DeepEqual(vals, []int64{0, 0, 4, 20, 0}) {
		t.Errorf("series %v", vals)
	}
	// a time of day and zone are ignored
	pts, err = r.Series(ctx, "pv_page", "human:vuln", time.Date(2026, 11, 13, 23, 0, 0, 0, sgt), day("2026-11-13"))
	if err != nil || len(pts) != 1 || pts[0].Value != 2 {
		t.Errorf("one-day series %v %v", pts, err)
	}
	if _, err := r.Series(ctx, "pv", "all", day("2026-11-14"), day("2026-11-13")); !errors.Is(err, ErrRange) {
		t.Errorf("reversed range: %v", err)
	}
	if _, err := r.Series(ctx, "pv", "all", day("2000-01-01"), day("2026-11-13")); !errors.Is(err, ErrRange) {
		t.Errorf("huge range: %v", err)
	}

	// Top sums over the range.
	top, err := r.Top(ctx, TopVulnPage, day("2026-11-01"), day("2026-11-30"), 10)
	if err != nil || !reflect.DeepEqual(top, []TopEntry{{"CVE-2024-3094", 4}}) {
		t.Errorf("top %v %v", top, err)
	}
	top, err = r.Top(ctx, TopCountry, day("2026-11-12"), day("2026-11-13"), 2)
	if err != nil || !reflect.DeepEqual(top, []TopEntry{{"JP", 12}, {"SG", 7}}) {
		t.Errorf("top countries %v %v", top, err)
	}
	if top, err := r.Top(ctx, "nope", day("2026-11-12"), day("2026-11-13"), 5); err != nil || len(top) != 0 {
		t.Errorf("unknown kind %v %v", top, err)
	}

	days, err := r.Days(ctx)
	if err != nil || len(days) != 2 || !days[0].Day.Equal(day("2026-11-12")) || days[1].Lines != 58 ||
		days[1].BadLines != 5 || days[1].RolledAt == nil || days[1].Files != 1 {
		t.Errorf("days %+v %v", days, err)
	}

	o, err := r.Overview(ctx, day("2026-11-13"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Requests != 50 || o.PageViews != 20 || o.HumanPageViews != 19 || o.Visitors != 4 || o.HumanVisitors != 3 ||
		o.APIRequests != 11 || o.APIClients != 4 || o.Metrics["req_status"]["all:5xx"] != 1 || o.PageP95 != 40 {
		t.Errorf("overview %+v", o)
	}
	o, err = r.Overview(ctx, day("2020-01-01"))
	if err != nil || o.Requests != 0 || len(o.Metrics) != 0 {
		t.Errorf("empty overview %+v %v", o, err)
	}
}
