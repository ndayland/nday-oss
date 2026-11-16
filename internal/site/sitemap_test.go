package site_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

func TestSitemapSpan(t *testing.T) {
	// A bucket must never mix ids of different digit counts (range scan).
	if 10000%site.SitemapSpan != 0 {
		t.Errorf("SitemapSpan %d does not divide 10^4", site.SitemapSpan)
	}
}

func TestSitemapBucketsAndVulns(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	// Bucket edges and ids whose text sorts inside another bucket's range.
	for _, id := range []string{"CVE-2026-4999", "CVE-2026-5000", "CVE-2026-10000", "CVE-2026-14999",
		"CVE-2026-100000", "CVE-2026-149999", "CVE-2025-1000"} {
		s.Vuln(id, nil)
	}
	s.Refresh()

	buckets, err := st.SitemapBuckets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range buckets {
		got = append(got, fmt.Sprintf("%d/%d", b.Year, b.Bucket))
	}
	if strings.Join(got, " ") != "2025/0 2026/0 2026/1 2026/2 2026/20 2026/29" {
		t.Errorf("buckets %v", got)
	}

	list := func(y, b int) string {
		t.Helper()
		es, err := st.SitemapVulns(ctx, site.SitemapBucket{Year: y, Bucket: b})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.CVEID)
		}
		return strings.Join(out, ",")
	}
	// 1005 is rejected; 1010 has no events and is listed.
	if g := list(2026, 0); g != "CVE-2026-1001,CVE-2026-1002,CVE-2026-1003,CVE-2026-1004,CVE-2026-1006,CVE-2026-1007,"+
		"CVE-2026-1008,CVE-2026-1009,CVE-2026-1010,CVE-2026-4999" {
		t.Errorf("2026/0 %s", g)
	}
	if g := list(2026, 1); g != "CVE-2026-5000" {
		t.Errorf("2026/1 %s", g)
	}
	if g := list(2026, 2); g != "CVE-2026-10000,CVE-2026-14999" {
		t.Errorf("2026/2 %s", g)
	}
	if g := list(2026, 20); g != "CVE-2026-100000,CVE-2026-102895" {
		t.Errorf("2026/20 %s", g)
	}
	if g := list(2026, 29); g != "CVE-2026-149999" {
		t.Errorf("2026/29 %s", g)
	}
	for _, b := range []site.SitemapBucket{{Year: 2026, Bucket: 3}, {Year: 2024, Bucket: 0}, {Year: 99, Bucket: 0}, {Year: 2026, Bucket: -1}, {Year: 2026, Bucket: 1 << 30}} {
		if g := list(b.Year, b.Bucket); g != "" {
			t.Errorf("%v: %s", b, g)
		}
	}

	// lastmod = later of vuln.updated_at and the newest event's created_at.
	if _, err := d.Conn.Exec(ctx, `UPDATE vuln SET updated_at = '2026-01-01T00:00:00Z' WHERE cve_id IN ($1, 'CVE-2026-1010')`,
		sitetest.GPU); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE event SET created_at = '2026-11-10T08:30:00+02:00' WHERE cve_id = $1 AND source = 'kev'`,
		sitetest.GPU); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE event SET created_at = '2026-02-01T00:00:00Z' WHERE cve_id = $1 AND source <> 'kev'`,
		sitetest.GPU); err != nil {
		t.Fatal(err)
	}
	es, err := st.SitemapVulns(ctx, site.SitemapBucket{Year: 2026, Bucket: 20})
	if err != nil || len(es) != 2 {
		t.Fatal(es, err)
	}
	if want := time.Date(2026, 11, 10, 6, 30, 0, 0, time.UTC); es[1].CVEID != sitetest.GPU || !es[1].LastMod.Equal(want) ||
		es[1].LastMod.Location() != time.UTC {
		t.Errorf("GPU lastmod %v", es[1])
	}
	es, _ = st.SitemapVulns(ctx, site.SitemapBucket{Year: 2026, Bucket: 0})
	for _, e := range es {
		if e.CVEID == "CVE-2026-1010" && !e.LastMod.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("no-event lastmod %v", e.LastMod)
		}
	}
}
