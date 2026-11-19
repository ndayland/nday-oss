package site_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

func seededGHSA(t *testing.T) *site.Store {
	st, d, _ := seeded(t)
	sitetest.SeedGHSA(t, d.Conn)
	return st
}

func TestParseVulnID(t *testing.T) {
	for in, want := range map[string]string{
		"CVE-2026-102895": "CVE-2026-102895", " cve-2026-102895 ": "CVE-2026-102895",
		"GHSA-gpwc-27cw-rh9r": "GHSA-gpwc-27cw-rh9r", "ghsa-GPWC-27CW-RH9R": "GHSA-gpwc-27cw-rh9r",
	} {
		if got, ok := site.ParseVulnID(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "CVE-2026-1", "GHSA-gpwc-27cw", "GHSA-aaaa-27cw-rh9r", "GHSA-gpwc-27cw-rh9r-",
		"GHSA_gpwc-27cw-rh9r", "GHSAgpwc-27cw-rh9r", "2026-102895", "gpwc-27cw-rh9r"} {
		if got, ok := site.ParseVulnID(in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	if !site.IsGHSAID(sitetest.GHSA) || site.IsGHSAID(sitetest.GPU) {
		t.Error("IsGHSAID")
	}
}

// A vulnerability keyed by a GHSA id is served like any other: detail with
// its own id, the advisory's description source and credits (found by the
// raw record's key, the advisory naming no CVE), raw records and patches.
func TestVulnKeyedByGHSA(t *testing.T) {
	st := seededGHSA(t)
	v, found, err := st.Vuln(ctx, "ghsa-GPWC-27cw-rh9r")
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	if v.CVEID != sitetest.GHSA || len(v.Aliases) != 0 || v.StageCode == nil || *v.StageCode != "PAT" ||
		v.DisclosedAt == nil || v.State == nil || v.State.Stage != "patch_released" {
		t.Errorf("detail %+v", v)
	}
	if v.DescriptionSource == nil || v.DescriptionSource.Source != "ghsa" || v.DescriptionSource.Key != sitetest.GHSA {
		t.Errorf("description source %+v", v.DescriptionSource)
	}
	if len(v.Credits) != 1 || v.Credits[0].Name != "qzfinder" || v.Credits[0].Key != sitetest.GHSA {
		t.Errorf("credits %+v", v.Credits)
	}
	if len(v.RawRecords) != 1 || v.RawRecords[0].Path != "/raw/ghsa/"+sitetest.GHSA+".json" {
		t.Errorf("raw %+v", v.RawRecords)
	}
	if len(v.Patches) != 1 || v.Patches[0].AdvisoryID == nil || *v.Patches[0].AdvisoryID != sitetest.GHSA ||
		v.CVSS == nil || v.CVSS.Source != "ghsa" {
		t.Errorf("patches %+v cvss %+v", v.Patches, v.CVSS)
	}
	// a GHSA id that is only an alias is not a vulnerability of its own
	if _, found, err := st.Vuln(ctx, sitetest.GHSAAlias); found || err != nil {
		t.Errorf("alias: %v %v", found, err)
	}
	var ie *site.InputError
	if _, _, err := st.Vuln(ctx, "GHSA-aaaa-27cw-rh9r"); !errors.As(err, &ie) {
		t.Errorf("malformed: %v", err)
	}
	if v.IsRejected || v.Rejection != nil {
		t.Errorf("published advisory reads as rejected: %+v", v.Rejection)
	}
}

// A withdrawn advisory (its disclosed event turned REJECTED by the ghsa
// collector) reads like a rejected CVE record, dated withdrawn_at.
func TestWithdrawnGHSA(t *testing.T) {
	st, d, _ := seeded(t)
	sitetest.SeedGHSA(t, d.Conn)
	if _, err := d.Conn.Exec(ctx, `UPDATE event SET detail = detail || '{"state": "REJECTED", "withdrawn_at": "2026-11-12T08:00:00Z"}'
		WHERE cve_id = $1 AND type = 'disclosed'`, sitetest.GHSA); err != nil {
		t.Fatal(err)
	}
	v, found, err := st.Vuln(ctx, sitetest.GHSA)
	if err != nil || !found || !v.IsRejected || v.Rejection == nil || v.Rejection.DateRejected == nil ||
		*v.Rejection.DateRejected != "2026-11-12T08:00:00Z" || len(v.Rejection.Reasons) != 0 {
		t.Errorf("%v %v %+v", found, err, v)
	}
}

// Hot list and catalogue pages walked one row at a time: the cursor of a
// GHSA-keyed row round-trips, and the year filter leaves the row out.
func TestGHSACursorsAndYear(t *testing.T) {
	st := seededGHSA(t)
	month := 30 * 24 * time.Hour
	var hot []string
	for cur := ""; ; {
		p, err := st.Hot(ctx, site.HotParams{Since: month, Limit: 1, Cursor: cur})
		if err != nil {
			t.Fatalf("hot after %q: %v", cur, err)
		}
		for _, r := range p.Rows {
			hot = append(hot, r.CVEID)
		}
		if p.NextCursor == nil {
			break
		}
		cur = *p.NextCursor
	}
	if i := slices.Index(hot, sitetest.GHSA); i < 0 || i == len(hot)-1 {
		t.Errorf("hot walk %v: the GHSA row must be on a page with a cursor after it", hot)
	}
	walk := func(year int) []string {
		var out []string
		for cur := ""; ; {
			p, err := st.Catalogue(ctx, site.CatalogueParams{Year: year, Limit: 1, Cursor: cur})
			if err != nil {
				t.Fatalf("catalogue %d after %q: %v", year, cur, err)
			}
			for _, r := range p.Rows {
				out = append(out, r.CVEID)
			}
			if p.NextCursor == nil {
				return out
			}
			cur = *p.NextCursor
		}
	}
	all, y2026 := walk(0), walk(2026)
	if i := slices.Index(all, sitetest.GHSA); i < 0 || i == len(all)-1 {
		t.Errorf("catalogue walk %v", all)
	}
	if slices.Contains(y2026, sitetest.GHSA) || len(y2026) != len(all)-1 {
		t.Errorf("year 2026 %v (all %v)", y2026, all)
	}
}

func TestGHSASitemap(t *testing.T) {
	st := seededGHSA(t)
	bs, err := st.SitemapBuckets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) == 0 || bs[len(bs)-1] != (site.SitemapBucket{GHSA: "g"}) || bs[0].GHSA != "" {
		t.Fatalf("buckets %+v", bs)
	}
	es, err := st.SitemapVulns(ctx, site.SitemapBucket{GHSA: "g"})
	if err != nil || len(es) != 1 || es[0].CVEID != sitetest.GHSA || es[0].LastMod.IsZero() {
		t.Errorf("ghsa shard %+v %v", es, err)
	}
	for _, b := range []site.SitemapBucket{{GHSA: "a"}, {GHSA: "gg"}, {GHSA: "g", Year: 2026}, {GHSA: "2"}} {
		if es, err := st.SitemapVulns(ctx, b); err != nil || len(es) != 0 {
			t.Errorf("%+v: %+v %v", b, es, err)
		}
	}
	// the CVE buckets are unchanged
	es, err = st.SitemapVulns(ctx, site.SitemapBucket{Year: 2026, Bucket: 0})
	if err != nil || len(es) == 0 || slices.ContainsFunc(es, func(e site.SitemapEntry) bool { return site.IsGHSAID(e.CVEID) }) {
		t.Errorf("cve shard %+v %v", es, err)
	}
}

// Search: a GHSA id finds the vulnerability keyed by it (first) as well as
// CVEs that have it as an alias; text and tag searches order a GHSA row
// without trying to read a year out of it.
func TestGHSASearch(t *testing.T) {
	st := seededGHSA(t)
	res, err := st.Search(ctx, "ghsa-GPWC-27cw-rh9r", 0)
	if err != nil || res.Kind != site.SearchAlias || res.Query != sitetest.GHSA || len(res.Rows) != 1 || res.Rows[0].CVEID != sitetest.GHSA {
		t.Errorf("own id: %+v %v", res, err)
	}
	res, err = st.Search(ctx, sitetest.GHSAAlias, 0)
	if err != nil || len(res.Rows) != 1 || res.Rows[0].CVEID != "CVE-2026-1004" {
		t.Errorf("alias: %+v %v", res, err)
	}
	res, err = st.Search(ctx, "qzmerge", 0)
	if err != nil || res.Kind != site.SearchText || len(res.Rows) != 1 || res.Rows[0].CVEID != sitetest.GHSA {
		t.Errorf("text: %+v %v", res, err)
	}
	// a text match on several rows, CVE and GHSA ids alike: the GHSA row
	// (no year to read) sorts by text after CVEs of the same transition time
	res, err = st.Search(ctx, "on", site.MaxSearchLimit)
	if err != nil || !slices.ContainsFunc(res.Rows, func(r site.SearchRow) bool { return r.CVEID == sitetest.GHSA }) {
		t.Errorf("broad text: %+v %v", res, err)
	}
}
