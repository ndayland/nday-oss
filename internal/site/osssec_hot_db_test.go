package site_test

import (
	"slices"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// An oss-security post (source osssec) is an ANA event like any other on
// the vulnerability page, but it never counts as a transition, so it never
// brings a vulnerability onto the hot list (migrations/0039,
// site.NoTransitionSources). Other analysis sources still count.
func TestOsssecPostIsNotATransition(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	st := site.New(site.SingleConn(d.Conn)).WithClock(func() time.Time { return sitetest.Now })

	// The Go list (vulnerability page) and the SQL function (lists) agree
	// over every registered source.
	all := slices.Concat([]string{"blog"}, site.SourceNames, site.PocSourceNames, site.NonPublicSources)
	for _, src := range all {
		var counts bool
		if err := d.Conn.QueryRow(ctx, `SELECT counts_as_transition($1)`, src).Scan(&counts); err != nil {
			t.Fatal(err)
		}
		if want := !slices.Contains(site.NoTransitionSources, src); counts != want {
			t.Errorf("counts_as_transition(%q) = %v, site.NoTransitionSources says %v", src, counts, want)
		}
	}

	at := func(days float64) *time.Time { v := sitetest.Ago(days); return &v }
	post := func(cve string, days float64) {
		s.Event(sitetest.Ev{CVE: cve, Type: "analysis_published", Source: "osssec", Occurred: at(days),
			Key: "2026/q4/" + cve, Detail: `{"subject": "s", "author": "a", "is_reply": false, "list": "oss-security"}`})
	}
	const (
		onlyPost  = "CVE-2026-9001" // (a) nothing but a post
		patchPost = "CVE-2026-9002" // (b) patch 2 days ago, post yesterday
		blog      = "CVE-2026-9003" // (d) a non-osssec analysis
		tie       = "CVE-2026-9004" // post and a blog analysis at the same instant
	)
	for _, id := range []string{onlyPost, patchPost, blog, tie} {
		s.Vuln(id, sitetest.P("t "+id))
	}
	post(onlyPost, 1)

	s.Event(sitetest.Ev{CVE: patchPost, Type: "disclosed", Source: "cvelist", Occurred: at(5), Key: "c"})
	patchID := s.Event(sitetest.Ev{CVE: patchPost, Type: "patch_released", Source: "ghsa", Occurred: at(2), Key: "g"})
	post(patchPost, 1)

	s.Event(sitetest.Ev{CVE: blog, Type: "disclosed", Source: "cvelist", Occurred: at(5), Key: "c"})
	post(blog, 3)
	s.Event(sitetest.Ev{CVE: blog, Type: "analysis_published", Source: "blog", Occurred: at(1), Key: "b"})

	s.Event(sitetest.Ev{CVE: tie, Type: "disclosed", Source: "cvelist", Occurred: at(5), Key: "c"})
	post(tie, 1) // lower id than the blog event, which must still win
	tieID := s.Event(sitetest.Ev{CVE: tie, Type: "analysis_published", Source: "blog", Occurred: at(1), Key: "b"})
	s.Refresh()

	page, err := st.Hot(ctx, site.HotParams{Since: 7 * 24 * time.Hour, MinStage: "disclosed", IncludeRejected: true, NoPins: true})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]site.HotRow{}
	for _, r := range page.Rows {
		rows[r.CVEID] = r
	}
	if _, ok := rows[onlyPost]; ok {
		t.Errorf("(a) a vulnerability with only an oss-security post is on the hot list")
	}
	if r, ok := rows[patchPost]; !ok {
		t.Errorf("(b) %s missing from the hot list", patchPost)
	} else if r.Transition.Type != "patch_released" || !r.Transition.At.Equal(sitetest.Ago(2)) ||
		r.Transition.EventID == nil || *r.Transition.EventID != patchID || r.Stage != "analysis_published" {
		t.Errorf("(b) want the patch transition at %v, stage ANA; got %+v stage %s", sitetest.Ago(2), r.Transition, r.Stage)
	}
	if r, ok := rows[blog]; !ok || r.Transition.Type != "analysis_published" || !r.Transition.At.Equal(sitetest.Ago(1)) ||
		r.Transition.Source == nil || *r.Transition.Source != "blog" {
		t.Errorf("(d) a non-osssec analysis must count: %v %+v", ok, r.Transition)
	}
	if r, ok := rows[tie]; !ok || r.Transition.EventID == nil || *r.Transition.EventID != tieID {
		t.Errorf("tie: the transition event must be the blog one (%d): %v %+v", tieID, ok, r.Transition)
	}
	if got := ids(page.Rows); got != "9003,9004,9002" && got != "9004,9003,9002" {
		t.Errorf("order %s", got)
	}

	// (c) the page still has the post, stage ANA and the ANA time.
	for _, c := range []struct {
		id     string
		trType string
		trAt   time.Time
	}{{onlyPost, "", time.Time{}}, {patchPost, "patch_released", sitetest.Ago(2)}, {blog, "analysis_published", sitetest.Ago(1)}} {
		v, found, err := st.Vuln(ctx, c.id)
		if err != nil || !found {
			t.Fatalf("%s: %v %v", c.id, found, err)
		}
		var posts int
		for _, e := range v.Events {
			if e.Source == "osssec" {
				posts++
			}
		}
		if posts != 1 || v.Stage == nil || *v.Stage != "analysis_published" || v.State == nil ||
			v.State.Stage != "analysis_published" || v.State.AnalysisAt == nil || !v.State.HasAnalysis {
			t.Errorf("(c) %s: posts %d stage %v state %+v", c.id, posts, v.Stage, v.State)
			continue
		}
		if c.trType == "" {
			if v.Transition != nil || v.State.LastTransitionAt != nil || v.State.LastTransitionType != nil {
				t.Errorf("(c) %s: want no transition, got %+v / %v %v", c.id, v.Transition, v.State.LastTransitionAt, v.State.LastTransitionType)
			}
			continue
		}
		if v.Transition == nil || v.Transition.Type != c.trType || !v.Transition.At.Equal(c.trAt) ||
			v.State.LastTransitionType == nil || *v.State.LastTransitionType != c.trType ||
			v.State.LastTransitionAt == nil || !v.State.LastTransitionAt.Equal(c.trAt) {
			t.Errorf("(c) %s: want %s at %v, got %+v / %v %v", c.id, c.trType, c.trAt, v.Transition,
				v.State.LastTransitionAt, v.State.LastTransitionType)
		}
		for _, sl := range v.Slots {
			if sl.Latest != (sl.Type == c.trType) {
				t.Errorf("(c) %s: slot %s latest %v", c.id, sl.Type, sl.Latest)
			}
		}
	}
	// the ANA slot keeps the first post's time (3 days ago), though the
	// transition is the blog's
	if v, _, _ := st.Vuln(ctx, blog); v == nil || v.State == nil || v.State.AnalysisAt == nil || !v.State.AnalysisAt.Equal(sitetest.Ago(3)) {
		t.Errorf("analysis_at must stay the first post's time")
	}
}
