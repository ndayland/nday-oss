package webui_test

import (
	"context"
	"html"
	"image/png"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/xdraft"
)

var (
	shareBlockRe = regexp.MustCompile(`(?s)<details class="share">.*?</details>`)
	shareXRe     = regexp.MustCompile(`<li><a href="([^"]*)" target="_blank" rel="noopener noreferrer"[^>]*>`)
	shareCopyRe  = regexp.MustCompile(`<li><button type="button" data-copy="([^"]*)" hidden="">`)
	canonRe      = regexp.MustCompile(`<link rel="canonical" href="([^"]*)"/>`)
)

// share is the share control of a page: the compose URL, the copied text
// and the whole block.
type share struct{ compose, text, block string }

func shareOf(t *testing.T, e *tenv, path string) (share, string) {
	t.Helper()
	resp, body := e.get(t, path, "Authorization", "")
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d", path, resp.StatusCode)
	}
	blocks := shareBlockRe.FindAllString(body, -1)
	if len(blocks) != 1 {
		t.Fatalf("%s: %d share controls", path, len(blocks))
	}
	x, c := shareXRe.FindStringSubmatch(blocks[0]), shareCopyRe.FindStringSubmatch(blocks[0])
	if x == nil || c == nil {
		t.Fatalf("%s: share control %s", path, blocks[0])
	}
	return share{compose: html.UnescapeString(x[1]), text: html.UnescapeString(c[1]), block: blocks[0]}, body
}

// The vulnerabilities of TestShareText, made after the draft pass's first
// run so that the pass drafts them like live events.
const (
	sharePOC      = "CVE-2026-9101" // POC (exploitdb, live), record title
	shareITW      = "CVE-2026-9102" // ITW (live), staff title over the record's
	shareKEV      = "CVE-2026-9103" // KEV (live), composed title only
	shareHostile  = "CVE-2026-9104" // KEV, hostile record title and product
	shareBoth     = "CVE-2026-9105" // POC then KEV (both live): the KEV draft
	shareRejected = "CVE-2026-9106" // KEV on a REJECTED record: no stage, as the generator skips it
	shareBase     = "https://www.nday.land"
	hostileTitle  = "Pwn https://evil.example/x see evil.com @admin #tag ‮evil⁦ $TSLA"
)

// TestShareText: the share text of a vulnerability page is what the draft
// generator writes for its most advanced stage (the same composer and the
// same input), the body without a stage sentence when none was reached,
// English on every locale, with the page's canonical URL in the page's
// language; it fits one post; hostile upstream text is neutralised; the
// control has no inline script or style.
func TestShareText(t *testing.T) {
	drafts := map[string]string{} // cve -> body of its newest-stage draft
	e := newEnvSeed(t, web.Config{PublicURL: shareBase}, webui.Options{}, func(conn *pgx.Conn) {
		ctx := context.Background()
		now := func() time.Time { return sitetest.Now }
		if r, err := xdraft.Generate(ctx, conn, xdraft.Options{Now: now}); err != nil || !r.Baseline {
			t.Fatalf("baseline %+v %v", r, err)
		}
		s := sitetest.Seeder{T: t, Conn: conn}
		disc := func(cve string, days float64) {
			s.Event(sitetest.Ev{CVE: cve, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Ago(days)), Backfill: true,
				Detail: `{"state": "PUBLISHED"}`})
		}
		live := func(cve, typ, src string, days float64) {
			s.Event(sitetest.Ev{CVE: cve, Type: typ, Source: src, Occurred: sitetest.P(sitetest.Ago(days)), Observed: sitetest.Ago(0.1), Key: cve + typ})
		}
		s.Vuln(sharePOC, sitetest.P("Acme Widget remote code execution"))
		s.Affected(sharePOC, "Acme", "Widget")
		s.Affected(sharePOC, "Acme", "Gadget")
		disc(sharePOC, 6)
		live(sharePOC, "poc_published", "exploitdb", 2)
		s.Vuln(shareITW, sitetest.P("record title"))
		s.Affected(shareITW, "Initech", "TPS")
		if _, err := conn.Exec(ctx, `INSERT INTO vuln_title (cve_id, staff_title, staff_at, staff_version) VALUES ($1, 'Staff title wins', now(), 1)`, shareITW); err != nil {
			t.Fatal(err)
		}
		disc(shareITW, 9)
		live(shareITW, "exploited_in_wild", "shadowserver", 1)
		s.Vuln(shareKEV, nil)
		s.Affected(shareKEV, "Acme", "Router")
		if _, err := conn.Exec(ctx, `INSERT INTO vuln_title (cve_id, rule_version, form, product, weakness, composed_en, composed_at)
			VALUES ($1, 1, 'full', 'Acme Router', 'sql-injection', 'SQL injection in Acme Router', now())`, shareKEV); err != nil {
			t.Fatal(err)
		}
		live(shareKEV, "kev_added", "kev", 0.5)
		s.Vuln(shareHostile, sitetest.P(hostileTitle))
		s.Affected(shareHostile, "@evil", "#Prod evil.com")
		disc(shareHostile, 3)
		live(shareHostile, "kev_added", "kev", 1)
		s.Vuln(shareRejected, sitetest.P("Rejected one"))
		s.Event(sitetest.Ev{CVE: shareRejected, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Ago(30)), Backfill: true,
			Detail: `{"state": "REJECTED"}`})
		s.Event(sitetest.Ev{CVE: shareRejected, Type: "kev_added", Source: "kev", Occurred: sitetest.P(sitetest.Ago(20)), Backfill: true})
		s.Vuln(shareBoth, sitetest.P("Both stages"))
		disc(shareBoth, 20)
		live(shareBoth, "poc_published", "nuclei", 10)
		live(shareBoth, "kev_added", "kev", 2)
		if r, err := xdraft.Generate(ctx, conn, xdraft.Options{Now: now}); err != nil || r.Created != 6 {
			t.Fatalf("drafts %+v %v", r, err)
		}
		rows, err := conn.Query(ctx, `SELECT DISTINCT ON (cve_id) cve_id, body FROM x_draft
			ORDER BY cve_id, array_position(ARRAY['kev_added', 'exploited_in_wild', 'poc_published'], stage)`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var c, b string
			if err := rows.Scan(&c, &b); err != nil {
				t.Fatal(err)
			}
			drafts[c] = b
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		s.Refresh()
	})

	locales := e.ui.Locales().Enabled
	if len(locales) != 7 {
		t.Fatalf("%d locales", len(locales))
	}
	// the stage parameter of each page's post link; no stage, no parameter
	stageParam := map[string]string{sharePOC: "?s=poc", shareITW: "?s=itw", shareKEV: "?s=kev", shareHostile: "?s=kev",
		shareBoth: "?s=kev", sitetest.GPU: "?s=kev", shareRejected: "", "CVE-2026-1004": ""}
	bodyOf := func(cve string) string {
		t.Helper()
		var first string
		for _, l := range locales {
			path := l.Path("/vuln/" + cve)
			sh, page := shareOf(t, e, path)
			link := shareBase + path
			if m := canonRe.FindStringSubmatch(page); m == nil || html.UnescapeString(m[1]) != link {
				t.Errorf("%s: canonical %v, want %s", path, m, link)
			}
			// the post link names the stage ("?s=kev": a URL of its own per
			// stage, so X does not reuse an earlier card); the canonical
			// URL above does not
			link += stageParam[cve]
			body, ok := strings.CutSuffix(sh.text, "\n"+link)
			if !ok {
				t.Errorf("%s: copy text %q does not end in the page link %s", path, sh.text, link)
				continue
			}
			if sh.compose != xdraft.ComposeURL(body, link) {
				t.Errorf("%s: compose %q", path, sh.compose)
			}
			if n := xdraft.WeightedLength(sh.text); n > xdraft.MaxWeighted {
				t.Errorf("%s: %d weighted", path, n)
			}
			if regexp.MustCompile(`(?i)\son[a-z]+=|\sstyle=|<script`).MatchString(sh.block) {
				t.Errorf("%s: inline script or style in %s", path, sh.block)
			}
			if first == "" {
				first = body
			} else if body != first {
				t.Errorf("%s: body differs by locale:\n%s\n%s", path, body, first)
			}
		}
		return first
	}

	for _, c := range []string{sharePOC, shareITW, shareKEV, shareHostile, shareBoth} {
		got := bodyOf(c)
		if drafts[c] == "" || got != drafts[c] {
			t.Errorf("%s: share body\n%q\nwant the draft's\n%q", c, got, drafts[c])
		}
	}
	// the exact texts (what the draft composer gives for these inputs)
	for c, want := range map[string]string{
		sharePOC:  "CVE-2026-9101 +POC T+4d\nAcme / Widget, Gadget\nAcme Widget remote code execution\nPublic PoC available: Exploit-DB entry.",
		shareITW:  "CVE-2026-9102 +ITW T+8d\nInitech / TPS\nStaff title wins\nExploitation in the wild reported (source: shadowserver).",
		shareKEV:  "CVE-2026-9103 +KEV\nAcme / Router\nSQL injection in Acme Router\nAdded to the CISA KEV catalog (known exploited).",
		shareBoth: "CVE-2026-9105 +KEV T+18d\nBoth stages\nAdded to the CISA KEV catalog (known exploited).",
		// a rejected record: no stage either
		shareRejected: "CVE-2026-9106\nRejected one",
		// no POC, ITW or KEV: the same body without the stage
		"CVE-2026-1004": "CVE-2026-1004\nonly disclosed",
		// KEV with known days (disclosed 11-04, KEV 11-09)
		sitetest.GPU: "CVE-2026-102895 +KEV T+5d\nGPUStack\nGPUStack: Authentication bypass via trusted loopback source\nAdded to the CISA KEV catalog (known exploited).",
	} {
		if got := bodyOf(c); got != want {
			t.Errorf("%s: share body\n%q\nwant\n%q", c, got, want)
		}
	}
	// hostile upstream text: no link, mention, hashtag, cashtag or bidi control survives
	h := bodyOf(shareHostile)
	for _, bad := range []string{"https://", "evil.com", "@", "#tag", "#Prod", "$TSLA", "‮", "⁦"} {
		if strings.Contains(h, bad) {
			t.Errorf("hostile share body keeps %q: %q", bad, h)
		}
	}
	if xdraft.Linkable(h) {
		t.Errorf("hostile share body is linkable: %q", h)
	}
	t.Logf("hostile: %q", h)
}

// TestAddressCard: ?addr=1 on the card route is the address card (the
// image forms of the drafts page): a PNG of its own key, with the card's
// caching and validators; the plain card is unchanged.
func TestAddressCard(t *testing.T) {
	e := newEnvFull(t, web.Config{PublicURL: shareBase}, webui.Options{})
	path := "/og/vuln/" + sitetest.GPU + ".png"
	pr, pb := e.get(t, path)
	ar, ab := e.get(t, path+"?addr=1")
	if pr.StatusCode != 200 || ar.StatusCode != 200 || ar.Header.Get("Content-Type") != "image/png" ||
		ar.Header.Get("X-Content-Type-Options") != "nosniff" || ar.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("%d %d %v", pr.StatusCode, ar.StatusCode, ar.Header)
	}
	if ab == pb || ar.Header.Get("ETag") == "" || ar.Header.Get("ETag") == pr.Header.Get("ETag") {
		t.Errorf("address card same as the plain one (etag %s vs %s)", ar.Header.Get("ETag"), pr.Header.Get("ETag"))
	}
	if _, err := png.Decode(strings.NewReader(ab)); err != nil {
		t.Fatal(err)
	}
	key := strings.Trim(ar.Header.Get("ETag"), `"`)
	if r, b := e.get(t, path+"?addr=1&v="+key); r.Header.Get("Cache-Control") != "public, max-age=86400" || b != ab {
		t.Errorf("current key: %q", r.Header.Get("Cache-Control"))
	}
	if r, _ := e.get(t, path+"?addr=1", "If-None-Match", ar.Header.Get("ETag")); r.StatusCode != 304 {
		t.Errorf("validator: %d", r.StatusCode)
	}
	// the page links the plain card, whose key is not the address card's
	if og := ogImage(t, e, "/vuln/"+sitetest.GPU); strings.Contains(og, "addr=") || strings.HasSuffix(og, "v="+key) {
		t.Errorf("og:image %s", og)
	}
	if r, _ := e.get(t, "/og/vuln/CVE-2026-9999999.png?addr=1"); r.StatusCode != 404 {
		t.Errorf("unknown id: %d", r.StatusCode)
	}
}
