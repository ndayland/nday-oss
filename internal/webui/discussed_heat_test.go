package webui_test

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

// The /discussed heat ranking (discussed.tmpl heatrow, site/discussed.go).
// Seeded at sitetest.Now (2026-11-13 01:00 UTC; today is day 6 of the
// sparkline, 2026-11-07 day 0):
//
//   - heatTop: 5 researchers (rank 1). Posts 30 min (day 6), 2 h (day 5),
//     3 days (day 3), 6 days 30 min and 5 days 2 h ago (both day 0, the
//     window's first UTC day); a disabled account 10 min ago (never
//     counted or shown). Faces: the 4 newest authors, 8004 (the oldest
//     post) is "+1". Avatars: 8001, 8003 and
//     8005 have one, 8002 and 8004 don't; the fifth author is "+1".
//   - heatHidden: 3 researchers. 8006's only post (5 days ago) is the 51st
//     newest of the CVE, so the CVE's public outline does not list 8006:
//     its avatar never shows, it only counts in "+1".
//   - heatNew: 2 researchers, first post 20 h ago, yesterday UTC ("new",
//     which wins over "no PoC or patch").
//   - sitetest.GPU: 1 researcher (8006, so 8006 IS listed somewhere), 25.5
//     h ago (the day before yesterday); the fixture has a PoC: no flag.
//   - heatFill: 51 stubs with 1 researcher each (no PoC or patch), so the
//     ranking has 55 entries over two pages.
const (
	heatTop    = "CVE-2026-9000"
	heatHidden = "CVE-2026-9001"
	heatNew    = "CVE-2026-9002"
	heatFill   = 51
)

// heatAvatars are the stored avatar hashes by author (putAvatar).
var heatAvatars = map[string]string{}

func heatSeed(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES
		('8001', 'QzHeatOne', true), ('8002', 'QzHeatTwo', true), ('8003', 'QzHeatThree', true), ('8004', 'QzHeatFour', true),
		('8005', 'QzHeatFive', true), ('8006', 'QzHeatSix', true), ('8099', 'QzHeatOff', false)`); err != nil {
		t.Fatal(err)
	}
	s := sitetest.Seeder{T: t, Conn: conn}
	n := 0
	post := func(cve, author string, ago time.Duration) {
		t.Helper()
		n++
		at := sitetest.Now.Add(-ago)
		id := fmt.Sprintf("18%017d", n)
		u := "https://x.com/QzHeat/status/" + id
		s.Event(sitetest.Ev{CVE: cve, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at, Key: id, URL: &u,
			Detail: `{"post_id": "` + id + `", "author_id": "` + author + `", "author_handle": "QzHeatHandle", "text": "QZHEAT-TEXT ` + id + `", "cves": ["` + cve + `"]}`})
	}
	for _, c := range []string{heatTop, heatHidden, heatNew} {
		s.Vuln(c, sitetest.P("Heat "+c))
	}
	for i := 0; i < heatFill; i++ {
		s.Vuln(fmt.Sprintf("CVE-2026-91%02d", i), nil)
	}
	h := time.Hour
	post(heatTop, "8001", 30*time.Minute)
	post(heatTop, "8002", 2*h)
	post(heatTop, "8003", 3*24*h)
	post(heatTop, "8004", 6*24*h+30*time.Minute)
	post(heatTop, "8005", 5*24*h+2*h)
	post(heatTop, "8099", 10*time.Minute)
	post(heatHidden, "8006", 5*24*h)
	post(heatHidden, "8002", h)
	for i := 0; i < 49; i++ {
		post(heatHidden, "8001", 2*h+time.Duration(i)*time.Minute)
	}
	post(heatNew, "8003", 3*h)
	post(heatNew, "8004", 20*h)
	post(sitetest.GPU, "8006", 25*h+30*time.Minute)
	for i := 0; i < heatFill; i++ {
		post(fmt.Sprintf("CVE-2026-91%02d", i), "8005", 26*h+time.Duration(i)*time.Minute)
	}
	for _, a := range []struct {
		id string
		w  int
	}{{"8001", 31}, {"8003", 33}, {"8005", 35}, {"8006", 37}, {"8099", 39}} {
		heatAvatars[a.id] = putAvatar(t, conn, a.id, sitetest.P("QzHeatName"+a.id), avatarPNG(t, a.w), "image/png")
	}
	s.Refresh()
}

var (
	heatRowRe   = regexp.MustCompile(`(?s)<li class="dzr" data-row="" data-id="([^"]+)".*?</li>`)
	heatRankRe  = regexp.MustCompile(`<span class="dz-rk">([^<]*)</span>`)
	heatNumRe   = regexp.MustCompile(`<span class="dz-n" aria-hidden="true">([^<]*)</span>`)
	heatBarRe   = regexp.MustCompile(`<rect class="dz-bf" width="(\d+)" height="4"/>`)
	heatSparkRe = regexp.MustCompile(`<svg class="dz-sp dz-(up|flat|down)" viewBox="0 0 60 20" role="img" aria-label="([^"]*)" focusable="false"><polyline points="([^"]*)"/></svg>`)
	heatFlagRe  = regexp.MustCompile(`<span class="dz-flag (dz-new|dz-bare)">([^<]*)</span>`)
	heatFaceRe  = regexp.MustCompile(`<img class="dz-fa" src="(/avatar/[0-9a-f]{16})" width="20" height="20" alt="" loading="lazy" decoding="async"/>|<span class="dz-fa dz-fx"></span>`)
	heatMoreRe  = regexp.MustCompile(`<span class="dz-more">([^<]*)</span>`)
	heatStageRe = regexp.MustCompile(`<span class="dz-st (st-[a-z]+)" title="[^"]*"><span aria-hidden="true">([A-Z]+)</span>`)
	styleAttrRe = regexp.MustCompile(`(?i)\sstyle\s*=`)
)

// heatRows maps each row of a page to its markup, in order.
func heatRows(body string) (ids []string, rows map[string]string) {
	rows = map[string]string{}
	for _, m := range heatRowRe.FindAllStringSubmatch(body, -1) {
		ids = append(ids, m[1])
		rows[m[1]] = m[0]
	}
	return ids, rows
}

func sub(re *regexp.Regexp, s string, i int) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[i]
	}
	return ""
}

// faces lists a row's avatars ("-" = the placeholder of an author without
// one).
func faces(row string) string {
	var out []string
	for _, m := range heatFaceRe.FindAllStringSubmatch(row, -1) {
		if m[1] == "" {
			out = append(out, "-")
		} else {
			out = append(out, m[1])
		}
	}
	return strings.Join(out, " ")
}

func TestDiscussedHeatRanking(t *testing.T) {
	e := newEnvSeeded(t, heatSeed)
	_, one := e.get(t, "/discussed")
	_, two := e.get(t, "/discussed?offset=50")
	ids1, rows1 := heatRows(one)
	ids2, rows2 := heatRows(two)
	if len(ids1) != 50 || len(ids2) != 5 {
		t.Fatalf("rows: %d + %d, want 50 + 5", len(ids1), len(ids2))
	}
	// order: researchers, then the newest post, then the id; ranks continue
	// across pages
	if got := strings.Join(ids1[:4], ","); got != heatTop+","+heatHidden+","+heatNew+","+sitetest.GPU {
		t.Errorf("top of the ranking: %s", got)
	}
	if ids1[4] != "CVE-2026-9100" || ids2[0] != "CVE-2026-9146" || ids2[4] != "CVE-2026-9150" {
		t.Errorf("fill order: %s … %s … %s", ids1[4], ids2[0], ids2[4])
	}
	for i, id := range ids1 {
		if got := sub(heatRankRe, rows1[id], 1); got != strconv.Itoa(i+1) {
			t.Errorf("page 1 row %d (%s): rank %q", i, id, got)
		}
	}
	for i, id := range ids2 {
		if got := sub(heatRankRe, rows2[id], 1); got != strconv.Itoa(51+i) {
			t.Errorf("page 2 row %d (%s): rank %q", i, id, got)
		}
	}
	// heat: the count, and a bar scaled to the WHOLE ranking's top (5), on
	// page 2 too
	for id, want := range map[string][2]string{heatTop: {"5", "100"}, heatHidden: {"3", "60"}, heatNew: {"2", "40"}, sitetest.GPU: {"1", "20"}} {
		if n, w := sub(heatNumRe, rows1[id], 1), sub(heatBarRe, rows1[id], 1); n != want[0] || w != want[1] {
			t.Errorf("%s: heat %s bar %s, want %v", id, n, w, want)
		}
	}
	if n, w := sub(heatNumRe, rows2[ids2[0]], 1), sub(heatBarRe, rows2[ids2[0]], 1); n != "1" || w != "20" {
		t.Errorf("page 2: heat %s bar %s, want 1 and 20 (the global top, not the page's)", n, w)
	}
	if !strings.Contains(rows1[heatTop], `<span class="dz-u" aria-hidden="true">researchers</span><span class="sr">5 researchers mentioned this in the last 7 days</span>`) ||
		!strings.Contains(rows1[sitetest.GPU], `<span class="dz-u" aria-hidden="true">researcher</span>`) {
		t.Errorf("unit: %s", rows1[heatTop])
	}
	// sparkline: posts per UTC day, oldest first (the window's 7 days); the
	// disabled account is not drawn
	for id, want := range map[string][3]string{
		heatTop:    {"flat", "7-day trend: steady", "2.0,2.0 11.3,18.0 20.7,18.0 30.0,10.0 39.3,18.0 48.7,10.0 58.0,10.0"},
		heatNew:    {"up", "7-day trend: rising", "2.0,18.0 11.3,18.0 20.7,18.0 30.0,18.0 39.3,18.0 48.7,2.0 58.0,18.0"},
		heatHidden: {"up", "7-day trend: rising", "2.0,18.0 11.3,17.7 20.7,18.0 30.0,18.0 39.3,18.0 48.7,2.0 58.0,17.7"},
	} {
		m := heatSparkRe.FindStringSubmatch(rows1[id])
		if m == nil || m[1] != want[0] || m[2] != want[1] || m[3] != want[2] {
			t.Errorf("%s sparkline %q, want %v\n%s", id, m, want, rows1[id])
		}
	}
	// flags: "new" wins over "no PoC or patch"; a stub has neither;
	// the GPU fixture has a PoC: none
	for id, want := range map[string]string{heatTop: "dz-bare", heatHidden: "dz-bare", heatNew: "dz-new", sitetest.GPU: "", ids2[0]: "dz-bare"} {
		row := rows1[id] + rows2[id]
		if got := sub(heatFlagRe, row, 1); got != want || strings.Count(row, `class="dz-flag `) > 1 {
			t.Errorf("%s: flag %q, want %q", id, got, want)
		}
	}
	if sub(heatFlagRe, rows1[heatNew], 2) != "new" || sub(heatFlagRe, rows1[heatTop], 2) != "discussed, no PoC or patch yet" {
		t.Errorf("flag words: %q %q", sub(heatFlagRe, rows1[heatNew], 2), sub(heatFlagRe, rows1[heatTop], 2))
	}
	// one stage label (the current stage) where there is a lifecycle state
	if st := heatStageRe.FindAllStringSubmatch(rows1[sitetest.GPU], -1); len(st) != 1 || st[0][1] != "st-"+strings.ToLower(st[0][2]) {
		t.Errorf("GPU stage label %v", st)
	}
	if strings.Contains(rows1[heatTop], `class="dz-st `) {
		t.Error("a stub row has a stage label")
	}
	// avatars: the listed window authors, newest post first, at most 4,
	// "+N" for the rest of the public count; 8006 is listed for GPU but not
	// for heatHidden (cut from its outline); the disabled account never
	a := func(id string) string { return "/avatar/" + heatAvatars[id] }
	for id, want := range map[string][2]string{
		heatTop:      {a("8001") + " - " + a("8003") + " " + a("8005"), "+1"},
		heatHidden:   {"- " + a("8001"), "+1"},
		heatNew:      {a("8003") + " -", ""},
		sitetest.GPU: {a("8006"), ""},
	} {
		if f, m := faces(rows1[id]), html.UnescapeString(sub(heatMoreRe, rows1[id], 1)); f != want[0] || m != want[1] {
			t.Errorf("%s: faces %q more %q, want %v", id, f, m, want)
		}
	}
	if strings.Contains(rows1[heatHidden], heatAvatars["8006"]) || strings.Contains(one+two, heatAvatars["8099"]) {
		t.Error("an avatar the CVE's outline does not show")
	}
	// the faces are decoration with an empty alt; no handle, name, profile
	// link, post id, text or author id anywhere on the page
	for _, body := range []string{one, two} {
		for _, bad := range []string{"QzHeat", "QZHEAT", "x.com", "8001", "8002", "8003", "8004", "8005", "8006", "8099", "18000000",
			"post_id", "author"} {
			if strings.Contains(body, bad) {
				t.Errorf("the page contains %q", bad)
			}
		}
		if styleAttrRe.MatchString(body) || strings.Contains(body, "<script>") {
			t.Error("an inline style attribute or script")
		}
		// the hot list's row parts are gone
		for _, gone := range []string{`class="chg"`, `class="strip"`, `class="six"`, `class="stc"`, "T+", `class="vn"`, `class="tr th"`, "stripdefs", `class="sdefs"`} {
			if strings.Contains(body, gone) {
				t.Errorf("the page still has %q", gone)
			}
		}
	}
	// the list is numbered from the page's first rank, and stays a list
	// for assistive technology despite list-style: none
	if !strings.Contains(one, `<ol class="dzl" role="list" start="1">`) || !strings.Contains(two, `<ol class="dzl" role="list" start="51">`) {
		t.Error("the ranked list lacks role=list or the page's start")
	}
	// the numbered pager pages the ranking
	if posOf(two) != `<span class="sr">page 2 of 2</span><span>51–55 of 55</span>` || numbersOf(two) != "1 [2]" ||
		!strings.Contains(pagerOf(one), `href="/discussed?offset=50"`) {
		t.Errorf("pager: %q %q\n%s", posOf(two), numbersOf(two), pagerOf(one))
	}
	// the avatar route serves exactly the listed authors' pictures
	for id, want := range map[string]int{"8001": 200, "8006": 200, "8099": 404} {
		if resp, _ := e.get(t, a(id)); resp.StatusCode != want {
			t.Errorf("avatar of %s: %d, want %d", id, resp.StatusCode, want)
		}
	}
}

// Every enabled locale renders the unit, the flags and the trend in its
// own words, never a missing-key marker.
func TestDiscussedHeatLocales(t *testing.T) {
	e := newEnvSeeded(t, heatSeed)
	want := map[string][4]string{
		"":        {"researchers", "new", "discussed, no PoC or patch yet", "7-day trend: rising"},
		"zh-hans": {"位研究员", "新上榜", "热议，尚无 PoC 和补丁", "7 天趋势：上升"},
		"zh-hant": {"位研究員", "新上榜", "熱議，尚無 PoC 和修補", "7 天趨勢：上升"},
		"ja":      {"人の研究者", "新着", "話題、PoC と修正はまだなし", "7 日間の推移：増加"},
		"ko":      {"명의 연구자", "신규", "화제, PoC·패치 아직 없음", "7일 추세: 상승"},
		"es":      {"investigadores", "nuevo", "debatido, sin PoC ni parche", "tendencia de 7 días: al alza"},
		"fr":      {"chercheurs", "nouveau", "discuté, ni PoC ni correctif", "tendance sur 7\u00a0jours\u202f: en hausse"},
	}
	for prefix, w := range want {
		path := "/discussed"
		if prefix != "" {
			path = "/" + prefix + "/discussed"
		}
		resp, body := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		_, rows := heatRows(body)
		top, nw := rows[heatTop], rows[heatNew]
		if !strings.Contains(top, `<span class="dz-u" aria-hidden="true">`+w[0]+`</span>`) ||
			sub(heatFlagRe, nw, 2) != w[1] || sub(heatFlagRe, top, 2) != w[2] || sub(heatSparkRe, rows[heatHidden], 2) != w[3] {
			t.Errorf("%s: unit/flags/trend not %v:\n%s\n%s", path, w, top, nw)
		}
		if strings.Contains(body, "⟦") || strings.Contains(body, "discussed.") {
			t.Errorf("%s: a missing message", path)
		}
	}
}

// Later pages scale their bars to the first page's top, even when they are
// computed after a post changed the top: page 1 (cached) says 5, a sixth
// researcher then posts about heatTop, page 2 (computed now) still draws
// a 1-researcher row at 1/5.
func TestDiscussedBarScaleAcrossPages(t *testing.T) {
	var conn *pgx.Conn
	e := newEnvSeeded(t, func(t *testing.T, c *pgx.Conn) { heatSeed(t, c); conn = c })
	_, one := e.get(t, "/discussed")
	if _, rows := heatRows(one); sub(heatNumRe, rows[heatTop], 1) != "5" {
		t.Fatalf("precondition: top %s", sub(heatNumRe, rows[heatTop], 1))
	}
	at := sitetest.Now.Add(-time.Minute)
	sitetest.Seeder{T: t, Conn: conn}.Event(sitetest.Ev{CVE: heatTop, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at,
		Key: "1899999999999999999", Detail: `{"post_id": "1899999999999999999", "author_id": "8006", "cves": ["` + heatTop + `"]}`})
	_, two := e.get(t, "/discussed?offset=50")
	ids, rows := heatRows(two)
	if len(ids) == 0 || sub(heatBarRe, rows[ids[0]], 1) != "20" {
		t.Errorf("page 2 bar %q, want 20 (1 of page 1's top 5)", sub(heatBarRe, rows[ids[0]], 1))
	}
}
