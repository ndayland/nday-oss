package webui_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/posts"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
)

// X posts (collector xposts, docs/xposts.md) and comments: their content
// is for signed-in users only; the public may see counts and the
// placeholder outline (site/public.go, docs/discuss.md §4.1).
// Distinctive markers: none may appear in any signed-out response.
const (
	postCVE     = "CVE-2026-7777" // known only from posts
	postHandle  = "QzMarkerHandle"
	postAuthor  = "4242424242424242"
	post2Handle = "QzSecondHandle"
	post2Author = "4343434343434343"
	goneHandle  = "QzGoneHandle" // disabled account
	goneAuthor  = "4444444444444444"
	evilAuthor  = "4545454545454545"
	postID1     = "1999000000000000001" // GPU, A, 1 h ago
	postID2     = "1999000000000000002" // postCVE, A, exactly 7 days ago (counts)
	postID3     = "1999000000000000003" // GPU, B, 2 days ago
	postID4     = "1999000000000000004" // GPU, disabled account, 1 h ago (never shown or counted)
	postID5     = "1999000000000000005" // GPU, A, 8 days ago (shown to members, not counted)
	postID6     = "1999000000000000006" // postCVE, B, 7 days + 1 s ago (not counted)
	postID7     = "1999000000000000007" // CVE-2026-1001, B, 30 min ago
	postID8     = "1999000000000000008" // stub 8881, B, 40 min ago
	postID9     = "1999000000000000009" // stub 8882, B, 40 min ago
	postIDEvil  = "1999000000000000099" // GPU, hostile, 3 h ago
	postText1   = "QZMARKER-TEXT-ONE PoC out for CVE-2026-102895"
	postText2   = "QZMARKER-TEXT-TWO exploited CVE-2026-7777"
	goneText    = "QZMARKER-GONE disabled account post"
	evilText    = "QZMARKER-EVIL <script>alert(1)</script>\"><img src=x onerror=alert(2)> \u202eevil"
	evilHandle  = "\"><svg onload=QZEVILHANDLE>"
	postURLPath = "x.com/" + postHandle + "/status/"
	postErr     = "QZMARKER-COLLECTOR-ERROR"
	commenter   = "qzcommenter"
	commenterB  = "qzcommentalt"
	stubA       = "CVE-2026-8881"
	stubB       = "CVE-2026-8882"
)

// Draft posts for the brand X account (x_draft, migrations/0012) are staff
// only too.
const (
	draftText = "QZDRAFT-BODY one draft"
	draftPost = "1999000000000000777"
)

var postMarkers = []string{postHandle, post2Handle, goneHandle, postAuthor, post2Author, goneAuthor, evilAuthor,
	postID1, postID2, postID3, postID4, postID5, postID6, postID7, postID8, postID9, postIDEvil,
	"QZMARKER", postURLPath, "QZEVILHANDLE", "QZCOMMENT", commenter, "QZDRAFT", draftPost, "x_draft", "intent/tweet",
	"xposts", "social_post", "QZSHORT", "QZTITLE", "QZMEDIA", "qzgone.example", "QZPAGE", "QZFETCHED"}

// Links of researcher posts (x_post_link): the public resources section
// shows resURL (posted by two researchers) and resEvil (escaped) with the
// linked pages' titles (resURL: the API title, which wins over a fetched
// one; resEvil: a hostile fetched title, web_page), never the short links,
// media links or a disabled author's link. Titles appear ONLY in that
// panel (resTitle, resPage; markers QZTITLE, QZPAGE, QZFETCHED).
const (
	resURL   = "https://github.com/qzres/fix/commit/abc123"
	resEvil  = `https://res.example/a?x=1&y="><script>alert(6)</script>`
	resTitle = "QZTITLE link title"
	resPage  = "QZPAGE <script>alert(7)</script> fetched"
)

// seedPosts adds what the xposts collector stores (social_post events,
// raw records, the collector's health row), the allowlist they were
// collected for (one account since disabled) and draft posts.
func seedPosts(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('` + postAuthor + `', '` + postHandle + `', true),
			('` + post2Author + `', '` + post2Handle + `', true), ('` + goneAuthor + `', '` + goneHandle + `', false),
			('` + evilAuthor + `', 'QzEvilAccount', true)`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	post := func(cve, id, author, handle, text string, at time.Time, u string) {
		if u == "" {
			u = "https://x.com/" + handle + "/status/" + id
		}
		h, _ := json.Marshal(handle)
		tx, _ := json.Marshal(text)
		s.Event(sitetest.Ev{CVE: cve, Type: "social_post", Source: "xposts", Occurred: sitetest.P(at),
			Observed: at, URL: &u, Key: id,
			Detail: `{"post_id": "` + id + `", "author_id": "` + author + `", "author_handle": ` + string(h) +
				`, "text": ` + string(tx) + `, "lang": "en", "cves": ["` + cve + `"]}`})
		s.Raw("xposts", id, "h-x-"+id, `{"post": {"id": "`+id+`", "text": `+string(tx)+`, "author_id": "`+author+
			`"}, "author": {"id": "`+author+`", "username": `+string(h)+`}}`, at)
	}
	now := sitetest.Now
	post(sitetest.GPU, postID1, postAuthor, postHandle, postText1, now.Add(-time.Hour), "")
	post(postCVE, postID2, postAuthor, postHandle, postText2, now.Add(-site.ResearcherWindow), "")
	post(sitetest.GPU, postID3, post2Author, post2Handle, "QZMARKER-THREE "+strings.Repeat("long ", 50), now.Add(-48*time.Hour), "")
	post(sitetest.GPU, postID4, goneAuthor, goneHandle, goneText, now.Add(-time.Hour), "")
	post(sitetest.GPU, postID5, postAuthor, postHandle, "QZMARKER-FIVE old", now.Add(-8*24*time.Hour), "")
	post(postCVE, postID6, post2Author, post2Handle, "QZMARKER-SIX just outside", now.Add(-site.ResearcherWindow-time.Second), "")
	post("CVE-2026-1001", postID7, post2Author, post2Handle, "QZMARKER-SEVEN", now.Add(-30*time.Minute), "")
	post(stubA, postID8, post2Author, post2Handle, "QZMARKER-EIGHT short one", now.Add(-40*time.Minute), "")
	post(stubB, postID9, post2Author, post2Handle, "QZMARKER-NINE different!", now.Add(-40*time.Minute), "")
	post(sitetest.GPU, postIDEvil, evilAuthor, evilHandle, evilText, now.Add(-3*time.Hour), "javascript:alert(4)")
	link := func(id string, pos int, short, final, kind string) {
		if _, err := conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, title, origin, status)
VALUES ($1, $2, $3, $4, $4, 'h.example', $5, 'QZTITLE link title', 'api', 'ok')`, id, pos, short, final, kind); err != nil {
			t.Fatal(err)
		}
	}
	link(postID1, 0, "https://t.co/QZSHORT01", resURL+"/", "patch")
	link(postID1, 1, "https://t.co/QZSHORT02", "https://pbs.twimg.com/media/QZMEDIA.jpg", "media")
	link(postID1, 2, "https://t.co/QZSHORT03", "javascript:alert(5)", "other")
	link(postID3, 0, "https://t.co/QZSHORT04", resURL, "patch") // first seen (older post)
	link(postID3, 1, "https://t.co/QZSHORT05", resEvil, "other")
	link(postID4, 0, "https://t.co/QZSHORT06", "https://qzgone.example/x", "other")
	evilKey, _ := site.ResourceKey(resEvil)
	resKey, _ := site.ResourceKey(resURL)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE x_post_link SET title = NULL WHERE final_url = $1`, []any{resEvil}},
		{`INSERT INTO web_page (url_key, url, first_source, status, title) VALUES ($1, $2, 'xposts', 'ok', $3), ($4, $5, 'xposts', 'ok', 'QZFETCHED loses')`,
			[]any{evilKey, resEvil, resPage, resKey, resURL}},
	} {
		if _, err := conn.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	s.Collector("xposts", "error", sitetest.P(sitetest.Ago(0.001)), sitetest.P(sitetest.Ago(0.002)), sitetest.P(postErr))
	seedDrafts(t, conn)
	s.Refresh()
}

// seedDrafts stores draft posts in every state (pending, posted with a post
// URL, discarded) on public CVEs, and the generator's watermark.
func seedDrafts(t *testing.T, conn *pgx.Conn) {
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO x_draft (cve_id, stage, event_id, body) VALUES ('` + sitetest.GPU + `', 'kev_added', 1, '` + draftText + ` +KEV')`,
		`INSERT INTO x_draft (cve_id, stage, event_id, body, status, post_url, decided_at)
			VALUES ('` + sitetest.GPU + `', 'poc_published', 2, '` + draftText + ` +POC', 'posted', 'https://x.com/ndayland/status/` + draftPost + `', now())`,
		`INSERT INTO x_draft (cve_id, stage, event_id, body, status, decided_at)
			VALUES ('` + postCVE + `', 'exploited_in_wild', 3, '` + draftText + ` +ITW', 'discarded', now())`,
		`INSERT INTO x_draft_state (id, last_event_id, last_run_at, last_run) VALUES (1, 999999, now(), '{"created": 3}')`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// newEnvSeeded is newEnvFull without t.Parallel, with extra seeding.
func newEnvSeeded(t *testing.T, extra func(*testing.T, *pgx.Conn)) *tenv {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	seedHostile(t, d.Conn)
	// The stub row a post creates (pipeline ensureStub); present in both
	// environments so the comparison isolates what the post itself adds.
	sitetest.Seeder{T: t, Conn: d.Conn}.Vuln(postCVE, nil)
	if extra != nil {
		extra(t, d.Conn)
	}
	// the last state refresh is wall-clock time (shown on /src, /stats and
	// in the JSON); pin it so the two databases compare equal
	if _, err := d.Conn.Exec(context.Background(), `UPDATE vuln_state_refresh SET refreshed_at = $1 WHERE id = 1`,
		sitetest.Now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 3, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	srv := web.New(web.Config{Store: site.New(pool).WithClock(now), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ui, err := webui.New(srv, webui.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui}
}

// memberEnv is the site with sign-in, discussions and the researcher
// section, in two-host mode (www.nday.land and api.nday.land), over a
// database with the fixture, posts and a comment.
type memberEnv struct {
	ts  *httptest.Server
	ui  *webui.UI
	idp *fakeidp.IDP
	as  *auth.Store
	ds  *discuss.Service
}

const (
	wwwOrigin = "https://www.nday.land"
	wwwHost   = "www.nday.land"
	apiHost   = "api.nday.land"
)

func newMemberEnv(t *testing.T, withPosts bool) (*memberEnv, *pgx.Conn) {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	seedHostile(t, d.Conn)
	// the stub rows posts create (pipeline ensureStub): in both databases, so
	// a comparison isolates what the posts themselves add (an accepted trace,
	// docs/xposts.md)
	for _, cve := range []string{postCVE, stubA, stubB} {
		sitetest.Seeder{T: t, Conn: d.Conn}.Vuln(cve, nil)
	}
	if withPosts {
		seedPosts(t, d.Conn)
	}
	// wall-clock columns that public responses show (the sitemap's lastmod,
	// the state refresh time) are pinned so the two databases compare equal;
	// the posts keep their insertion time, later than everything else
	for _, q := range []string{`UPDATE vuln_state_refresh SET refreshed_at = $1 WHERE id = 1`, `UPDATE vuln SET updated_at = $1`,
		`UPDATE event SET created_at = $1 WHERE type <> 'social_post'`} {
		if _, err := d.Conn.Exec(context.Background(), q, sitetest.Now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 4, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	idp := fakeidp.New()
	t.Cleanup(idp.Server.Close)
	acfg := &auth.Config{PublicOrigin: wwwOrigin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, SessionIdle: 24 * time.Hour, SessionMax: 48 * time.Hour,
		HandleHold: time.Hour, RPID: "nday.land", Origins: []string{wwwOrigin}}
	creds := auth.ProviderCredentials{ClientID: "client-github", ClientSecret: "secret-github"}
	acfg.Providers[auth.GitHub] = creds
	idp.Register(auth.GitHub, fakeidp.Client{ID: creds.ClientID, Secret: creds.ClientSecret, RedirectURI: acfg.RedirectURI(auth.GitHub)})
	as := &auth.Store{DB: pool}
	big := func() *auth.RateLimiter { return auth.NewRateLimiter(100000, time.Millisecond) }
	asvc, err := auth.New(acfg, auth.Options{Store: as, Logger: log, Client: idp.Server.Client(), Endpoints: idp.Endpoints(),
		StartLimit: big(), CallbackLimit: big(), PasskeyLimit: big(), AccountLimit: big(), TokenLimit: big(), SessionLookups: 4})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return sitetest.Now }
	store := site.New(pool).WithClock(now)
	// pinning off: its fill pins every discussed CVE (site/pin.go, the same
	// public aggregate as /discussed), which would reorder the hot list of
	// the database with posts; site's pin tests cover pinning
	store.SetPinConfig(site.PinConfig{Max: 0, MinResearchers: 2, Recent: 72 * time.Hour, Wave: 7 * 24 * time.Hour})
	lim := discuss.DefaultLimits()
	lim.ReadBurst = 100000
	// signed-out reading of the comments off: this environment checks
	// that nothing but the outline is public then (TestGuestCommentsPublic
	// covers reading on)
	lim.GuestRead = false
	ds, err := discuss.New(discuss.Options{Store: &discuss.Store{DB: pool}, Auth: asvc, Logger: log, Limits: &lim})
	if err != nil {
		t.Fatal(err)
	}
	srv := web.New(web.Config{Store: store, Logger: log, PublicURL: wwwOrigin, APIURL: "https://" + apiHost})
	asvc.Register(srv)
	ds.Register(srv)
	posts.New(posts.Options{Auth: asvc, Store: store, Logger: log, ReadBurst: 100000, ReadEvery: time.Millisecond}).Register(srv)
	ui, err := webui.New(srv, webui.Options{Now: now, Accounts: webui.AccountsOf(asvc), Discussions: webui.DiscussionsOf(ds)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &memberEnv{ts: ts, ui: ui, idp: idp, as: as, ds: ds}, d.Conn
}

// fetch is a GET with a Host and optional cookies; redirects are not followed.
func (e *memberEnv) fetch(t *testing.T, host, path string, cookies []*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("CF-Connecting-IP", "198.51.100.9")
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// signIn signs a new GitHub account in, gives it handle (if not ""), and
// returns its cookies and id.
func (e *memberEnv) signIn(t *testing.T, sub, handle string) ([]*http.Cookie, string) {
	t.Helper()
	jar := map[string]*http.Cookie{}
	do := func(path string) *http.Response {
		var cs []*http.Cookie
		for _, c := range jar {
			cs = append(cs, c)
		}
		resp, _ := e.fetch(t, wwwHost, path, cs)
		for _, c := range resp.Cookies() {
			if c.MaxAge < 0 {
				delete(jar, c.Name)
			} else {
				jar[c.Name] = c
			}
		}
		return resp
	}
	resp := do("/auth/github/start?return=/")
	cb, err := e.idp.Approve(auth.GitHub, resp.Header.Get("Location"), fakeidp.Account{Subject: sub, Name: sub, Username: sub})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cb)
	if resp := do(u.RequestURI()); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	var cs []*http.Cookie
	for _, c := range jar {
		cs = append(cs, c)
	}
	_, me := e.fetch(t, wwwHost, "/api/me", cs)
	var m struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(me), &m); err != nil || m.User.ID == "" {
		t.Fatalf("/api/me: %s", me)
	}
	if handle != "" {
		key, err := auth.CanonicalHandle(handle)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.as.SetHandle(context.Background(), m.User.ID, handle, key, 0); err != nil {
			t.Fatal(err)
		}
	}
	return cs, m.User.ID
}

// Comments of the differential test, with fixed ids so both databases
// answer the same URLs: a thread with a reply, a hidden thread with a
// reply, a deleted thread with a reply.
const (
	cmT1 = "0b141010-ef0f-49ba-b9bd-2f476f8923bb"
	cmR1 = "44583087-828d-4c12-bfe1-cd9a01288cba"
	cmT2 = "5d1c2a6e-1b2c-4d5e-8f90-0a1b2c3d4e5f"
	cmR2 = "6e2d3b7f-2c3d-4e5f-9a01-1b2c3d4e5f60"
	cmT3 = "7f3e4c80-3d4e-4f60-8b12-2c3d4e5f6071"
	cmR3 = "80405d91-4e5f-4071-9c23-3d4e5f607182"
)

var cmAt = sitetest.Now.Add(-2 * time.Hour)

// cmCursor is the discussion cursor after comment id created at at
// (discuss.encodeCursor).
func cmCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMicro(), 10) + "." + id))
}

// seedComments signs a commenter in (handle) and stores the comments with
// word in every body (the same size classes whatever word is).
func seedComments(t *testing.T, e *memberEnv, conn *pgx.Conn, word, handle string) []*http.Cookie {
	t.Helper()
	cookies, uid := e.signIn(t, "9001", handle)
	ins := func(id string, parent *string, body, status string, at time.Time) {
		var hiddenAt, deletedAt *time.Time
		var reason *string
		switch status {
		case "hidden":
			hiddenAt, reason = &at, sitetest.P("QZCOMMENT-REASON")
		case "deleted":
			deletedAt = &at
		}
		if _, err := conn.Exec(context.Background(), `INSERT INTO comments (id, cve_id, parent_id, is_reply, author_id, body, lang, links,
			status, hidden_at, hidden_reason, deleted_at, created_at, updated_at)
			VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, 'en', true, $7, $8, $9, $10, $11, $11)`,
			id, sitetest.GPU, parent, parent != nil, uid, body, status, hiddenAt, reason, deletedAt, at); err != nil {
			t.Fatal(err)
		}
	}
	ins(cmT1, nil, word+" first comment", "visible", cmAt)
	ins(cmR1, sitetest.P(cmT1), word+" reply "+strings.Repeat("a", 200), "visible", cmAt.Add(time.Second))
	ins(cmT2, nil, word+" hidden one", "hidden", cmAt.Add(2*time.Second))
	ins(cmR2, sitetest.P(cmT2), word+" under hidden", "visible", cmAt.Add(3*time.Second))
	ins(cmT3, nil, word+" deleted one", "deleted", cmAt.Add(4*time.Second))
	ins(cmR3, sitetest.P(cmT3), word+" under deleted", "visible", cmAt.Add(5*time.Second))
	return cookies
}

// Public by design (site/public.go, docs/discuss.md §4.1): stripped before
// the two databases are compared, narrowly.
var (
	stripRsch      = regexp.MustCompile(`,"researchers_7d":\d+`)
	stripBadge     = regexp.MustCompile(` <span class="tag rsch-b" title="[^"]*"><span aria-hidden="true">@\d+</span><span class="sr">[^<]*</span></span>`)
	stripSection   = regexp.MustCompile(`(?s)<section class="sec disc rsch" id="research".*?</section>`)
	stripResources = regexp.MustCompile(`(?s)\n\n<section class="panel rsrc" id="resources".*?</section>\n`)
	resourcesSecRe = regexp.MustCompile(`(?s)<section class="panel rsrc" id="resources".*?</section>`)
	researchSecRe  = stripSection
	publicByDesign = regexp.MustCompile(`^(/[a-z-]+)?/discussed(\?|$)|^/v1/discussed|^/api/discussed|^/api/posts/`)
)

// publicHandles are the names the outline makes public (enabled accounts
// with valid handles); they may appear in the research section of a
// vulnerability page and in the signed-out /api/posts body, nowhere else.
var publicHandles = []string{postHandle, post2Handle}

// TestPostsNotPublic: with X posts, an allowlist (one account disabled),
// comments (a reply, a hidden and a deleted thread) and draft posts stored,
// compared with a database that has no posts and other comment texts of the
// same sizes by another commenter:
//
//   - every signed-out response — every HTML page reachable by crawling in
//     every enabled locale, the feeds, the sitemap index and every shard,
//     share cards, raw records, the JSON API on both hosts and the
//     auth-class /api/posts and /api/discuss with real ?c=, thread= and
//     cursor= values — is byte-identical between the two, except for the
//     parts public by design (stripped narrowly: researchers_7d, the @N
//     badge, the research section, /discussed and its JSON, the signed-out
//     /api/posts body);
//   - no signed-out response anywhere contains post text, post ids or URLs,
//     author ids, a disabled account's handle, the hostile handle, comment
//     bodies, hide reasons or commenter handles; enabled authors' handles
//     appear only in the research section and the /api/posts outline;
//   - a signed-in client gets the content.
func TestPostsNotPublic(t *testing.T) {
	e, conn := newMemberEnv(t, true)
	cookies := seedComments(t, e, conn, "QZCOMMENT-BODY", commenter)
	base, bconn := newMemberEnv(t, false)
	seedComments(t, base, bconn, "QZCOMMENT-ALTB", commenterB)
	markers := append(append([]string(nil), postMarkers...), commenterB, "QZCOMMENT-REASON")

	set := e.ui.Locales()
	q := url.QueryEscape
	g := "/vuln/" + sitetest.GPU
	extra := []string{"/vuln/" + postCVE, "/vuln/" + stubA, "/discussed", "/discussed?offset=50", "/vuln?q=" + q(postHandle),
		"/vuln?q=" + q("QZMARKER-TEXT-ONE"), "/vuln?q=" + q(postCVE), "/vuln?q=" + q(postID1), "/vuln?q=" + q("QZDRAFT-BODY"),
		"/vuln?q=" + q("QZCOMMENT"), "/feed.xml", g + "?c=" + cmT1, g + "?c=" + cmR1 + "#c-" + cmR1, g + "?c=" + cmR2,
		g + "?thread=" + cmT1 + "&rcursor=" + cmCursor(cmAt.Add(time.Second), cmR1), g + "?cursor=" + cmCursor(cmAt, cmT1),
		g + "?c=00000000-0000-4000-8000-000000000000", g + "?fresh=1", g + "?research", g + "?discussion"}
	type req struct {
		host, path string
	}
	var start []req
	for _, l := range set.Enabled {
		for _, p := range append(append([]string(nil), pages...), extra...) {
			start = append(start, req{wwwHost, l.Path(p)})
		}
	}
	dq := "/api/discuss/" + sitetest.GPU
	for _, p := range []string{"/sitemap.xml", "/sitemap/pages.xml", "/robots.txt",
		"/og/vuln/" + sitetest.GPU + ".png", "/og/vuln/" + postCVE + ".png", "/og/vuln/" + stubA + ".png",
		// auth-class endpoints, signed out, whatever the query asks
		"/api/posts/" + sitetest.GPU, "/api/posts/" + postCVE, "/api/posts/" + stubA, "/api/posts/" + sitetest.GPU + "?all=1",
		dq, dq + "?limit=200&locale=ja", dq + "?c=" + cmR1, dq + "?thread=" + cmT1 + "&cursor=" + cmCursor(cmAt.Add(time.Second), cmR1),
		dq + "?cursor=" + cmCursor(cmAt, cmT1), dq + "?thread=" + cmT2, "/api/me",
		// data routes on the site host (308 to the API host)
		"/api/hot", "/api/discussed", "/raw/xposts/" + postID1 + ".json"} {
		start = append(start, req{wwwHost, p})
	}
	for _, p := range []string{"/", "/v1", "/v1/hot", "/v1/hot?since=1d&min_stage=disclosed", "/v1/hot?since=366d&min_stage=disclosed&include_rejected=1&limit=200",
		"/v1/hot?since=366d&min_stage=disclosed&limit=2", "/v1/discussed", "/v1/discussed?limit=1&offset=1", "/v1/discussed?limit=200",
		"/v1/vuln/" + sitetest.GPU, "/v1/vuln/" + postCVE, "/v1/vuln/" + stubA, "/v1/sources", "/v1/stats", "/v1/tags", "/healthz",
		"/v1/search?q=" + q(postHandle), "/v1/search?q=" + q("QZMARKER"), "/v1/search?q=" + q(postCVE), "/v1/search?q=" + q(postID1),
		"/v1/search?q=2026", "/v1/search?q=" + q("QZDRAFT-BODY"), "/v1/search?q=" + q(draftPost), "/v1/search?q=" + q("QZCOMMENT"),
		"/v1/raw/xposts/" + postID1 + ".json", "/v1/raw/xposts/" + postID2 + ".json", "/v1/raw/kev/" + sitetest.GPU + ".json",
		"/v1/raw/cvelist/" + postCVE + ".json", "/api/posts/" + sitetest.GPU, "/api/discuss/" + sitetest.GPU} {
		start = append(start, req{apiHost, p})
	}
	const maxCrawl = 30000
	// breadth-first to depth maxDepth from the start list (every route of
	// the site is in it or one or two links away; deeper levels only
	// combine filters); deduplicated when queued
	const maxDepth = 2
	seen := map[req]bool{}
	depth := map[req]int{}
	queue := []req{}
	push := func(r req, d int) {
		if _, ok := depth[r]; ok || d > maxDepth {
			return
		}
		depth[r] = d
		queue = append(queue, r)
	}
	for _, r := range start {
		push(r, 0)
	}
	shardRe := regexp.MustCompile(`<loc>https://www\.nday\.land(/sitemap/[^<]+)</loc>`)
	compared := 0
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if seen[r] {
			continue
		}
		if len(seen) >= maxCrawl {
			t.Fatalf("crawl reached its cap of %d responses with %d queued: coverage would be partial; raise maxCrawl", maxCrawl, len(queue))
		}
		seen[r] = true
		resp, body := e.fetch(t, r.host, r.path, nil)
		bresp, bbody := base.fetch(t, r.host, r.path, nil)
		path, _, _ := strings.Cut(r.path, "?")
		isVulnPage := r.host == wwwHost && regexp.MustCompile(`^(/[a-z-]+)?/vuln/CVE-`).MatchString(path)
		isPostsAPI := r.host == wwwHost && strings.HasPrefix(path, "/api/posts/")

		// 1. markers: the research section and the signed-out /api/posts
		// body may name enabled authors; nothing else may name anyone
		scan := strings.ToLower(body)
		if u, err := url.Parse(r.path); err == nil {
			echo := u.Query().Get("q")
			if ret, err := url.Parse(u.Query().Get("return")); err == nil && echo == "" {
				echo = ret.Query().Get("q") // the sign-in page of a search page echoes it in its return links
			}
			if echo != "" {
				for _, v := range []string{echo, url.QueryEscape(echo), url.QueryEscape(url.QueryEscape(echo))} {
					scan = strings.ReplaceAll(scan, strings.ToLower(v), "")
				}
			}
		}
		allowed := func(m string) bool {
			for _, h := range publicHandles {
				if strings.EqualFold(m, h) {
					return true
				}
			}
			return false
		}
		check := func(where, text string, names bool) {
			if names { // the public names themselves are not a leak (QZMARKER is a prefix of one)
				for _, h := range publicHandles {
					text = strings.ReplaceAll(text, strings.ToLower(h), "")
				}
			}
			for _, m := range markers {
				if names && allowed(m) {
					continue
				}
				if strings.Contains(text, strings.ToLower(m)) {
					t.Errorf("%s%s%s: signed-out response contains %q", r.host, r.path, where, m)
				}
			}
		}
		switch {
		case isVulnPage:
			sec := researchSecRe.FindString(scan)
			check(" (research section)", sec, true)
			rest := strings.Replace(scan, sec, "", 1)
			// the resources panel may show the link titles (exactly), nothing else
			if rsec := resourcesSecRe.FindString(rest); rsec != "" {
				shown := rsec
				for _, ti := range []string{resTitle, html.EscapeString(resPage)} {
					shown = strings.ReplaceAll(shown, strings.ToLower(ti), "")
				}
				check(" (resources section)", shown, false)
				rest = strings.Replace(rest, rsec, "", 1)
			}
			check("", rest, false)
		case isPostsAPI:
			check("", scan, true)
		default:
			check("", scan, false)
		}

		// 2. the differential comparison, public-by-design parts stripped
		if !publicByDesign.MatchString(r.path) {
			a, b := body, bbody
			for _, re := range []*regexp.Regexp{stripRsch, stripBadge, stripSection, stripResources} {
				a, b = re.ReplaceAllString(a, ""), re.ReplaceAllString(b, "")
			}
			if resp.StatusCode != bresp.StatusCode || a != b {
				t.Errorf("%s%s: response differs with posts stored (status %d vs %d)\n--- with\n%s\n--- without\n%s",
					r.host, r.path, resp.StatusCode, bresp.StatusCode, truncBody(diffAt(a, b)), truncBody(diffAt(b, a)))
			}
			compared++
		}

		// follow
		if loc := resp.Header.Get("Location"); loc != "" && strings.HasPrefix(loc, "https://"+apiHost+"/") {
			push(req{apiHost, strings.TrimPrefix(loc, "https://"+apiHost)}, depth[r])
		}
		for _, m := range shardRe.FindAllStringSubmatch(body, -1) {
			push(req{wwwHost, m[1]}, depth[r])
		}
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			links, _ := CheckHTML(body)
			for _, l := range links {
				if strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "//") && !strings.HasPrefix(l, "/auth/") {
					push(req{wwwHost, l}, depth[r]+1)
				}
			}
		}
	}
	for _, l := range set.Enabled {
		for _, must := range []string{"/feed.xml", "/src", "/stats", "/discussed", "/vuln/" + sitetest.GPU, "/vuln/" + postCVE} {
			if !seen[req{wwwHost, l.Path(must)}] {
				t.Errorf("crawl did not reach %s", l.Path(must))
			}
		}
	}
	shards := 0
	for r := range seen {
		if strings.HasPrefix(r.path, "/sitemap/vuln-") {
			shards++
		}
	}
	if shards == 0 || !seen[req{wwwHost, "/sitemap/vuln-2026-0.xml"}] {
		t.Errorf("crawl fetched %d vulnerability sitemap shards", shards)
	}
	t.Logf("checked %d signed-out responses, %d compared with the database without posts, %d sitemap shards", len(seen), compared, shards)

	// The vuln sitemap shard of GPU (whose posts were collected after its
	// other events) is the same without posts (lastmod reads public events
	// only).
	shard := "/sitemap/vuln-2026-" + strconv.Itoa(102895/site.SitemapSpan) + ".xml" // GPU's
	_, s1 := e.fetch(t, wwwHost, shard, nil)
	_, s2 := base.fetch(t, wwwHost, shard, nil)
	if s1 != s2 || !strings.Contains(s1, sitetest.GPU) || !seen[req{wwwHost, shard}] {
		t.Errorf("sitemap shard differs with posts stored:\n%s\n%s", truncBody(diffAt(s1, s2)), truncBody(diffAt(s2, s1)))
	}

	// A guessed raw URL of a post is indistinguishable from an unknown source.
	r1, b1 := e.fetch(t, apiHost, "/v1/raw/xposts/"+postID1+".json", nil)
	r2, b2 := e.fetch(t, apiHost, "/v1/raw/nosuchsource/"+postID1+".json", nil)
	if r1.StatusCode != r2.StatusCode || b1 != b2 || r1.Header.Get("Cache-Control") != r2.Header.Get("Cache-Control") {
		t.Errorf("raw xposts %d %q != unknown source %d %q", r1.StatusCode, b1, r2.StatusCode, b2)
	}

	// The vulnerability page is the same bytes signed in and out, and its
	// research section names the enabled authors (public), not the disabled
	// one, and the hostile handle only as the neutral name.
	_, out := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	_, in := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, cookies)
	if out != in {
		t.Error("the vulnerability page differs for a signed-in visitor")
	}
	sec := researchSecRe.FindString(out)
	for _, w := range []string{`<a class="rp-au" href="https://x.com/` + postHandle + `" rel="noopener noreferrer nofollow">@` + postHandle + `</a>`,
		`@` + post2Handle + `</a>`, `<span class="rp-au weak">researcher</span>`, "Post by @" + postHandle + " on 2026-11-13. Sign in to read it.",
		"Post by a researcher on 2026-11-12. Sign in to read it."} {
		if !strings.Contains(sec, w) {
			t.Errorf("research section lacks %q:\n%s", w, sec)
		}
	}

	// The resources section (public): the links' final URLs, the titles of
	// the linked pages (API title first, else the fetched one) with the
	// host, the number of researchers, escaped; no author, short link,
	// media link or a disabled author's link (the markers above are checked
	// everywhere, titles everywhere outside this panel).
	res := resourcesSecRe.FindString(out)
	for _, w := range []string{`<a href="` + resURL + `" title="` + resURL + `" dir="auto" rel="noopener noreferrer nofollow ugc">` + resTitle +
		`</a> <span class="rsrc-host">h.example</span> <span class="rsrc-n">2 researchers</span>`,
		`href="https://res.example/a?x=1&amp;y=%22%3e%3cscript%3ealert%286%29%3c/script%3e"`,
		`title="https://res.example/a?x=1&amp;y=&#34;&gt;&lt;script&gt;alert(6)&lt;/script&gt;"`,
		`>QZPAGE &lt;script&gt;alert(7)&lt;/script&gt; fetched</a> <span class="rsrc-host">h.example</span>`,
		`>Patches</h3>`, `>Articles and other links</h3>`} {
		if !strings.Contains(res, w) {
			t.Errorf("resources section lacks %q:\n%s", w, res)
		}
	}
	if strings.Contains(res, "<script>") || strings.Contains(res, "javascript:") || strings.Contains(res, "@") || strings.Contains(res, "x.com") {
		t.Errorf("resources section:\n%s", res)
	}
	// in the side column (below the raw records panel), outside the
	// research section that names authors
	if i := strings.Index(out, `id="resources"`); i > strings.Index(out, "</aside>") || i > strings.Index(out, `id="research"`) {
		t.Error("the resources panel is not in the side column before the research section")
	}
	_, other := e.fetch(t, wwwHost, "/vuln/"+postCVE, nil)
	if strings.Contains(other, `id="resources"`) {
		t.Error("a resources section without links")
	}

	// Signed in: the content is there, as data.
	resp, body := e.fetch(t, wwwHost, "/api/posts/"+sitetest.GPU, cookies)
	t.Logf("signed-in GET /api/posts/%s: %s", sitetest.GPU, body)
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != posts.CacheControl {
		t.Errorf("signed-in posts: %d %v", resp.StatusCode, resp.Header)
	}
	var pr posts.Response
	if err := json.Unmarshal([]byte(body), &pr); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range pr.Posts {
		ids = append(ids, p.PostID)
	}
	// newest first; the disabled account's post is absent; the 8-day-old one is listed
	if want := postID1 + "," + postIDEvil + "," + postID3 + "," + postID5; strings.Join(ids, ",") != want || !pr.SignedIn ||
		pr.Researchers != 3 || pr.Count != 4 || pr.Outline != nil {
		t.Errorf("signed-in posts: ids %v, want %s; %+v", ids, want, pr)
	}
	if p := pr.Posts[0]; p.Text != postText1 || p.AuthorHandle != postHandle || p.AuthorURL == nil || *p.AuthorURL != "https://x.com/"+postHandle ||
		p.URL == nil || *p.URL != "https://"+postURLPath+postID1 || p.Lang != "en" || !p.PostedAt.Equal(sitetest.Now.Add(-time.Hour)) {
		t.Errorf("post 1: %+v", p)
	}
	// hostile post: the text as it was posted (data, never markup), no
	// profile link for an invalid handle, the post link rebuilt from the id
	if p := pr.Posts[1]; p.Text != evilText || p.AuthorHandle != evilHandle || p.AuthorURL != nil || p.URL == nil ||
		*p.URL != "https://x.com/i/web/status/"+postIDEvil {
		t.Errorf("hostile post: %+v", p)
	}
	if strings.Contains(body, goneText) || strings.Contains(body, goneHandle) {
		t.Error("a disabled account's post is shown")
	}
	// each post's resolved links, in order (the client links only http/https)
	var ls []string
	for _, l := range pr.Posts[0].Links {
		ls = append(ls, l.ShortURL+">"+l.FinalURL+"|"+l.Host+"|"+l.Kind)
	}
	if got, want := strings.Join(ls, " "), "https://t.co/QZSHORT01>"+resURL+"/|h.example|patch "+
		"https://t.co/QZSHORT02>https://pbs.twimg.com/media/QZMEDIA.jpg|h.example|media https://t.co/QZSHORT03>javascript:alert(5)|h.example|other"; got != want {
		t.Errorf("signed-in links of post 1:\n%s\nwant\n%s", got, want)
	}
	if pr.Posts[1].Links == nil || len(pr.Posts[1].Links) != 0 || !strings.Contains(body, `"links":[]`) {
		t.Errorf("a post without links: %+v", pr.Posts[1].Links)
	}
	_, body = e.fetch(t, wwwHost, "/api/discuss/"+sitetest.GPU, cookies)
	if !strings.Contains(body, "QZCOMMENT-BODY first comment") || !strings.Contains(body, `"handle":"`+commenter+`"`) {
		t.Errorf("signed-in discussion lacks the comment: %s", body)
	}

	// Signed out: the outline only — author name and link, day, size class.
	resp, body = e.fetch(t, wwwHost, "/api/posts/"+sitetest.GPU, nil)
	t.Logf("signed-out GET /api/posts/%s: %s", sitetest.GPU, body)
	want := `{"cve":"` + sitetest.GPU + `","signed_in":false,"researchers_7d":3,"count":4,"posts":[],"outline":[` +
		`{"author":"` + postHandle + `","author_url":"https://x.com/` + postHandle + `","size":"s","day":"2026-11-13"},` +
		`{"author":"","author_url":null,"size":"s","day":"2026-11-12"},` +
		`{"author":"` + post2Handle + `","author_url":"https://x.com/` + post2Handle + `","size":"l","day":"2026-11-11"},` +
		`{"author":"` + postHandle + `","author_url":"https://x.com/` + postHandle + `","size":"s","day":"2026-11-05"}]}`
	if strings.TrimSpace(body) != want || resp.Header.Get("Cache-Control") != posts.CacheControl ||
		!strings.Contains(strings.Join(resp.Header.Values("Vary"), ","), "Cookie") {
		t.Errorf("signed-out posts:\n got %s\nwant %s\n%v", body, want, resp.Header)
	}
	// placeholders depend on author, size class and date only: two stubs
	// with different texts of one size class by the same author, posted at
	// the same time
	_, oa := e.fetch(t, wwwHost, "/api/posts/"+stubA, nil)
	_, ob := e.fetch(t, wwwHost, "/api/posts/"+stubB, nil)
	if strings.ReplaceAll(oa, stubA, "X") != strings.ReplaceAll(ob, stubB, "X") {
		t.Errorf("outline payloads differ: %s / %s", oa, ob)
	}
	_, pa := e.fetch(t, wwwHost, "/vuln/"+stubA, nil)
	_, pb := e.fetch(t, wwwHost, "/vuln/"+stubB, nil)
	sa := between(t, pa, `<section class="sec disc rsch" id="research"`, "</section>")
	sb := between(t, pb, `<section class="sec disc rsch" id="research"`, "</section>")
	if strings.ReplaceAll(sa, stubA, "X") != strings.ReplaceAll(sb, stubB, "X") || !strings.Contains(sa, "@"+post2Handle) {
		t.Errorf("placeholder sections differ:\n%s\n%s", sa, sb)
	}
	// the auth-class endpoint stays on the public host
	if r, _ := e.fetch(t, apiHost, "/api/posts/"+sitetest.GPU, cookies); r.StatusCode != 404 {
		t.Errorf("/api/posts on the API host: %d", r.StatusCode)
	}
	// another host never reaches the handler: web.Server sends a GET to the public
	// origin (308, foreign.go); the 421 wrong_host of the handler itself is for a
	// request the server lets through.
	if r, b := e.fetch(t, "evil.example", "/api/posts/"+sitetest.GPU, cookies); r.StatusCode != http.StatusPermanentRedirect ||
		r.Header.Get("Location") != wwwOrigin+"/api/posts/"+sitetest.GPU || len(b) != 0 && strings.Contains(string(b), "QZMARKER") {
		t.Errorf("/api/posts on another host: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	for p, code := range map[string]int{"/api/posts/x": 400, "/api/posts/CVE-2099-99999": 404, "/api/posts/": 404, "/api/posts/a/b": 404} {
		if r, b := e.fetch(t, wwwHost, p, nil); r.StatusCode != code || r.Header.Get("Cache-Control") != posts.CacheControl {
			t.Errorf("%s: %d %v %s", p, r.StatusCode, r.Header, b)
		}
	}
}

// TestGuestCommentsPublic: with signed-out reading on, a signed-out
// GET /api/discuss gives the visible comments (bodies, the commenter's
// handle) and none of the hidden or deleted ones, nor a hide reason; the
// vulnerability page itself still holds no comment and is the same signed
// in and out.
func TestGuestCommentsPublic(t *testing.T) {
	e, conn := newMemberEnv(t, false)
	cookies := seedComments(t, e, conn, "QZCOMMENT-BODY", commenter)
	lim := e.ds.Limits()
	lim.GuestRead = true
	e.ds.SetLimits(lim)
	dq := "/api/discuss/" + sitetest.GPU
	for _, q := range []string{"", "?c=" + cmR1, "?c=" + cmR2, "?thread=" + cmT1, "?thread=" + cmT2, "?thread=" + cmT3,
		"?cursor=" + cmCursor(cmAt, cmT1), "?limit=200&locale=ja"} {
		resp, body := e.fetch(t, wwwHost, dq+q, nil)
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", q, resp.StatusCode, resp.Header)
		}
		for _, bad := range []string{"QZCOMMENT-BODY hidden one", "QZCOMMENT-BODY deleted one", "QZCOMMENT-REASON", `"body":`, "moderation"} {
			if strings.Contains(body, bad) {
				t.Errorf("signed-out %s holds %q", q, bad)
			}
		}
	}
	_, body := e.fetch(t, wwwHost, dq, nil)
	for _, want := range []string{"QZCOMMENT-BODY first comment", "QZCOMMENT-BODY reply", "QZCOMMENT-BODY under hidden",
		"QZCOMMENT-BODY under deleted", `"handle":"` + commenter + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-out discussion lacks %q: %s", want, body)
		}
	}
	_, out := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	_, in := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, cookies)
	if out != in || strings.Contains(strings.ToLower(out), "qzcomment") || !strings.Contains(out, `data-guest="1"`) {
		t.Error("the vulnerability page differs signed in, holds a comment, or lacks data-guest")
	}
}

// diffAt returns a from a little before the first byte where it differs
// from b.
func diffAt(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return a[max(0, i-200):]
}

// TestResearcherCounts: the public count (hot rows, /discussed, the
// vulnerability page) is the number of distinct enabled authors with a post
// in [now-7d, now]; /discussed ranks by it, then by the latest post, then
// by CVE id, with offset paging; the hot list's order and cursor do not
// change with posts.
func TestResearcherCounts(t *testing.T) {
	e, _ := newMemberEnv(t, true)
	base, _ := newMemberEnv(t, false)
	type row struct {
		CVE   string  `json:"cve_id"`
		N     int     `json:"researchers_7d"`
		Stage *string `json:"stage"`
	}
	var page struct {
		Rows       []row `json:"rows"`
		NextOffset *int  `json:"next_offset"`
	}
	resp, body := e.fetch(t, apiHost, "/v1/discussed", nil)
	t.Logf("GET /v1/discussed: %s", body)
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("/v1/discussed: %d %v", resp.StatusCode, resp.Header)
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range page.Rows {
		got = append(got, r.CVE+"="+strconv.Itoa(r.N))
	}
	// GPU: A, B and the hostile account (the disabled one and the 8-day-old
	// post do not count); postCVE: A exactly 7 days ago (B one second
	// earlier does not count); ties by latest post, then CVE id
	want := sitetest.GPU + "=3,CVE-2026-1001=1," + stubA + "=1," + stubB + "=1," + postCVE + "=1"
	if strings.Join(got, ",") != want || page.NextOffset != nil {
		t.Errorf("discussed: %v, want %s", got, want)
	}
	if page.Rows[2].Stage != nil {
		t.Errorf("a stub has a stage: %+v", page.Rows[2])
	}
	// offset paging
	var all []string
	for off := 0; ; {
		_, b := e.fetch(t, apiHost, "/v1/discussed?limit=2&offset="+strconv.Itoa(off), nil)
		var p struct {
			Rows       []row `json:"rows"`
			NextOffset *int  `json:"next_offset"`
		}
		if err := json.Unmarshal([]byte(b), &p); err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Rows {
			all = append(all, r.CVE+"="+strconv.Itoa(r.N))
		}
		if p.NextOffset == nil {
			break
		}
		off = *p.NextOffset
		if off > 10 {
			t.Fatal("no end")
		}
	}
	if strings.Join(all, ",") != want {
		t.Errorf("paged: %v", all)
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?offset=-1", "?offset=10001", "?x=1"} {
		if r, _ := e.fetch(t, apiHost, "/v1/discussed"+q, nil); r.StatusCode != 400 {
			t.Errorf("/v1/discussed%s: %d", q, r.StatusCode)
		}
	}
	if r, _ := e.fetch(t, wwwHost, "/api/discussed?limit=2", nil); r.StatusCode != 308 ||
		r.Header.Get("Location") != "https://"+apiHost+"/v1/discussed?limit=2" {
		t.Errorf("/api/discussed on the site host: %d %v", r.StatusCode, r.Header)
	}

	// hot: same order and cursors as without posts; only the count is added
	strip := regexp.MustCompile(`,"researchers_7d":\d+`)
	for _, p := range []string{"/v1/hot?since=366d&min_stage=disclosed&include_rejected=1&limit=200", "/v1/hot?since=366d&min_stage=disclosed&limit=2"} {
		_, a := e.fetch(t, apiHost, p, nil)
		_, b := base.fetch(t, apiHost, p, nil)
		if !strings.Contains(a, `"cve_id":"`+sitetest.GPU+`"`) && strings.Contains(p, "limit=200") {
			t.Errorf("%s: no GPU row", p)
		}
		if strip.ReplaceAllString(a, "") != strip.ReplaceAllString(b, "") {
			t.Errorf("%s: hot list changed with posts\n%s\n%s", p, truncBody(a), truncBody(b))
		}
		if strings.Contains(p, "limit=200") {
			if !strings.Contains(a, `"cve_id":"`+sitetest.GPU+`"`) || !regexp.MustCompile(`"cve_id":"`+sitetest.GPU+`".*?"researchers_7d":3`).MatchString(a) {
				t.Errorf("hot GPU row lacks researchers_7d 3")
			}
		}
	}
	// pages: the badge on hot rows, the count on the vulnerability page
	_, hot := e.fetch(t, wwwHost, "/?since=30d&min_stage=disclosed", nil)
	if !strings.Contains(hot, `<span class="tag rsch-b" title="3 researchers mentioned this in the last 7 days"><span aria-hidden="true">@3</span>`) {
		t.Error("hot page: no badge")
	}
	_, hot0 := base.fetch(t, wwwHost, "/?since=30d&min_stage=disclosed", nil)
	if strings.Contains(hot0, "rsch-b") {
		t.Error("badge without posts")
	}
	_, v := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	sec := between(t, v, `<section class="sec disc rsch" id="research"`, "</section>")
	for _, w := range []string{"3 researchers mentioned this in the last 7 days", "Sign in to read 4 posts.",
		`<span class="spk" data-size="l" aria-hidden="true"></span>`, `<span class="rp-t">2026-11-05</span>`,
		`href="/login?return=%2Fvuln%2F` + sitetest.GPU + `%3Fresearch"`} {
		if !strings.Contains(sec, w) {
			t.Errorf("research section lacks %q:\n%s", w, sec)
		}
	}
	_, zh := e.fetch(t, wwwHost, "/zh-hans/discussed", nil)
	if !strings.Contains(zh, "研究员热议") || !strings.Contains(zh, `href="/zh-hans/vuln/`+stubA+`"`) || !strings.Contains(zh, `aria-current="page"`) {
		t.Error("/zh-hans/discussed")
	}
}
func truncBody(s string) string {
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}
