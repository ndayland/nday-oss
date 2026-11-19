package admin_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
)

// ghUsers is a GitHubLookup stub: known logins (case-insensitive) with
// their id and spelling; "ghost" does not exist; anything else fails like
// a network error.
func ghUsers(t *testing.T, known map[string]int64) func(context.Context, string) (int64, string, error) {
	return func(_ context.Context, login string) (int64, string, error) {
		for k, id := range known {
			if strings.EqualFold(k, login) {
				return id, k, nil
			}
		}
		if strings.EqualFold(login, "ghost") {
			return 0, "", ghrepo.ErrLoginNotFound
		}
		return 0, "", errors.New("dial tcp: i/o timeout")
	}
}

// ownerAudits lists "action:target_label" of the audit rows of trusted accounts.
func (h *harness) ownerAudits() string {
	h.t.Helper()
	var s *string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT string_agg(action || ':' || target_label, ' ' ORDER BY id) FROM admin_audit
        WHERE action LIKE 'github.owner.%'`).Scan(&s)
	if s == nil {
		return ""
	}
	return *s
}

// Trusted accounts: admins only (moderator 403, signed out 401, CSRF),
// login and field validation, duplicates, the effect on the review lists,
// the X link (set, change, clear, unknown handle, ON DELETE SET NULL),
// disable/enable, and an audit row for every change.
func TestGitHubOwners(t *testing.T) {
	h := newHarness(t, hopt{ghLookup: ghUsers(t, map[string]int64{"CAROL": 300})})
	r := h.ghFixture() // alice/CVE-2024-3094-poc unverified, bob/xz-lab rule, carol/fake-poc rejected by an admin
	carolTrusted := h.ghRepo(906, "carol/kept", "", 1, false, false, "2024-04-03", "search", "trusted", "admin")
	carolNew := h.ghRepo(907, "Carol/new-poc", "", 1, false, false, "2024-04-04", "search", "unverified", nil)
	h.sql(`UPDATE github_repo SET owner_id = 300 WHERE lower(owner_login) = 'carol'`)
	h.sql(`INSERT INTO x_accounts (user_id, handle) VALUES ('111', 'carol_x'), ('222', 'carol_alt')`)
	anon := h.browser()
	mod := h.user("mia", "moderator")
	adm := h.user("kim", "admin")

	resp, body := anon.post("/api/admin/github/owners", `{"login":"carol"}`)
	expect(t, "signed out", resp, body, 401, "not_signed_in")
	resp, body = mod.post("/api/admin/github/owners", `{"login":"carol"}`)
	expect(t, "moderator", resp, body, 403, "forbidden")
	resp, body = adm.post("/api/admin/github/owners", `{"login":"carol"}`, "X-CSRF-Token", "")
	expect(t, "no CSRF", resp, body, 403, "csrf")
	for _, bad := range []string{`{"login":""}`, `{"login":"-carol"}`, `{"login":"car_ol"}`, `{"login":"` + strings.Repeat("a", 40) + `"}`,
		`{"login":"a/b"}`} {
		resp, body = adm.post("/api/admin/github/owners", bad)
		expect(t, bad, resp, body, 400, "bad_login")
	}
	resp, body = adm.post("/api/admin/github/owners", `{"login":"carol","note":"a\nb"}`)
	expect(t, "bad note", resp, body, 400, "bad_note")
	resp, body = adm.post("/api/admin/github/owners", `{"login":"carol","x_handle":"no such!"}`)
	expect(t, "bad handle", resp, body, 400, "bad_handle")
	resp, body = adm.post("/api/admin/github/owners", `{"login":"carol","x_handle":"nobody"}`)
	expect(t, "unknown X handle", resp, body, 422, "x_not_listed")
	if n := h.count(`SELECT count(*) FROM github_trusted_owner`); n != 0 {
		t.Fatalf("refused requests listed %d accounts", n)
	}

	resp, body = adm.post("/api/admin/github/owners", `{"login":"@CAROL","note":"lab","x_handle":"@Carol_X"}`)
	expect(t, "add", resp, body, 200, "")
	// carol's undecided repository is trusted by 'owner'; the admin's decisions stay
	for id, want := range map[int64]string{carolNew: "trusted/owner", r.bad: "rejected/admin", carolTrusted: "trusted/admin",
		r.poc: "unverified/-", r.lab: "trusted/rule"} {
		if got := h.ghStatus(id); got != want {
			t.Errorf("row %d after add: %s, want %s", id, got, want)
		}
	}
	resp, body = adm.post("/api/admin/github/owners", `{"login":"carol"}`)
	expect(t, "duplicate", resp, body, 409, "owner_exists")
	var id string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT id::text FROM github_trusted_owner`).Scan(&id)
	if got := h.count(`SELECT count(*) FROM github_trusted_owner WHERE login = 'CAROL' AND owner_id = 300 AND x_user_id = '111' AND note = 'lab'`); got != 1 {
		t.Errorf("stored account: %d", got)
	}

	// the page: the list with the X link, the row's marker and origin flag
	_, page := adm.do("GET", "/admin/github", "")
	s := string(page)
	for _, pr := range checkHTML(s, adminElems) {
		t.Error(pr)
	}
	_, sec, ok := strings.Cut(s, `id="owners"`)
	if !ok {
		t.Fatal("no trusted accounts section")
	}
	sec, _, _ = strings.Cut(sec, "</section>")
	for _, w := range []string{"trusted accounts (1)", `<a href="https://github.com/CAROL" target="_blank" rel="noopener noreferrer nofollow" dir="ltr">CAROL</a>`,
		`<a href="/admin/x?q=carol_x#r-accounts">@carol_x</a>`, `<td class="r">1 / 3</td>`, `data-act="ghodisable" data-o="` + id + `"`,
		`name="x_handle" value="carol_x"`, `id="f-ghoadd"`} {
		if !strings.Contains(sec, w) {
			t.Errorf("owners section lacks %s\n%s", w, sec)
		}
	}
	_, trusted, _ := strings.Cut(s, `<details class="adm-hist" id="trusted">`)
	if row := rowOf(trusted, carolNew); !strings.Contains(row, "account trusted") || strings.Contains(row, `data-act="ghowner"`) {
		t.Errorf("owner-trusted row:\n%s", row)
	}
	if row := rowOf(s, r.poc); !strings.Contains(row, `data-act="ghowner" data-r="`+idStr(r.poc)+`"`) {
		t.Errorf("unlisted owner's row has no quick add:\n%s", row)
	}
	// the X page marks the linked account, admin only
	_, xp := adm.do("GET", "/admin/x", "")
	if !strings.Contains(string(xp), `<a class="adm-st" href="/admin/github#owners" dir="ltr"><span class="sr">linked GitHub account </span>CAROL</a>`) {
		t.Error("/admin/x lacks the GitHub marker")
	}
	_, zh := adm.do("GET", "/zh-hans/admin/github", "")
	for _, w := range []string{"可信账号（1）", "关联的 X 账号", "账号可信"} {
		if !strings.Contains(string(zh), w) {
			t.Errorf("zh-Hans page lacks %s", w)
		}
	}

	// the link: change, unknown, no change, clear
	up := "/api/admin/github/owners/" + id + "/update"
	resp, body = adm.post(up, `{"note":"lab","x_handle":"carol_alt"}`)
	expect(t, "change link", resp, body, 200, "")
	resp, body = adm.post(up, `{"note":"lab","x_handle":"ghost"}`)
	expect(t, "unknown link", resp, body, 422, "x_not_listed")
	resp, body = adm.post(up, `{"note":"lab","x_handle":"carol_alt"}`)
	expect(t, "same", resp, body, 409, "no_change")
	resp, body = adm.post(up, `{"note":"lab 2","x_handle":""}`)
	expect(t, "clear link", resp, body, 200, "")
	if n := h.count(`SELECT count(*) FROM github_trusted_owner WHERE x_user_id IS NULL AND note = 'lab 2'`); n != 1 {
		t.Error("link not cleared")
	}
	resp, body = adm.post("/api/admin/github/owners/999/update", `{"note":""}`)
	expect(t, "no such account", resp, body, 404, "not_found")
	// the link never changes trust, and a deleted X account clears it
	adm.post(up, `{"note":"lab 2","x_handle":"carol_x"}`)
	h.sql(`DELETE FROM x_accounts WHERE user_id = '111'`)
	if n := h.count(`SELECT count(*) FROM github_trusted_owner WHERE x_user_id IS NULL AND enabled`); n != 1 {
		t.Error("ON DELETE SET NULL")
	}
	if got := h.ghStatus(carolNew); got != "trusted/owner" {
		t.Errorf("trust after the X account went: %s", got)
	}

	// disable: owner trust goes back, the admin's decisions stay
	resp, body = adm.post("/api/admin/github/owners/"+id+"/disable", ``)
	expect(t, "disable", resp, body, 200, "")
	resp, body = adm.post("/api/admin/github/owners/"+id+"/disable", ``)
	expect(t, "disable again", resp, body, 409, "no_change")
	for id, want := range map[int64]string{carolNew: "unverified/-", r.bad: "rejected/admin", carolTrusted: "trusted/admin"} {
		if got := h.ghStatus(id); got != want {
			t.Errorf("row %d after disable: %s, want %s", id, got, want)
		}
	}
	resp, body = adm.post("/api/admin/github/owners/"+id+"/enable", ``)
	expect(t, "enable", resp, body, 200, "")
	if got := h.ghStatus(carolNew); got != "trusted/owner" {
		t.Errorf("after enable: %s", got)
	}
	resp, body = mod.post("/api/admin/github/owners/"+id+"/disable", ``)
	expect(t, "moderator disable", resp, body, 403, "forbidden")

	if got := h.ownerAudits(); got != "github.owner.add:CAROL github.owner.link:CAROL github.owner.update:CAROL github.owner.unlink:CAROL "+
		"github.owner.link:CAROL github.owner.disable:CAROL github.owner.enable:CAROL" {
		t.Errorf("audit: %s", got)
	}
	var d string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT details::text FROM admin_audit WHERE action = 'github.owner.add'`).Scan(&d)
	if !strings.Contains(d, `"trusted": 1`) || !strings.Contains(d, `"x_handle": "carol_x"`) {
		t.Errorf("add details: %s", d)
	}
}

// Quick add from a review row: the repository's owner is listed with the
// row's owner id (no lookup), or one looked up on GitHub when the row has
// none; linked to the X account when exactly one allow-listed account
// posted the repository, unlinked when several did. A repository surfaced
// by a post whose link is stamped (its poster since disabled) and nobody
// reviewed is trusted by the quick add (the main use case).
func TestGitHubOwnerQuickAdd(t *testing.T) {
	lookups := 0
	h := newHarness(t, hopt{ghLookup: func(_ context.Context, login string) (int64, string, error) {
		lookups++
		if login == "erin" {
			return 512, "erin", nil
		}
		return 0, "", errors.New("unexpected lookup " + login)
	}})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	one := h.ghRepo(911, "dora/CVE-2026-0001-poc", "", 1, false, false, "2026-01-01", "xposts", "unverified", nil)
	two := h.ghRepo(912, "erin/CVE-2026-0001-lab", "", 1, false, false, "2026-01-01", "xposts", "unverified", nil)
	none := h.ghRepo(913, "frank/thing", "", 1, false, false, "2026-01-01", "search", "unverified", nil)
	h.sql(`UPDATE github_repo SET owner_id = 4242 WHERE id = $1`, one)
	h.sql(`UPDATE github_repo SET owner_login = NULL WHERE id = $1`, none)
	h.sql(`INSERT INTO x_accounts (user_id, handle) VALUES ('301', 'dora_x'), ('302', 'erin_x'), ('303', 'erin_fan')`)
	post := func(id, author string) {
		h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
            VALUES ($1, 'social_post', now(), now(), 'xposts', 'https://x.com/i/web/status/'||$2, jsonb_build_object('author_id', $3::text), $2)`,
			cveA, id, author)
	}
	link := func(postID, full string) {
		// a root link not stamped (yet): a stamped one would make the repository rule-trusted
		h.sql(`INSERT INTO x_post_link (post_id, pos, short_url, final_url, kind, origin, status, repo_root_key)
            VALUES ($1, 0, 'https://t.co/x', 'https://github.com/'||$2, 'code', 'api', 'ok', lower($2))`, postID, full)
	}
	post("71", "301")
	link("71", "dora/CVE-2026-0001-poc")
	h.sql(`UPDATE x_post_link SET repo_checked_at = now(), repo_github_id = 911 WHERE post_id = '71'`)
	h.sql(`UPDATE x_accounts SET enabled = false WHERE user_id = '301'`)
	post("72", "302")
	link("72", "erin/CVE-2026-0001-lab")
	post("73", "303")
	link("73", "erin/CVE-2026-0001-lab")

	p := func(id int64) string { return "/api/admin/github/repos/" + idStr(id) + "/owner" }
	resp, body := mod.post(p(one), ``)
	expect(t, "moderator", resp, body, 403, "forbidden")
	resp, body = adm.post(p(one), ``)
	expect(t, "quick add", resp, body, 200, "")
	if !strings.Contains(string(body), `"x_handle":"dora_x"`) {
		t.Errorf("answer: %s", body)
	}
	if n := h.count(`SELECT count(*) FROM github_trusted_owner WHERE login = 'dora' AND owner_id = 4242 AND x_user_id = '301'`); n != 1 {
		t.Error("dora not listed with her id and X account")
	}
	if got := h.ghStatus(one); got != "trusted/owner" {
		t.Errorf("dora's repository: %s", got)
	}
	if lookups != 0 {
		t.Errorf("%d lookups for a row with an owner id", lookups)
	}
	var doraID int64
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT id FROM github_trusted_owner WHERE login = 'dora'`).Scan(&doraID)
	resp, body = adm.post(p(one), ``)
	expect(t, "again", resp, body, 409, "owner_exists")
	if !strings.Contains(string(body), fmt.Sprintf(`"id":%d`, doraID)) {
		t.Errorf("conflict does not name the listed account: %s", body)
	}
	resp, body = adm.post(p(two), ``)
	expect(t, "two finders", resp, body, 200, "")
	if n := h.count(`SELECT count(*) FROM github_trusted_owner WHERE login = 'erin' AND owner_id = 512 AND x_user_id IS NULL`); n != 1 {
		t.Error("erin not listed with the looked-up id, or linked although two accounts posted her repository")
	}
	resp, body = adm.post(p(none), ``)
	expect(t, "no owner", resp, body, 422, "no_owner")
	resp, body = adm.post("/api/admin/github/repos/99999/owner", ``)
	expect(t, "no repository", resp, body, 404, "not_found")
	resp, body = adm.post(p(none), `{"x":1}`)
	expect(t, "body", resp, body, 400, "bad_request")
	// listed owners' rows show it and offer no quick add
	_, page := adm.do("GET", "/admin/github", "")
	_, trusted, _ := strings.Cut(string(page), `<details class="adm-hist" id="trusted">`)
	if row := rowOf(trusted, one); !strings.Contains(row, `<span class="adm-st">account trusted</span>`) || strings.Contains(row, `data-act="ghowner"`) {
		t.Errorf("listed owner's row:\n%s", row)
	}
	if got := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'github.owner.add' AND details->>'repo_id' IS NOT NULL`); got != 2 {
		t.Errorf("audit rows of quick adds: %d", got)
	}
}

// The X link stays on admin pages: a signed-out vulnerability page and the
// public API of a CVE whose PoC repository's owner is linked to an X
// account show neither the handle nor anything about the link.
func TestGitHubOwnerLinkNotPublic(t *testing.T) {
	h := newHarness(t, hopt{ghLookup: ghUsers(t, map[string]int64{"gina": 444})})
	adm := h.user("kim", "admin")
	created := h.clock.Now().Add(-24 * time.Hour).Format("2006-01-02")
	repo := h.ghRepo(921, "gina/CVE-2026-0001-poc", "", 3, false, false, created, "search", "unverified", nil)
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, $2, 'name')`, repo, cveA)
	h.sql(`UPDATE github_repo SET owner_id = 444 WHERE id = $1`, repo)
	h.sql(`INSERT INTO x_accounts (user_id, handle) VALUES ('401', 'ginasecretx')`)
	resp, body := adm.post("/api/admin/github/owners", `{"login":"gina","note":"privnote","x_handle":"ginasecretx"}`)
	expect(t, "add", resp, body, 200, "")
	h.adm.WaitStateRefresh()
	if got := h.ghStatus(repo); got != "trusted/owner" {
		t.Fatalf("repository: %s", got)
	}
	if n := h.count(`SELECT count(*) FROM event WHERE source = 'github' AND cve_id = $1`, cveA); n != 1 {
		t.Fatalf("PoC events: %d", n)
	}
	var ev string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT detail::text || url FROM event WHERE source = 'github'`).Scan(&ev)
	anon := h.browser()
	tok, err := h.svc.IssueAPIToken(context.Background(), auth.UserID(adm.id), "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/vuln/" + cveA, "/v1/vuln/" + cveA, "/zh-hans/vuln/" + cveA} {
		var hdr []string
		if strings.HasPrefix(p, "/v1/") {
			hdr = []string{"Host", apiHost, "Authorization", "Bearer " + tok}
		}
		resp, body := anon.do("GET", p, "", hdr...)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		s := strings.ToLower(string(body))
		if !strings.Contains(s, "gina/cve-2026-0001-poc") {
			t.Errorf("%s does not show the PoC repository", p)
		}
		for _, bad := range []string{"ginasecretx", "privnote", "trusted account", "可信账号", "x_user", "x_handle", "owner"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s shows %q", p, bad)
			}
		}
	}
	for _, bad := range []string{"ginasecretx", "owner", "x_user"} {
		if strings.Contains(ev, bad) {
			t.Errorf("event holds %q: %s", bad, ev)
		}
	}
}

// Adding by login: the id comes from GitHub; a login GitHub does not know
// is refused; a failed lookup saves the account "id pending", which trusts
// nothing (not even a repository whose row has the login and an id).
func TestGitHubOwnerLookup(t *testing.T) {
	h := newHarness(t, hopt{ghLookup: ghUsers(t, map[string]int64{"Gail": 700})})
	adm := h.user("kim", "admin")
	gail := h.ghRepo(931, "gail/CVE-2026-0001-poc", "", 1, false, false, "2026-01-01", "search", "unverified", nil)
	prev := h.ghRepo(932, "gail/older", "", 1, false, false, "2026-01-01", "search", "unverified", nil)
	pend := h.ghRepo(933, "pend/CVE-2026-0001-poc", "", 1, false, false, "2026-01-01", "search", "unverified", nil)
	h.sql(`UPDATE github_repo SET owner_id = 700 WHERE id = $1`, gail)
	h.sql(`UPDATE github_repo SET owner_id = 699 WHERE id = $1`, prev) // a previous holder of the login
	h.sql(`UPDATE github_repo SET owner_id = 800 WHERE id = $1`, pend)
	resp, body := adm.post("/api/admin/github/owners", `{"login":"ghost"}`)
	expect(t, "unknown login", resp, body, 422, "github_not_found")
	resp, body = adm.post("/api/admin/github/owners", `{"login":"gail"}`)
	expect(t, "add", resp, body, 200, "")
	if !strings.Contains(string(body), `"pending":false`) {
		t.Errorf("answer: %s", body)
	}
	resp, body = adm.post("/api/admin/github/owners", `{"login":"pend"}`)
	expect(t, "lookup down", resp, body, 200, "")
	if !strings.Contains(string(body), `"pending":true`) {
		t.Errorf("answer: %s", body)
	}
	for id, want := range map[int64]string{gail: "trusted/owner", prev: "unverified/-", pend: "unverified/-"} {
		if got := h.ghStatus(id); got != want {
			t.Errorf("row %d: %s, want %s", id, got, want)
		}
	}
	if n := h.count(`SELECT count(*) FROM github_trusted_owner WHERE login = 'Gail' AND owner_id = 700`); n != 1 {
		t.Error("gail not pinned with GitHub's spelling")
	}
	_, page := adm.do("GET", "/admin/github", "")
	_, sec, _ := strings.Cut(string(page), `id="owners"`)
	if c := strings.Count(sec, `<span class="adm-st">id pending</span>`); c != 1 {
		t.Errorf("%d pending tags, want 1", c)
	}
	_, zh := adm.do("GET", "/zh-hans/admin/github", "")
	if !strings.Contains(string(zh), "待确认") {
		t.Error("zh-Hans: no 待确认")
	}
}

// An account with hundreds of repositories: adding and disabling it is one
// transaction that the auth pool's 5 s statement_timeout does not cut
// (ownerTx sets its own), and every PoC event comes and goes.
func TestGitHubOwnerLarge(t *testing.T) {
	h := newHarness(t, hopt{stmtTimeout: "5000", ghLookup: ghUsers(t, map[string]int64{"bulk": 1000})})
	adm := h.user("kim", "admin")
	const n = 400
	created := h.clock.Now().Add(-24 * time.Hour).Format("2006-01-02")
	h.sql(`INSERT INTO vuln (cve_id) SELECT 'CVE-2026-' || (5000 + g) FROM generate_series(1, $1) g`, n)
	h.sql(`INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, owner_id, state, fetched_at, first_source,
            repo_created_at, status) SELECT 50000 + g, 'bulk/cve-2026-' || (5000 + g), 'bulk/CVE-2026-' || (5000 + g), 'bulk', 1000,
            'ok', now(), 'search', $2::date, 'unverified' FROM generate_series(1, $1) g`, n, created)
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, upper(split_part(full_name, '/', 2)), 'name'
            FROM github_repo WHERE owner_login = 'bulk'`)
	start := time.Now()
	resp, body := adm.post("/api/admin/github/owners", `{"login":"bulk"}`)
	expect(t, "add", resp, body, 200, "")
	if c := h.count(`SELECT count(*) FROM event WHERE source = 'github'`); c != n {
		t.Errorf("events after add: %d, want %d", c, n)
	}
	var id string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT id::text FROM github_trusted_owner`).Scan(&id)
	resp, body = adm.post("/api/admin/github/owners/"+id+"/disable", ``)
	expect(t, "disable", resp, body, 200, "")
	if c := h.count(`SELECT count(*) FROM event WHERE source = 'github'`); c != 0 {
		t.Errorf("events after disable: %d", c)
	}
	t.Logf("add and disable of %d repositories: %v", n, time.Since(start))
	h.adm.WaitStateRefresh()
}
