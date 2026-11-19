package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/ghrepo"
)

// ghRepos is the fixture of the GitHub review tests (ids from ghFixture).
type ghRepos struct {
	poc, hostile, lab, bad, coll int64
}

// ghRepo inserts one fetched repository and returns its id.
func (h *harness) ghRepo(ghID int64, full, desc string, stars int, fork, archived bool, created, source, status string, by any) int64 {
	h.t.Helper()
	var at any
	if by != nil {
		at = "2026-11-10T00:00:00Z"
	}
	var d any
	if desc != "" {
		d = desc
	}
	var id int64
	err := h.db.Conn.QueryRow(context.Background(), `INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, description,
		stars, forks, is_fork, is_archived, repo_created_at, state, fetched_at, first_source, status, status_by, status_at)
		VALUES ($1, lower($2), $2, split_part($2, '/', 1), $3, $4, 0, $5, $6, $7::date, 'ok', '2026-11-10', $8, $9, $10, $11)
		RETURNING id`, ghID, full, d, stars, fork, archived, created, source, status, by, at).Scan(&id)
	if err != nil {
		h.t.Fatal(err)
	}
	h.sql(`INSERT INTO github_repo_name (name_key, repo_id) VALUES (lower($1), $2)`, full, id)
	return id
}

// ghFixture: poc (unverified, found by search, created before its CVE was
// published), hostile (unverified, a full name that is not valid and a
// description with markup), lab (trusted by the post rule), bad (rejected by
// an admin), coll (unverified fork, archived, 7 CVEs by name: a collection).
func (h *harness) ghFixture() ghRepos {
	h.t.Helper()
	h.sql(`INSERT INTO vuln (cve_id, published_at) VALUES ('CVE-2024-3094', '2024-03-29')`)
	var r ghRepos
	r.poc = h.ghRepo(901, "alice/CVE-2024-3094-poc", "PoC for the xz backdoor", 42, false, false, "2024-03-01", "search", "unverified", nil)
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2024-3094', 'name'), ($1, 'CVE-2024-3094', 'description')`, r.poc)
	r.hostile = h.ghRepo(902, `evil/<b>x</b>`, `<script>alert(1)</script> "quoted" & more`, 1, false, false, "2025-01-01", "search", "unverified", nil)
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2024-3094', 'description')`, r.hostile)
	r.lab = h.ghRepo(903, "bob/xz-lab", "", 310, false, false, "2024-04-01", "xposts", "trusted", "rule")
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2024-3094', 'post')`, r.lab)
	r.bad = h.ghRepo(904, "carol/fake-poc", "Totally real", 5, false, false, "2024-04-02", "search", "rejected", "admin")
	// GHSA ids: one that is an alias of the CVE (shown as the CVE), one of a vulnerability without a CVE (linked by its GHSA id)
	h.sql(`INSERT INTO vuln (cve_id) VALUES ('GHSA-gpwc-27cw-rh9r')`)
	h.sql(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2024-3094', 'GHSA-2222-3333-4444', 'ghsa')`)
	h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'GHSA-2222-3333-4444', 'name'), ($1, 'GHSA-gpwc-27cw-rh9r', 'description')`, r.bad)
	r.coll = h.ghRepo(905, "dan/cve-collection", "Many PoCs", 1200, true, true, "2023-01-01", "search", "unverified", nil)
	for i := 1; i <= 7; i++ {
		h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, $2, 'name')`, r.coll, fmt.Sprintf("CVE-2025-%04d", 1000+i))
	}
	// a repository not fetched yet is never listed
	h.sql(`INSERT INTO github_repo (queued_name, first_source) VALUES ('pending/repo', 'search')`)
	return r
}

func idStr(id int64) string { return fmt.Sprint(id) }

// rowOf cuts the table row of repository id out of a page section.
func rowOf(sec string, id int64) string {
	_, row, ok := strings.Cut(sec, `<tr data-repo="`+idStr(id)+`">`)
	if !ok {
		return ""
	}
	row, _, _ = strings.Cut(row, "</tr>")
	return row
}

// TestGitHubReviewPage: the unverified list open with its actions, trusted
// and rejected behind toggles with theirs, the row contents (link, stars,
// date, CVE links, "+N", flags, source, description), third-party text
// escaped and an invalid full name not linked; admins only.
func TestGitHubReviewPage(t *testing.T) {
	h := newHarness(t, hopt{})
	r := h.ghFixture()
	adm := h.user("kim", "admin")
	resp, body := adm.do("GET", "/admin/github", "")
	if resp.StatusCode != 200 {
		t.Fatalf("/admin/github: %d\n%s", resp.StatusCode, h.logs.String())
	}
	s := string(body)
	for _, pr := range checkHTML(s, adminElems) {
		t.Error(pr)
	}
	if !strings.Contains(s, `href="/admin/github" aria-current="page"`) && !strings.Contains(s, `aria-current="page" href="/admin/github"`) {
		t.Error("no current GitHub tab in the nav")
	}
	_, sec, _ := strings.Cut(s, `id="repos"`)
	sec, _, _ = strings.Cut(sec, "</section>")
	open, rest, ok := strings.Cut(sec, `<details class="adm-hist" id="trusted">`)
	if !ok {
		t.Fatalf("no trusted toggle:\n%s", sec)
	}
	trusted, rejected, ok := strings.Cut(rest, `<details class="adm-hist" id="rejected">`)
	if !ok {
		t.Fatalf("no rejected toggle:\n%s", rest)
	}
	if !strings.Contains(open, "unverified (3)") || !strings.Contains(trusted, "trusted (1)") || !strings.Contains(rejected, "rejected (1)") {
		t.Error("list headings or totals")
	}

	poc := rowOf(open, r.poc)
	for _, w := range []string{`<a href="https://github.com/alice/CVE-2024-3094-poc" target="_blank" rel="noopener noreferrer nofollow" dir="ltr">alice/CVE-2024-3094-poc</a>`,
		`<span class="adm-clip dim" dir="auto">PoC for the xz backdoor</span>`, `<td class="r">42</td>`, `<td>2024-03-01</td>`,
		`<a href="/vuln/CVE-2024-3094">CVE-2024-3094</a>`, "predates the CVE", `<td class="adm-nw">search</td>`,
		`data-act="ghtrust" data-r="` + idStr(r.poc) + `"`, `data-act="ghreject" data-r="` + idStr(r.poc) + `"`} {
		if !strings.Contains(poc, w) {
			t.Errorf("poc row lacks %q:\n%s", w, poc)
		}
	}
	if strings.Contains(poc, "ghreset") || strings.Contains(poc, "fork") || strings.Contains(poc, "collection") {
		t.Errorf("poc row: reset or wrong flags:\n%s", poc)
	}
	if bad := rowOf(rejected, r.bad); !strings.Contains(bad, `<a href="/vuln/CVE-2024-3094">CVE-2024-3094</a> <a href="/vuln/GHSA-gpwc-27cw-rh9r">GHSA-gpwc-27cw-rh9r</a>`) ||
		strings.Contains(bad, "GHSA-2222-3333-4444") {
		t.Errorf("GHSA ids of the rejected row (main id for an alias, a link for a GHSA-keyed vulnerability):\n%s", bad)
	}
	coll := rowOf(open, r.coll)
	for _, w := range []string{"CVE-2025-1007", "CVE-2025-1003", "+2", "fork · archived · collection", `<td class="r">1,200</td>`} {
		if !strings.Contains(coll, w) {
			t.Errorf("collection row lacks %q:\n%s", w, coll)
		}
	}
	if strings.Contains(coll, "CVE-2025-1002") || strings.Contains(coll, "predates") {
		t.Errorf("collection row lists a sixth CVE or predates:\n%s", coll)
	}
	hostile := rowOf(open, r.hostile)
	for _, w := range []string{`<bdi>evil/&lt;b&gt;x&lt;/b&gt;</bdi>`, `&lt;script&gt;alert(1)&lt;/script&gt; &#34;quoted&#34; &amp; more`} {
		if !strings.Contains(hostile, w) {
			t.Errorf("hostile row lacks %q:\n%s", w, hostile)
		}
	}
	if strings.Contains(hostile, "github.com/evil") || strings.Contains(s, "<script>alert") || strings.Contains(s, "<b>x") {
		t.Errorf("hostile name linked or markup not escaped:\n%s", hostile)
	}
	if strings.Contains(s, "pending/repo") {
		t.Error("an unfetched repository is listed")
	}

	lab := rowOf(trusted, r.lab)
	for _, w := range []string{`data-act="ghreject" data-r="` + idStr(r.lab) + `"`, `data-act="ghreset" data-r="` + idStr(r.lab) + `"`, `<td class="adm-nw">X post</td>`} {
		if !strings.Contains(lab, w) {
			t.Errorf("trusted row lacks %q:\n%s", w, lab)
		}
	}
	if strings.Contains(lab, "ghtrust") {
		t.Error("trusted row offers trust")
	}
	bad := rowOf(rejected, r.bad)
	for _, w := range []string{`data-act="ghtrust" data-r="` + idStr(r.bad) + `"`, `data-act="ghreset" data-r="` + idStr(r.bad) + `"`} {
		if !strings.Contains(bad, w) {
			t.Errorf("rejected row lacks %q:\n%s", w, bad)
		}
	}
	if strings.Contains(bad, "ghreject") {
		t.Error("rejected row offers reject")
	}
	for name, part := range map[string]string{"open": open, "trusted": trusted, "rejected": rejected} {
		for _, other := range []int64{r.poc, r.hostile, r.coll, r.lab, r.bad} {
			in := rowOf(part, other) != ""
			want := (name == "open" && (other == r.poc || other == r.hostile || other == r.coll)) ||
				(name == "trusted" && other == r.lab) || (name == "rejected" && other == r.bad)
			if in != want {
				t.Errorf("%s list: repo %d listed %v, want %v", name, other, in, want)
			}
		}
	}

	if _, body := adm.do("GET", "/zh-hans/admin/github", ""); !strings.Contains(string(body), "设为可信") || !strings.Contains(string(body), "未验证（3）") {
		t.Error("zh-hans: no Chinese labels")
	}

	// paging: 10 rows a page of 53, numbered (?up=), the heading counts all
	h.sql(`INSERT INTO github_repo (github_id, queued_name, full_name, state, fetched_at, first_source)
		SELECT 1000 + g, 'fill/r' || g, 'fill/r' || g, 'ok', now(), 'search' FROM generate_series(1, 50) g`)
	_, body = adm.do("GET", "/admin/github", "")
	_, sec, _ = strings.Cut(string(body), `id="repos"`)
	open, _, _ = strings.Cut(sec, "<details")
	if !strings.Contains(open, "unverified (53)") || !strings.Contains(open, "page 1 of 6") ||
		strings.Count(open, "<tr data-repo=") != admin.GitHubReviewPage || !strings.Contains(open, `href="/admin/github?up=2#r-gh-unverified" rel="next"`) {
		t.Errorf("paging: %d rows", strings.Count(open, "<tr data-repo="))
	}

	// admins only
	if resp, _ := h.browser().do("GET", "/admin/github", ""); resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?return=%2Fadmin%2Fgithub" {
		t.Errorf("signed out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for i, role := range []string{"user", "moderator", "suspended moderator", "suspended admin"} {
		b := h.user(fmt.Sprintf("viewer%d", i), strings.TrimPrefix(role, "suspended "))
		if strings.HasPrefix(role, "suspended") {
			h.suspend(b.id)
		}
		if resp, body := b.do("GET", "/admin/github", ""); resp.StatusCode != 404 || strings.Contains(string(body), "alice/CVE") {
			t.Errorf("%s: %d", role, resp.StatusCode)
		}
	}
	// the nav shows the tab to admins only
	_, mp := h.user("mia", "moderator").do("GET", "/admin/moderation", "")
	if strings.Contains(string(mp), `href="/admin/github"`) {
		t.Error("a moderator's nav links /admin/github")
	}
}

func (h *harness) ghStatus(id int64) string {
	h.t.Helper()
	var s string
	if err := h.db.Conn.QueryRow(context.Background(), `SELECT status || '/' || coalesce(status_by, '-') FROM github_repo WHERE id = $1`, id).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

// TestGitHubReviewActions: trust / reject / reset behind the same checks as
// every admin action, their refusals, the status and audit rows they write,
// that a later post-rule sweep keeps an admin decision, and that a failing
// audit insert rolls the change back.
func TestGitHubReviewActions(t *testing.T) {
	h := newHarness(t, hopt{})
	r := h.ghFixture()
	ctx := context.Background()
	anon := h.browser()
	user := h.user("pat", "user")
	mod := h.user("mia", "moderator")
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	adm := h.user("kim", "admin")
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit`) }
	path := func(id int64, verb string) string { return "/api/admin/github/repos/" + idStr(id) + "/" + verb }

	// refused before anything is read or written
	p := path(r.poc, "trust")
	for _, c := range []struct {
		what   string
		b      *browser
		status int
		code   string
	}{{"signed out", anon, 401, "not_signed_in"}, {"user", user, 404, "not_found"}, {"moderator", mod, 403, "forbidden"},
		{"suspended admin", sadm, 404, "not_found"}} {
		for _, verb := range []string{"trust", "reject", "reset"} {
			check(t, c.what+" "+verb, c.status, c.code)(c.b.post(path(r.lab, verb), ""))
		}
	}
	check(t, "GET", 405, "method_not_allowed")(adm.do("GET", p, ""))
	check(t, "no CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", ""))
	check(t, "bad CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", flip(adm.csrf)))
	check(t, "other user's CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", mod.csrf))
	check(t, "cross-site", 403, "cross_site")(adm.post(p, "", "Sec-Fetch-Site", "cross-site"))
	check(t, "foreign origin", 403, "cross_site")(adm.post(p, "", "Origin", "https://evil.example", "Sec-Fetch-Site", ""))
	for _, bad := range []string{"0" + idStr(r.poc), "0", "-1", "x", "1e3", "1234567890123456789", "99999999999999999999", idStr(r.poc) + "%20", "%2B1"} {
		check(t, "bad id "+bad, 404, "not_found")(adm.post("/api/admin/github/repos/"+bad+"/trust", ""))
	}
	check(t, "unknown verb", 404, "not_found")(adm.post(path(r.poc, "approve"), ""))
	check(t, "no verb", 404, "not_found")(adm.post("/api/admin/github/repos/"+idStr(r.poc), ""))
	check(t, "body", 400, "bad_request")(adm.post(p, `{"status":"trusted"}`))
	check(t, "absent", 404, "not_found")(adm.post(path(999999999, "trust"), ""))
	check(t, "absent, max id", 404, "not_found")(adm.post("/api/admin/github/repos/999999999999999999/reset", ""))
	if audits() != 0 || h.ghStatus(r.poc) != "unverified/-" || h.ghStatus(r.lab) != "trusted/rule" {
		t.Fatal("a refused request wrote something")
	}

	// trust: admin decision, github.repo.trust, 409 on a repeat
	resp, body := adm.post(p, "")
	var out struct {
		OK     bool   `json:"ok"`
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != 200 || !out.OK || out.ID != r.poc || out.Status != "trusted" {
		t.Fatalf("trust: %d %s", resp.StatusCode, body)
	}
	if st := h.ghStatus(r.poc); st != "trusted/admin" {
		t.Errorf("after trust: %s", st)
	}
	// the decision changed a github PoC event (migration 0032): the lists
	// are refreshed in the background. The repository was created 28 days
	// before the CVE's publication (migration 0033: up to 30 days), so the
	// PoC counts at the publication time.
	h.adm.WaitStateRefresh()
	var poc string
	if err := h.db.Conn.QueryRow(ctx, `SELECT concat_ws(' ', stage, poc_sources, COALESCE(poc_at::text, '-'))
		FROM vuln_state_mat WHERE cve_id = 'CVE-2024-3094'`).Scan(&poc); err != nil || poc != "poc_published 1 2024-03-29 00:00:00+00" {
		t.Errorf("state after trust: %q %v", poc, err)
	}
	lastAudit := func() string {
		var row string
		if err := h.db.Conn.QueryRow(ctx, `SELECT action || ' ' || target_type || '/' || target_id || ' ' || coalesce(target_label, '-') || ' ' ||
			details::text || ' ' || actor_handle || ' ' || actor_role || ' ' || source FROM admin_audit ORDER BY id DESC LIMIT 1`).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	if want := fmt.Sprintf(`github.repo.trust x_account/github_repo:%d alice/CVE-2024-3094-poc {"to": "trusted", "from": "unverified", "repo_id": %d, "full_name": "alice/CVE-2024-3094-poc"} kim admin web`, r.poc, r.poc); lastAudit() != want {
		t.Errorf("audit:\n%s\nwant\n%s", lastAudit(), want)
	}
	check(t, "trust again", 409, "no_change")(adm.post(p, ""))
	if audits() != 1 {
		t.Errorf("audit rows: %d", audits())
	}

	// reject: from trusted by an admin
	check(t, "reject", 200, "")(adm.post(path(r.poc, "reject"), ""))
	if want := fmt.Sprintf(`github.repo.reject x_account/github_repo:%d alice/CVE-2024-3094-poc {"to": "rejected", "from": "trusted", "from_by": "admin", "repo_id": %d, "full_name": "alice/CVE-2024-3094-poc"} kim admin web`, r.poc, r.poc); lastAudit() != want {
		t.Errorf("audit:\n%s\nwant\n%s", lastAudit(), want)
	}
	check(t, "reject again", 409, "no_change")(adm.post(path(r.poc, "reject"), ""))

	// reset of a repository trusted by the post rule: unverified by an admin
	check(t, "reset", 200, "")(adm.post(path(r.lab, "reset"), ""))
	if st := h.ghStatus(r.lab); st != "unverified/admin" {
		t.Errorf("after reset: %s", st)
	}
	if want := fmt.Sprintf(`github.repo.reset x_account/github_repo:%d bob/xz-lab {"to": "unverified", "from": "trusted", "from_by": "rule", "repo_id": %d, "full_name": "bob/xz-lab"} kim admin web`, r.lab, r.lab); lastAudit() != want {
		t.Errorf("audit:\n%s\nwant\n%s", lastAudit(), want)
	}
	check(t, "reset again", 409, "no_change")(adm.post(path(r.lab, "reset"), ""))
	// trust of the rejected one
	check(t, "trust rejected", 200, "")(adm.post(path(r.bad, "trust"), ""))
	var actions string
	_ = h.db.Conn.QueryRow(ctx, `SELECT string_agg(action || ':' || target_id, ' ' ORDER BY id) FROM admin_audit`).Scan(&actions)
	if want := fmt.Sprintf("github.repo.trust:github_repo:%d github.repo.reject:github_repo:%d github.repo.reset:github_repo:%d github.repo.trust:github_repo:%d",
		r.poc, r.poc, r.lab, r.bad); actions != want {
		t.Errorf("audit:\n%s\nwant\n%s", actions, want)
	}
	// the page moved them
	_, page := adm.do("GET", "/admin/github", "")
	_, sec, _ := strings.Cut(string(page), `id="repos"`)
	open, rest, _ := strings.Cut(sec, `id="trusted"`)
	trusted, rejected, _ := strings.Cut(rest, `id="rejected"`)
	if rowOf(open, r.lab) == "" || rowOf(rejected, r.poc) == "" || rowOf(trusted, r.bad) == "" {
		t.Error("the lists do not show the new statuses")
	}
	// the audit page names the action and shows the target as a repository
	_, ap := adm.do("GET", "/admin/audit?action=github_repo_reset", "")
	for _, w := range []string{"reset a GitHub repository", "GitHub repository", `<a href="/admin/github"><bdi>bob/xz-lab</bdi></a>`} {
		if !strings.Contains(string(ap), w) {
			t.Errorf("audit page lacks %q", w)
		}
	}

	// a later post-rule sweep keeps every admin decision: a researcher's post
	// links the rejected poc, the reset lab and the undecided collection
	for i, full := range []string{"alice/CVE-2024-3094-poc", "bob/xz-lab", "dan/cve-collection"} {
		u := "https://github.com/" + full
		h.sql(`INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
			VALUES ('1900000000000000000', $1::int, 'https://t.co/x' || $1::text, $2, $2, 'github.com', 'code', 'api', 'ok')`, i, u)
	}
	res, err := ghrepo.Enqueue(ctx, h.db.Conn, nil)
	if err != nil || res.Candidates != 3 {
		t.Fatalf("enqueue: %+v %v", res, err)
	}
	if st := h.ghStatus(r.poc); st != "rejected/admin" {
		t.Errorf("rejected by an admin, after the sweep: %s", st)
	}
	if st := h.ghStatus(r.lab); st != "unverified/admin" {
		t.Errorf("reset by an admin, after the sweep: %s", st)
	}
	if st := h.ghStatus(r.coll); st != "unverified/-" { // the sweep grants no trust: only a link check of the fetch pass does
		t.Errorf("undecided, after the sweep: %s", st)
	}

	// a failing audit insert rolls the change back
	h.sql(`CREATE FUNCTION test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit fails'; END $$`)
	h.sql(`CREATE TRIGGER test_audit_fail BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION test_audit_fail()`)
	check(t, "reject, audit fails", 500, "internal")(adm.post(path(r.hostile, "reject"), ""))
	check(t, "trust, audit fails", 500, "internal")(adm.post(path(r.poc, "trust"), ""))
	if h.ghStatus(r.hostile) != "unverified/-" || h.ghStatus(r.poc) != "rejected/admin" {
		t.Errorf("applied without its audit row: %s, %s", h.ghStatus(r.hostile), h.ghStatus(r.poc))
	}
}

func TestValidRepoID(t *testing.T) {
	for s, want := range map[string]bool{"1": true, "42": true, "999999999999999999": true, "0": false, "01": false, "": false,
		"-1": false, "+1": false, "1 ": false, "1e3": false, "1000000000000000000": false, "99999999999999999999": false, "١": false} {
		if admin.ValidRepoID(s) != want {
			t.Errorf("ValidRepoID(%q) = %v", s, !want)
		}
	}
}
