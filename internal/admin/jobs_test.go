package admin_test

import (
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/admin"
)

// TestJobStatus: the status vocabulary of the jobs table.
func TestJobStatus(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := now.Add(-d); return &x }
	yes, no := true, false
	for _, c := range []struct {
		j    admin.JobRow
		want string
	}{
		{admin.JobRow{Name: "github-fetch"}, "none"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(5 * time.Minute)}, "running"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(2 * time.Hour)}, "unfinished"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(time.Hour), FinishedAt: at(time.Hour), OK: &no}, "error"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(5 * time.Hour), FinishedAt: at(5 * time.Hour), OK: &no}, "error"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(2 * time.Hour), FinishedAt: at(2 * time.Hour), OK: &yes}, "ok"},
		{admin.JobRow{Name: "github-fetch", Recorded: true, StartedAt: at(3 * time.Hour), FinishedAt: at(3 * time.Hour), OK: &yes}, "stale"},
		{admin.JobRow{Name: "site-icons", Recorded: true, StartedAt: at(40 * time.Hour), FinishedAt: at(40 * time.Hour), OK: &yes}, "ok"},
		{admin.JobRow{Name: "site-icons", Recorded: true, StartedAt: at(61 * time.Hour), FinishedAt: at(61 * time.Hour), OK: &yes}, "stale"},
	} {
		if got := admin.JobStatus(c.j, now); got != c.want {
			t.Errorf("%+v: %s, want %s", c.j, got, c.want)
		}
	}
}

// TestSystemJobs: the jobs table under the collectors — one row per job,
// "no record yet" for a job that never ran, the error (escaped) with its
// detail row, the backlog counts; admin only.
func TestSystemJobs(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")

	// before any run: every job neutral, no error
	_, body := adm.do("GET", "/admin/system", "")
	s := string(body)
	for _, want := range []string{`id="h-jobs"`, ">jobs<", "GitHub repository discovery", "GitHub PoC repair", "GitHub repository fetch",
		"web pages", "site icons", "0 pending", "0 due"} {
		if !strings.Contains(s, want) {
			t.Errorf("empty: %q not found", want)
		}
	}
	if n := strings.Count(s, `<span class="weak">no record yet</span>`); n != 5 {
		t.Errorf("empty: %d neutral rows, want 5", n)
	}
	if strings.Contains(s, `id="dt-j-`) {
		t.Error("empty: an error detail row")
	}

	now := h.clock.Now()
	h.sql(`INSERT INTO job_run (name, started_at, finished_at, ok, last_success_at, detail) VALUES
		('github-discover', $1, $1, true, $1, '{"requests":3}'),
		('site-icons', $2, $2, true, $2, NULL)`, now.Add(-30*time.Minute), now.Add(-80*time.Hour))
	h.sql(`INSERT INTO job_run (name, started_at, finished_at, ok, error, last_success_at) VALUES
		('pages-fetch', $1, $1, false, $2, $3)`, now.Add(-10*time.Minute), `<script>alert(1)</script> boom`, now.Add(-70*time.Minute))
	h.sql(`INSERT INTO web_page (url_key, url, first_source) VALUES ('a', 'https://a.example/', 'xposts'), ('b', 'https://b.example/', 'xposts')`)
	h.sql(`INSERT INTO web_page (url_key, url, first_source, status, fetched_at) VALUES ('c', 'https://c.example/', 'xposts', 'failed', now())`)
	h.sql(`INSERT INTO github_repo (queued_name, first_source) VALUES ('a/b', 'xposts')`)
	h.sql(`INSERT INTO site_icon (host, status, fetched_at, next_try_at) VALUES ('a.example', 'none', now(), now() - interval '1 hour'),
		('b.example', 'none', now(), now() + interval '1 day')`)

	_, body = adm.do("GET", "/admin/system", "")
	s = string(body)
	for _, want := range []string{`<span class="ok">ok</span>`, `<span class="warn">stale</span>`, `<span class="bad">error</span>`,
		"2 pending", "1 pending", "1 due", "&lt;script&gt;alert(1)&lt;/script&gt; boom", `aria-controls="dt-j-3"`, `id="dt-j-3"`} {
		if !strings.Contains(s, want) {
			t.Errorf("%q not found", want)
		}
	}
	if n := strings.Count(s, `<span class="weak">no record yet</span>`); n != 2 {
		t.Errorf("%d neutral rows, want 2 (github-poc, github-fetch)", n)
	}
	// the jobs table sits between the collectors and the database
	if c, j, d := strings.Index(s, `id="h-coll"`), strings.Index(s, `id="h-jobs"`), strings.Index(s, `id="h-db"`); !(c < j && j < d) {
		t.Errorf("order: collectors %d, jobs %d, database %d", c, j, d)
	}
	for _, pr := range checkHTML(s, adminElems) {
		t.Error(pr)
	}

	// zh-Hans names
	_, body = adm.do("GET", "/zh-hans/admin/system", "")
	for _, want := range []string{"后台任务", "GitHub 仓库发现", "GitHub 仓库抓取", "网页抓取", "站点图标", "暂无记录"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("zh-Hans: %q not found", want)
		}
	}

	// moderators do not get the system page
	if resp, body := mod.do("GET", "/admin/system", ""); resp.StatusCode == 200 || strings.Contains(string(body), `id="h-jobs"`) {
		t.Errorf("moderator: %d", resp.StatusCode)
	}
}

// TestJobLimited: a run that finished ok but was rate limited reads
// "rate limited" (warn), below running, unfinished, error and stale; a
// missing, null or malformed detail is not limited.
func TestJobLimited(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := now.Add(-d); return &x }
	yes, no := true, false
	for _, c := range []struct {
		j    admin.JobRow
		want string
	}{
		{admin.JobRow{Name: "github-discover", Recorded: true, StartedAt: at(time.Hour), FinishedAt: at(time.Hour), OK: &yes, Limited: true}, "limited"},
		{admin.JobRow{Name: "github-discover", Recorded: true, StartedAt: at(3 * time.Hour), FinishedAt: at(3 * time.Hour), OK: &yes, Limited: true}, "stale"},
		{admin.JobRow{Name: "github-discover", Recorded: true, StartedAt: at(time.Hour), FinishedAt: at(time.Hour), OK: &no, Limited: true}, "error"},
		{admin.JobRow{Name: "github-discover", Recorded: true, StartedAt: at(5 * time.Minute), Limited: true}, "running"},
		{admin.JobRow{Name: "github-discover", Recorded: true, StartedAt: at(2 * time.Hour), Limited: true}, "unfinished"},
	} {
		if got := admin.JobStatus(c.j, now); got != c.want {
			t.Errorf("%+v: %s, want %s", c.j, got, c.want)
		}
	}

	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	n := h.clock.Now().Add(-10 * time.Minute)
	h.sql(`INSERT INTO job_run (name, started_at, finished_at, ok, last_success_at, detail) VALUES
		('github-discover', $1, $1, true, $1, '{"requests": 1, "rate_limited": true, "cves": 0, "added": 0}'),
		('github-fetch', $1, $1, true, $1, '{"rate_limited": false}'),
		('github-poc', $1, $1, true, $1, '{"rate_limited": "yes"}'),
		('pages-fetch', $1, $1, true, $1, '[true]'),
		('site-icons', $1, $1, true, $1, NULL)`, n)
	_, body := adm.do("GET", "/admin/system", "")
	s := string(body)
	if c := strings.Count(s, `<span class="warn">rate limited</span>`); c != 1 {
		t.Errorf("%d rate limited rows, want 1", c)
	}
	if c := strings.Count(s, `<span class="ok">ok</span>`); c != 4 {
		t.Errorf("%d ok rows, want 4", c)
	}
	if strings.Contains(s, `id="dt-j-`) {
		t.Error("a limited run has no error, so no detail row")
	}
	_, body = adm.do("GET", "/zh-hans/admin/system", "")
	if !strings.Contains(string(body), `<span class="warn">受限</span>`) {
		t.Error("zh-Hans: no 受限")
	}
}
