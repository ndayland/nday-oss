package site_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// seedLinks stores researcher posts with links (x_post_link) about GPU:
// two enabled authors, one disabled, one post about another CVE.
func seedLinks(t *testing.T, s sitetest.Seeder) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('1001', 'resA', true), ('1002', 'resB', true), ('1003', 'resGone', false)`,
	} {
		if _, err := s.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	post := func(cve, id, author string, at time.Time) {
		s.Event(sitetest.Ev{CVE: cve, Type: "social_post", Source: "xposts", Occurred: sitetest.P(at), Observed: at, Key: id,
			Detail: `{"post_id": "` + id + `", "author_id": "` + author + `", "author_handle": "h` + author + `", "text": "see https://t.co/a", "lang": "en"}`})
	}
	link := func(id string, pos int, final, kind, status string) {
		var f, h any
		if final != "" {
			f, h = final, "h.example"
		}
		if _, err := s.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, title, origin, status)
VALUES ($1, $2, $3, $4, $4, $5, $6, 'QZTITLE', 'api', $7)`, id, pos, fmt.Sprintf("https://t.co/s%s%d", id[len(id)-2:], pos), f, h, kind, status); err != nil {
			t.Fatal(err)
		}
	}
	gpu := sitetest.GPU
	post(gpu, "2000000000000000011", "1001", sitetest.Ago(3))
	link("2000000000000000011", 0, "https://github.com/o/r/commit/abc", "patch", "ok")
	link("2000000000000000011", 1, "https://pbs.twimg.com/media/x.jpg", "media", "ok")
	link("2000000000000000011", 2, "https://x.com/foo/status/1", "quote", "ok")
	link("2000000000000000011", 3, "javascript:alert(1)", "other", "ok")
	link("2000000000000000011", 4, "https://example.com/post#frag", "other", "ok")
	link("2000000000000000011", 5, "", "other", "pending")
	link("2000000000000000011", 6, "https://failed.example/", "other", "failed")
	post(gpu, "2000000000000000012", "1002", sitetest.Ago(2))
	link("2000000000000000012", 0, "https://GitHub.com/o/r/commit/abc/", "patch", "ok")
	link("2000000000000000012", 1, "https://www.exploit-db.com/exploits/1", "poc", "ok")
	link("2000000000000000012", 2, "https://example.com/post", "other", "ok")
	link("2000000000000000012", 3, "https://user:pw@evil.example/", "other", "ok")
	link("2000000000000000012", 4, "ftp://files.example/x", "other", "ok")
	post(gpu, "2000000000000000013", "1003", sitetest.Ago(1))
	link("2000000000000000013", 0, "https://disabled.example/only", "other", "ok")
	link("2000000000000000013", 1, "https://example.com/a", "other", "ok")
	post(gpu, "2000000000000000014", "1001", sitetest.Ago(1))
	link("2000000000000000014", 0, "https://github.com/o/r", "code", "ok")
	link("2000000000000000014", 1, "https://msrc.microsoft.com/update-guide/x", "advisory", "ok")
	link("2000000000000000014", 2, "https://example.com/a", "other", "ok")
	link("2000000000000000014", 3, "https://exploit-db.com/exploits/2", "poc", "ok")
	link("2000000000000000014", 4, "https://example.com/post", "other", "ok") // same author again: still 2
	post("CVE-2026-1001", "2000000000000000015", "1001", sitetest.Ago(1))
	link("2000000000000000015", 0, "https://elsewhere.example/", "other", "ok")
}

func TestResources(t *testing.T) {
	st, d, _ := seeded(t)
	seedLinks(t, sitetest.Seeder{T: t, Conn: d.Conn})
	// titles: the API title (QZTITLE) wins over a fetched one; without an
	// API title the fetched title of the same key (web_page, status 'ok')
	for _, q := range []string{
		`UPDATE x_post_link SET title = NULL WHERE final_url IN ('https://exploit-db.com/exploits/2', 'https://msrc.microsoft.com/update-guide/x')`,
		`UPDATE x_post_link SET title = '  ' WHERE final_url = 'https://github.com/o/r'`,
		`INSERT INTO web_page (url_key, url, first_source, status, title) VALUES
			('https://exploit-db.com/exploits/2', 'https://exploit-db.com/exploits/2/', 'xposts', 'ok', 'Fetched EDB &amp; co'),
			('https://msrc.microsoft.com/update-guide/x', 'https://msrc.microsoft.com/update-guide/x', 'xposts', 'none', NULL),
			('https://github.com/o/r', 'https://github.com/o/r', 'xposts', 'pending', NULL),
			('https://github.com/o/r/commit/abc', 'https://github.com/o/r/commit/abc', 'xposts', 'ok', 'Fetched GH')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := st.Resources(ctx, sitetest.GPU)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, fmt.Sprintf("%s|%s|%s|%d|%s", r.Kind, r.URL, r.Host, r.Researchers, r.Title))
	}
	want := []string{
		"poc|https://www.exploit-db.com/exploits/1|h.example|1|QZTITLE",
		"poc|https://exploit-db.com/exploits/2|h.example|1|Fetched EDB &amp; co",
		"patch|https://github.com/o/r/commit/abc|h.example|2|QZTITLE",
		"advisory|https://msrc.microsoft.com/update-guide/x|h.example|1|",
		"code|https://github.com/o/r|h.example|1|",
		"other|https://example.com/post#frag|h.example|2|QZTITLE",
		"other|https://example.com/a|h.example|1|QZTITLE",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("resources:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// first mentioned: the UTC day of the earliest (enabled) post per link;
	// no publication time without migration data
	got = nil
	for _, r := range rs {
		got = append(got, r.URL+"|"+r.FirstMentioned)
		if r.Published != nil || r.PublishedPrecision != "" {
			t.Errorf("%s: published %v %q before any was stored", r.URL, r.Published, r.PublishedPrecision)
		}
	}
	want = []string{"https://www.exploit-db.com/exploits/1|2026-11-11", "https://exploit-db.com/exploits/2|2026-11-12",
		"https://github.com/o/r/commit/abc|2026-11-10", "https://msrc.microsoft.com/update-guide/x|2026-11-12",
		"https://github.com/o/r|2026-11-12", "https://example.com/post#frag|2026-11-10", "https://example.com/a|2026-11-12"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("first mentioned:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// publication times of 'ok' pages only (also for a link with an API title)
	for _, q := range []string{
		`UPDATE web_page SET published_at = '2026-11-01 10:00:00+02', published_precision = 'exact', published_source = 'json-ld'
			WHERE url_key = 'https://exploit-db.com/exploits/2'`,
		`UPDATE web_page SET published_at = '2026-10-30', published_precision = 'day', published_source = 'meta:date'
			WHERE url_key IN ('https://github.com/o/r/commit/abc', 'https://msrc.microsoft.com/update-guide/x')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	rs, err = st.Resources(ctx, sitetest.GPU)
	if err != nil {
		t.Fatal(err)
	}
	pub := map[string]string{}
	for _, r := range rs {
		if r.Published != nil {
			pub[r.URL] = r.Published.Format(time.RFC3339) + " " + r.PublishedPrecision
		}
	}
	if len(pub) != 2 || pub["https://exploit-db.com/exploits/2"] != "2026-11-01T08:00:00Z exact" ||
		pub["https://github.com/o/r/commit/abc"] != "2026-10-30T00:00:00Z day" || rs[1].Title != "Fetched EDB &amp; co" || rs[2].Title != "QZTITLE" {
		t.Errorf("published: %v", pub)
	}

	// none for a CVE without links; [] not nil
	rs, err = st.Resources(ctx, "CVE-2026-1003")
	if err != nil || rs == nil || len(rs) != 0 {
		t.Errorf("no links: %v %v", rs, err)
	}

	// signed-in data: every resolved link of each post, in order
	ps, err := st.MemberPosts(ctx, sitetest.GPU)
	if err != nil {
		t.Fatal(err)
	}
	links := map[string][]string{}
	for _, p := range ps {
		if p.Links == nil {
			t.Errorf("%s: nil Links", p.PostID)
		}
		for _, l := range p.Links {
			links[p.PostID] = append(links[p.PostID], l.ShortURL+">"+l.FinalURL+"|"+l.Kind)
		}
	}
	if got, want := strings.Join(links["2000000000000000011"], " "), "https://t.co/s110>https://github.com/o/r/commit/abc|patch "+
		"https://t.co/s111>https://pbs.twimg.com/media/x.jpg|media https://t.co/s112>https://x.com/foo/status/1|quote "+
		"https://t.co/s113>javascript:alert(1)|other https://t.co/s114>https://example.com/post#frag|other"; got != want {
		t.Errorf("post 11 links:\n%s\nwant\n%s", got, want)
	}
	if _, ok := links["2000000000000000013"]; ok {
		t.Error("a disabled author's post is listed")
	}
	if n := len(links["2000000000000000014"]); n != 5 {
		t.Errorf("post 14: %d links", n)
	}
}

func TestResourcesFor(t *testing.T) {
	var rows []site.ResourceLink
	for i := 0; i < 40; i++ {
		rows = append(rows, site.ResourceLink{URL: fmt.Sprintf("https://a.example/%d", i), Kind: "other", Author: "1"})
	}
	rows = append(rows, site.ResourceLink{URL: "https://a.example/39/", Kind: "other", Author: "2"},
		site.ResourceLink{URL: "HTTPS://A.EXAMPLE/39#x", Kind: "other", Author: "3"},
		site.ResourceLink{URL: "https://a.example/39?q=1", Kind: "other", Author: "4"},
		site.ResourceLink{URL: "https://www.b.example/p", Kind: "patch", Author: "1"})
	rows[0].Title = "Sign in" // generic: no title
	rows = append(rows, site.ResourceLink{URL: "https://a.example/0#again", Kind: "other", Author: "1", Title: " First\u200b  &amp; real "},
		site.ResourceLink{URL: "https://a.example/0", Kind: "other", Author: "1", Title: "Later title"})
	rs := site.ResourcesFor(rows)
	if len(rs) != site.MaxResources {
		t.Fatalf("%d resources", len(rs))
	}
	if rs[0].URL != "https://www.b.example/p" || rs[0].Host != "b.example" || rs[0].Kind != "patch" {
		t.Errorf("first: %+v", rs[0])
	}
	if rs[1].URL != "https://a.example/39" || rs[1].Researchers != 3 || rs[1].Host != "a.example" {
		t.Errorf("deduplicated: %+v", rs[1])
	}
	if rs[2].Title != "First & real" || rs[3].Title != "" {
		t.Errorf("API titles: %q %q", rs[2].Title, rs[3].Title)
	}
	if rs[2].URL != "https://a.example/0" || rs[3].URL != "https://a.example/1" {
		t.Errorf("first seen order: %+v %+v", rs[2], rs[3])
	}
	for _, u := range []string{"javascript:alert(1)", "data:text/html,x", "//a.example/x", "/x", "https://", "https://u@a.example/",
		"mailto:a@b.example", "http:a.example", "https://a.example/" + strings.Repeat("x", 3000)} {
		if k, ok := site.ResourceKey(u); ok {
			t.Errorf("%q accepted as %q", u, k)
		}
	}
	if k, _ := site.ResourceKey("HTTP://Example.COM/A/?b#c"); k != "http://example.com/A?b" {
		t.Errorf("key %q", k)
	}
	if got := site.ResourcesFor(nil); got == nil || len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}

// TestResourcesFirstMentioned: the earliest day of a key's rows, whatever
// the spelling of the URL; "" when no row has a day.
func TestResourcesFirstMentioned(t *testing.T) {
	rs := site.ResourcesFor([]site.ResourceLink{
		{URL: "https://a.example/x", Kind: "other", Author: "1", Day: "2026-11-05"},
		{URL: "https://A.example/x/", Kind: "other", Author: "2", Day: "2026-11-03"},
		{URL: "https://a.example/x#f", Kind: "other", Author: "3", Day: "2026-11-09"},
		{URL: "https://b.example/", Kind: "patch", Author: "1"},
	})
	if len(rs) != 2 || rs[0].FirstMentioned != "" || rs[1].FirstMentioned != "2026-11-03" {
		t.Errorf("%+v", rs)
	}
}
