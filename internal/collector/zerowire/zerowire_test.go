package zerowire_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector/zerowire"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(arts []zerowire.Article, slug string) *zerowire.Article {
	for i := range arts {
		if arts[i].Slug == slug {
			return &arts[i]
		}
	}
	return nil
}

// The saved copy of the real feed, trimmed to three advisories.
func TestParseFeedSample(t *testing.T) {
	arts, st, err := zerowire.ParseFeed(fixture(t, "feed_sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 3 || st.Items != 3 || st.BadLink != 0 || st.Duplicate != 0 {
		t.Fatalf("%d articles, %+v", len(arts), st)
	}
	ruby := find(arts, "ruby2shell")
	if ruby == nil || ruby.Title != "ruby2shell: heap overflow in Ruby string case conversion" ||
		ruby.Link != "https://radar.cloudflare.com/zero-wire/ruby2shell" || ruby.PubDate != "2026-11-19" {
		t.Fatalf("%+v", ruby)
	}
	if !slices.Equal(ruby.CVEs, []string{"CVE-2026-132825"}) || !slices.Equal(ruby.GHSAs, []string{"GHSA-34m4-m9fh-gqp5", "GHSA-87fm-7w84-j2px"}) {
		t.Errorf("ruby ids %v %v", ruby.CVEs, ruby.GHSAs)
	}
	nginx := find(arts, "nginx2root")
	want := []string{"CVE-2026-123007", "CVE-2026-123633", "CVE-2026-121810", "CVE-2026-123634", "CVE-2026-113425", "CVE-2026-118899", "CVE-2026-120993"}
	if nginx == nil || !slices.Equal(nginx.CVEs, want) || len(nginx.GHSAs) != 0 || nginx.PubDate != "2026-11-18" {
		t.Errorf("nginx %+v", nginx)
	}
	em := find(arts, "emudhra-certificate-compromise")
	if em == nil || len(em.CVEs)+len(em.GHSAs) != 0 || em.Title != "eMudhra certificate compromise" || em.PubDate != "2026-10-30" {
		t.Errorf("emudhra %+v", em)
	}
}

func item(title, link, pub, desc, content string) string {
	return `<item><title>` + title + `</title><link>` + link + `</link><guid isPermaLink="false">x@2026-11-19</guid>` +
		`<pubDate>` + pub + `</pubDate><dc:creator>Cloudforce One</dc:creator><description>` + desc + `</description>` +
		`<content:encoded><![CDATA[` + content + `]]></content:encoded><category>Patch now</category><unknown a="b">x</unknown></item>`
}

func feed(items ...string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Zero Wire | Cloudflare Radar</title>` + strings.Join(items, "\n") + `</channel></rss>`)
}

const nov19 = "Thu, 19 Nov 2026 00:00:00 GMT"

func TestParseFeedLinksAndTitles(t *testing.T) {
	body := feed(
		item("ok", "https://radar.cloudflare.com/zero-wire/good-one", nov19, "CVE-2026-1111", ""),
		item("http", "http://radar.cloudflare.com/zero-wire/plain-http", nov19, "CVE-2026-1", ""),
		item("host", "https://radar.cloudflare.com.evil.example/zero-wire/x", nov19, "CVE-2026-1", ""),
		item("other path", "https://radar.cloudflare.com/blog/x", nov19, "CVE-2026-1", ""),
		item("query", "https://radar.cloudflare.com/zero-wire/x?a=1", nov19, "CVE-2026-1", ""),
		item("slash", "https://radar.cloudflare.com/zero-wire/x/y", nov19, "CVE-2026-1", ""),
		item("upper", "https://radar.cloudflare.com/zero-wire/Upper", nov19, "CVE-2026-1", ""),
		item("leading dash", "https://radar.cloudflare.com/zero-wire/-x", nov19, "CVE-2026-1", ""),
		item("too long", "https://radar.cloudflare.com/zero-wire/"+strings.Repeat("a", 201), nov19, "CVE-2026-1", ""),
		item("again", "https://radar.cloudflare.com/zero-wire/good-one", nov19, "CVE-2026-2222", ""),
		// hostile title: bidi override, zero-width space, a control, markup, overlong
		item("A\u202e\u200btxt.exe\u009b &amp;lt;script&amp;gt;  x "+strings.Repeat("y", 400),
			" https://radar.cloudflare.com/zero-wire/hostile ", "garbage",
			"", `<a href="https://github.com/advisories/GHSA-2CM2-M3W5-GP2F">advisory</a> and CVE&#45;2026&#45;5555, cve-2026-5556`),
	)
	arts, st, err := zerowire.ParseFeed(body)
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	for _, a := range arts {
		slugs = append(slugs, a.Slug)
	}
	if !slices.Equal(slugs, []string{"good-one", "hostile"}) || st.BadLink != 8 || st.Duplicate != 1 || st.Items != 11 {
		t.Fatalf("%v %+v", slugs, st)
	}
	if !slices.Equal(arts[0].CVEs, []string{"CVE-2026-1111"}) || !slices.Equal(arts[0].Categories, []string{"Patch now"}) {
		t.Errorf("%+v", arts[0])
	}
	h := arts[1]
	if !strings.HasPrefix(h.Title, "Atxt.exe <script> x yyy") || !strings.HasSuffix(h.Title, "…") ||
		len([]rune(h.Title)) != zerowire.MaxTitleRunes || strings.ContainsAny(h.Title, "\u202e\u200b\u009b") {
		t.Errorf("title %q", h.Title)
	}
	if h.PubDate != "" {
		t.Errorf("pub date %q", h.PubDate)
	}
	if !slices.Equal(h.GHSAs, []string{"GHSA-2cm2-m3w5-gp2f"}) || !slices.Equal(h.CVEs, []string{"CVE-2026-5556", "CVE-2026-5555"}) {
		t.Errorf("ids %v %v", h.CVEs, h.GHSAs)
	}
}

func TestParseFeedNotRSS(t *testing.T) {
	for _, b := range []string{"<html><body>maintenance</body></html>", "not xml", `<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title></item></channel></rss>`} {
		if _, _, err := zerowire.ParseFeed([]byte(b)); err == nil {
			t.Errorf("no error for %q", b)
		}
	}
}

// --- fake network ---

type fakeNet struct {
	mu      sync.Mutex
	reqs    []*http.Request
	handler func(r *http.Request) *http.Response
}

func (f *fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	resp := f.handler(r)
	resp.Request = r
	return resp, nil
}

func respond(status int, hdr map[string]string, body []byte) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: -1}
}

func newCollector(f *fakeNet) *zerowire.Collector {
	return zerowire.New(zerowire.Options{Transport: f, Sleep: func(context.Context, time.Duration) error { return nil },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func cursorOf(etag any) any {
	o := pyjson.NewObject()
	o.Set("etag", etag)
	o.Set("last_modified", nil)
	return o
}

func TestFetch(t *testing.T) {
	f := &fakeNet{}
	f.handler = func(r *http.Request) *http.Response {
		if r.Header.Get("If-None-Match") == `"v1"` {
			return respond(http.StatusNotModified, nil, nil)
		}
		return respond(200, map[string]string{"ETag": `"v1"`}, fixture(t, "feed_sample.xml"))
	}
	c := newCollector(f)
	res, err := c.Fetch(context.Background(), model.CollectorState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 || f.reqs[0].URL.String() != zerowire.FeedURL || f.reqs[0].Header.Get("User-Agent") != httpc.UserAgent ||
		f.reqs[0].Header.Get("If-None-Match") != "" {
		t.Fatalf("requests %v", f.reqs)
	}
	var keys []string
	for _, r := range res.Records {
		keys = append(keys, r.SourceKey)
	}
	if !slices.Equal(keys, []string{"ruby2shell", "nginx2root", "emudhra-certificate-compromise"}) {
		t.Errorf("keys %v", keys)
	}
	got, _ := pyjson.Encode(res.Records[0].Payload, pyjson.Options{})
	want := `{"slug": "ruby2shell", "title": "ruby2shell: heap overflow in Ruby string case conversion", "link": "https://radar.cloudflare.com/zero-wire/ruby2shell", "pub_date": "2026-11-19", "cve_ids": ["CVE-2026-132825"], "ghsa_ids": ["GHSA-34m4-m9fh-gqp5", "GHSA-87fm-7w84-j2px"], "categories": ["Memory corruption", "RCE", "Ruby", "Runtime"]}`
	if got != want {
		t.Errorf("payload\n%s\nwant\n%s", got, want)
	}
	cur, _ := pyjson.Encode(res.Cursor, pyjson.Options{})
	if cur != `{"etag": "\"v1\"", "last_modified": null, "last_run": {"status": 200, "items": 3, "records": 3, "without_ids": 1, "skipped_bad_link": 0, "skipped_duplicate": 0}}` {
		t.Errorf("cursor %s", cur)
	}

	// second run: conditional, 304, nothing
	res, err = c.Fetch(context.Background(), model.CollectorState{Cursor: res.Cursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || f.reqs[1].Header.Get("If-None-Match") != `"v1"` {
		t.Errorf("%d records, %v", len(res.Records), f.reqs[1].Header)
	}
	if o := res.Cursor.(*pyjson.Object); o.Get("etag") != `"v1"` {
		t.Errorf("etag lost: %v", o.Get("etag"))
	}
}

func TestFetchRefusesOffHostRedirect(t *testing.T) {
	for _, loc := range []string{"https://evil.example/zero-wire/feed", "http://radar.cloudflare.com/zero-wire/feed"} {
		f := &fakeNet{}
		f.handler = func(r *http.Request) *http.Response {
			if r.URL.Host != zerowire.Host || r.URL.Scheme != "https" {
				t.Errorf("request went to %s", r.URL)
			}
			return respond(http.StatusFound, map[string]string{"Location": loc}, nil)
		}
		_, err := newCollector(f).Fetch(context.Background(), model.CollectorState{})
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%s: err %v", loc, err)
		}
		for _, r := range f.reqs {
			if r.URL.String() != zerowire.FeedURL {
				t.Errorf("%s: request to %s", loc, r.URL)
			}
		}
	}
	// a redirect on the same host is fine
	f := &fakeNet{}
	f.handler = func(r *http.Request) *http.Response {
		if r.URL.Path == "/zero-wire/feed" {
			return respond(http.StatusMovedPermanently, map[string]string{"Location": "/zero-wire/feed.xml"}, nil)
		}
		return respond(200, nil, fixture(t, "feed_sample.xml"))
	}
	if res, err := newCollector(f).Fetch(context.Background(), model.CollectorState{}); err != nil || len(res.Records) != 3 {
		t.Errorf("same-host redirect: %v", err)
	}
}

func TestFetchSizeCap(t *testing.T) {
	f := &fakeNet{}
	f.handler = func(*http.Request) *http.Response {
		return respond(200, nil, bytes.Repeat([]byte("x"), zerowire.MaxBytes+1))
	}
	_, err := newCollector(f).Fetch(context.Background(), model.CollectorState{})
	var tl *httpc.TooLargeError
	if err == nil || !errors.As(err, &tl) {
		t.Errorf("err %v", err)
	}
	if len(f.reqs) != 1 {
		t.Errorf("%d requests: a too-large body is not retried", len(f.reqs))
	}
	// a page that isn't RSS fails the run
	f.handler = func(*http.Request) *http.Response { return respond(200, nil, []byte("<html>maintenance</html>")) }
	if _, err := newCollector(f).Fetch(context.Background(), model.CollectorState{}); err == nil {
		t.Error("no error")
	}
}

func TestNormalize(t *testing.T) {
	c := zerowire.New(zerowire.Options{})
	arts, _, err := zerowire.ParseFeed(fixture(t, "feed_sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Normalize(zerowire.Record(*find(arts, "ruby2shell")))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range n.Events {
		ids = append(ids, e.CVEID)
		if e.Type != model.EventAnalysisPublished || e.Source != "zerowire" || e.DedupeKey != "ruby2shell" ||
			*e.URL != "https://radar.cloudflare.com/zero-wire/ruby2shell" ||
			!e.OccurredAt.Equal(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%+v", e)
		}
	}
	if !slices.Equal(ids, []string{"CVE-2026-132825", "GHSA-34m4-m9fh-gqp5", "GHSA-87fm-7w84-j2px"}) {
		t.Errorf("ids %v", ids)
	}
	d, _ := pyjson.Encode(n.Events[0].Detail, pyjson.Options{SortKeys: true})
	if d != `{"precision": "day", "title": "ruby2shell: heap overflow in Ruby string case conversion"}` {
		t.Errorf("detail %s", d)
	}

	// no id: no event
	if n, err := c.Normalize(zerowire.Record(*find(arts, "emudhra-certificate-compromise"))); err != nil || len(n.Events) != 0 {
		t.Errorf("%v %+v", err, n)
	}

	// no date: occurred_at unknown, no precision; implausible years dropped
	a := zerowire.Article{Slug: "x", Link: zerowire.ArticleURL("x"), CVEs: []string{"CVE-1998-1234", "CVE-2026-1234"}}
	n, _ = c.Normalize(zerowire.Record(a))
	if len(n.Events) != 1 || n.Events[0].OccurredAt != nil || n.Events[0].Detail["precision"] != nil || n.Events[0].Detail["title"] != nil {
		t.Errorf("%+v", n.Events)
	}
	a.PubDate = "2026-11-19"
	a.CVEs = []string{"CVE-2031-1234"}
	if n, _ = c.Normalize(zerowire.Record(a)); len(n.Events) != 0 {
		t.Errorf("%+v", n.Events)
	}

	// malformed payloads are NormalizeErrors
	bad := zerowire.Record(a)
	bad.SourceKey = "other"
	for _, r := range []model.RawRecord{bad, {Source: "zerowire", SourceKey: "x", Payload: "nope"},
		zerowire.Record(zerowire.Article{Slug: "x", Link: "https://evil.example/x"}),
		zerowire.Record(zerowire.Article{Slug: "x", Link: zerowire.ArticleURL("x"), PubDate: "Nov 19"})} {
		if _, err := c.Normalize(r); err == nil {
			t.Errorf("no error for %+v", r)
		}
	}
}
