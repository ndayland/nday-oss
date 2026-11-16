package feed_test

// Go-only unit tests of _feed.py semantics not covered by the Python tests.

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"testing"

	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/feed/feedtest"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestScrubNulKeysValuesAndCount(t *testing.T) {
	v, err := pyjson.DecodeString(`{"a\u0000": ["x\u0000y", 1, {"k": "\u0000\u0000"}], "b": "ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	out, n := feed.ScrubNul(v)
	s, _ := pyjson.Encode(out, pyjson.Options{})
	if n != 3 || s != `{"a\\u0000": ["x\\u0000y", 1, {"k": "\\u0000\\u0000"}], "b": "ok"}` {
		t.Errorf("%d %s", n, s)
	}
}

func TestSplitCVEIDs(t *testing.T) {
	valid, dropped := feed.SplitCVEIDs([]any{" cve-2020-0001 ", "CVE-2020-0001", "CVE-2019–9193", pyjson.Int("5"), nil, "CVE-2020-0002"})
	if pyjson.Repr(feed.Strings(valid)) != "['CVE-2020-0001', 'CVE-2020-0002']" ||
		pyjson.Repr(feed.Strings(dropped)) != "['CVE-2019–9193', '5', 'None']" {
		t.Errorf("%q %q", valid, dropped)
	}
	_, _, err := feed.RequireCVEs("k", nil)
	if err == nil || err.Error() != "k: no valid CVE id among []" {
		t.Error(err)
	}
}

func fetchWith(t *testing.T, cursor any, h func(*http.Request) (int, http.Header, []byte, error)) (*testutil.FakeTransport, any, error) {
	ft := &testutil.FakeTransport{Handler: h}
	c, err := feedtest.Nuclei.New(feed.Options{Transport: ft, Sleep: (&feedtest.NoSleep{}).Sleep})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Fetch(context.Background(), modelState(cursor))
	if err != nil {
		return ft, nil, err
	}
	return ft, res.Cursor, nil
}

func TestEmptyGzip304AndHeaderJoin(t *testing.T) {
	prev, _ := pyjson.DecodeString(`{"url": "` + feedtest.Nuclei.URL + `", "etag": "\"a\"", "last_modified": "Mon, 01 Jan 2026 00:00:00 GMT", "feed": null}`)
	// 304 with Content-Encoding: gzip and no body (httpx: empty decode is fine);
	// no ETag in the 304 -> the sent validator is kept (resp ETag `or` etag).
	ft, cur, err := fetchWith(t, prev, func(r *http.Request) (int, http.Header, []byte, error) {
		return 304, http.Header{"Content-Encoding": {"gzip"}}, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if h := ft.Requests[0].Header; h.Get("If-None-Match") != `"a"` || h.Get("If-Modified-Since") != "Mon, 01 Jan 2026 00:00:00 GMT" {
		t.Errorf("%v", h)
	}
	s, _ := pyjson.Canonical(cur)
	if s != `{"etag":"\"a\"","feed":null,"last_modified":"Mon, 01 Jan 2026 00:00:00 GMT","last_run":{"attempts":1,"http_status":304},"url":"`+feedtest.Nuclei.URL+`"}` {
		t.Error(s)
	}
	// Several ETag headers are joined with ", " (httpx headers.get); an empty
	// Last-Modified is "" (not None) on a 200.
	body := []byte(`{"ID":"CVE-2020-1234","Info":{},"file_path":"x"}` + "\n")
	_, cur, err = fetchWith(t, nil, func(r *http.Request) (int, http.Header, []byte, error) {
		return 200, http.Header{"Etag": {`"x"`, `"y"`}, "Last-Modified": {""}, "Content-Encoding": {"gzip"}}, gz(body), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	o := cur.(*pyjson.Object)
	if o.Get("etag") != `"x", "y"` || o.Get("last_modified") != "" || o.Get("feed").(*pyjson.Object).Get("bytes") != pyjson.IntOf(int64(len(body))) {
		t.Errorf("%s", pyjson.Repr(o))
	}
	// A truthy non-string validator in the cursor cannot be sent (httpx raises).
	bad, _ := pyjson.DecodeString(`{"url": "` + feedtest.Nuclei.URL + `", "etag": 5}`)
	if _, _, err := fetchWith(t, bad, nil); err == nil {
		t.Error("non-string etag accepted")
	}
}
