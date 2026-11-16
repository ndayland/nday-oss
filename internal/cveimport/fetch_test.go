package cveimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/httpc"
)

func noSleep(context.Context, time.Duration) error { return nil }

func resp(r *http.Request, status int, hdr http.Header, body []byte) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: hdr, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: r, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
}

func TestLocateFollowsLatestRedirect(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.String())
		mu.Unlock()
		switch {
		case r.URL.String() == LatestURL:
			return resp(r, 302, http.Header{"Location": {"https://github.com/CVEProject/cvelistV5/releases/tag/cve_2026-11-13_0400Z"}}, nil), nil
		case r.Method == http.MethodHead && r.URL.String() == AssetURL("cve_2026-11-13_0400Z", "2026-11-13_all_CVEs_at_midnight.zip.zip"):
			h := http.Header{"Etag": {`"0xABC"`}}
			x := resp(r, 200, h, nil)
			x.ContentLength = 661998144
			return x, nil
		}
		return resp(r, 404, nil, []byte("Not Found")), nil
	})
	b, err := Locate(context.Background(), LocateOptions{Transport: rt, Now: func() time.Time { return time.Date(2026, 11, 13, 4, 41, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if b.Tag != "cve_2026-11-13_0400Z" || b.Asset != "2026-11-13_all_CVEs_at_midnight.zip.zip" || b.Size != 661998144 ||
		b.ETag != `"0xABC"` || !b.Date.Equal(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", b)
	}
	if len(seen) != 2 {
		t.Fatalf("requests: %v", seen)
	}
}

func TestLocateProbesHourlyTagsWhenLatestUnusable(t *testing.T) {
	var seen []string
	good := AssetURL("cve_2026-11-12_2200Z", "2026-11-12_all_CVEs_at_midnight.zip.zip")
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Method+" "+r.URL.String())
		if r.URL.String() == LatestURL {
			return resp(r, 429, nil, nil), nil // e.g. throttled
		}
		if r.Method == http.MethodHead && r.URL.String() == good {
			x := resp(r, 200, nil, nil)
			x.ContentLength = 1234
			return x, nil
		}
		return resp(r, 404, nil, nil), nil
	})
	now := time.Date(2026, 11, 13, 1, 30, 0, 0, time.UTC)
	b, err := Locate(context.Background(), LocateOptions{Transport: rt, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if b.URL != good || b.Size != 1234 {
		t.Fatalf("%+v", b)
	}
	// latest, then 0100Z, 0000Z of today, then 2300Z, 2200Z of yesterday.
	want := []string{"GET " + LatestURL,
		"HEAD " + AssetURL("cve_2026-11-13_0100Z", "2026-11-13_all_CVEs_at_midnight.zip.zip"),
		"HEAD " + AssetURL("cve_2026-11-13_0000Z", "2026-11-13_all_CVEs_at_midnight.zip.zip"),
		"HEAD " + AssetURL("cve_2026-11-12_2300Z", "2026-11-12_all_CVEs_at_midnight.zip.zip"),
		"HEAD " + good}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(seen, "\n"))
	}
}

func TestLocateGivesUp(t *testing.T) {
	n := 0
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		n++
		return resp(r, 404, nil, nil), nil
	})
	_, err := Locate(context.Background(), LocateOptions{Transport: rt, MaxDays: 2,
		Now: func() time.Time { return time.Date(2026, 11, 13, 3, 0, 0, 0, time.UTC) }})
	if err == nil || n != 1+4+24 {
		t.Fatalf("err=%v requests=%d", err, n)
	}
}

// rangeServer serves data with Range support; cutAt[i] truncates the i-th
// GET body after that many bytes with a transport error (0 = no cut).
type rangeServer struct {
	data        []byte
	etag        string
	cutAt       []int
	ignoreRange bool
	gets        []string // Range header of each GET
}

type cutBody struct {
	r   io.Reader
	n   int
	err error
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, c.err
	}
	if len(p) > c.n {
		p = p[:c.n]
	}
	k, err := c.r.Read(p)
	c.n -= k
	return k, err
}
func (c *cutBody) Close() error { return nil }

func (s *rangeServer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return resp(r, 405, nil, nil), nil
	}
	rng := r.Header.Get("Range")
	s.gets = append(s.gets, rng)
	i := len(s.gets) - 1
	body, status, hdr := s.data, 200, http.Header{"Etag": {s.etag}}
	if rng != "" && !s.ignoreRange && (r.Header.Get("If-Range") == "" || r.Header.Get("If-Range") == s.etag) {
		var from int
		fmt.Sscanf(rng, "bytes=%d-", &from)
		if from >= len(s.data) {
			return resp(r, 416, nil, nil), nil
		}
		body, status = s.data[from:], 206
		hdr.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(s.data)-1, len(s.data)))
	}
	x := resp(r, status, hdr, body)
	if i < len(s.cutAt) && s.cutAt[i] > 0 {
		x.Body = &cutBody{r: bytes.NewReader(body), n: s.cutAt[i], err: errors.New("connection reset by peer")}
	}
	return x, nil
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7 % 251)
	}
	return b
}

func TestDownloadResumesAfterCutAndAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	data := payload(1 << 20)
	s := &rangeServer{data: data, etag: `"e1"`, cutAt: []int{300_000, 200_000}}
	b := &Baseline{Asset: "2026-11-13_all_CVEs_at_midnight.zip.zip", URL: "https://example.invalid/x", Size: int64(len(data)), ETag: `"e1"`}
	// Run 1: two cut transfers, then attempts exhausted (Attempts=2).
	_, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, Attempts: 2, Sleep: noSleep})
	if err == nil {
		t.Fatal("expected failure")
	}
	fi, err := os.Stat(filepath.Join(dir, b.Asset+".part"))
	if err != nil || fi.Size() != 500_000 {
		t.Fatalf("part: %v %v", fi, err)
	}
	// Run 2 (new process): resumes from 500000.
	dl, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dl.Path)
	if !bytes.Equal(got, data) || !dl.Resumed || dl.Size != int64(len(data)) || len(dl.SHA256) != 64 {
		t.Fatalf("resumed=%v size=%d", dl.Resumed, len(got))
	}
	if strings.Join(s.gets, ",") != ",bytes=300000-,bytes=500000-" {
		t.Fatalf("ranges: %q", s.gets)
	}
	if _, err := os.Stat(filepath.Join(dir, b.Asset+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("part file left behind")
	}
	// Run 3: complete file reused, no request.
	n := len(s.gets)
	if _, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, Sleep: noSleep}); err != nil || len(s.gets) != n {
		t.Fatalf("reuse: %v, %d requests", err, len(s.gets)-n)
	}
}

func TestDownloadRestartsWhenRangeIgnoredOrObjectChanged(t *testing.T) {
	dir := t.TempDir()
	data := payload(100_000)
	s := &rangeServer{data: data, etag: `"e1"`, cutAt: []int{40_000}, ignoreRange: true}
	b := &Baseline{Asset: "a.zip.zip", URL: "https://example.invalid/a", Size: int64(len(data)), ETag: `"e1"`}
	dl, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dl.Path); !bytes.Equal(got, data) || dl.Resumed {
		t.Fatal("content mismatch after restart")
	}
	// A stale part file of another object (different etag) is discarded.
	os.Remove(dl.Path)
	os.WriteFile(filepath.Join(dir, "a.zip.zip.part"), []byte("garbage-of-another-version"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.zip.zip.part.json"), []byte(`{"url":"https://example.invalid/a","size":100000,"etag":"\"old\""}`), 0o644)
	s2 := &rangeServer{data: data, etag: `"e1"`}
	dl, err = Download(context.Background(), b, dir, DownloadOptions{Transport: s2, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dl.Path); !bytes.Equal(got, data) || s2.gets[0] != "" {
		t.Fatalf("stale part reused: ranges %q", s2.gets)
	}
}

func TestDownloadSizeCaps(t *testing.T) {
	dir := t.TempDir()
	data := payload(10_000)
	s := &rangeServer{data: data, etag: `"e"`}
	// Advertised size over the cap: refused before any request.
	b := &Baseline{Asset: "a", URL: "https://example.invalid/a", Size: 10_000}
	if _, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, MaxBytes: 5000, Sleep: noSleep}); err == nil || len(s.gets) != 0 {
		t.Fatalf("err=%v gets=%d", err, len(s.gets))
	}
	// Unknown size, body over the cap: permanent error, no retry.
	b = &Baseline{Asset: "b", URL: "https://example.invalid/b"}
	_, err := Download(context.Background(), b, dir, DownloadOptions{Transport: s, MaxBytes: 5000, Sleep: noSleep})
	if err == nil || !strings.Contains(err.Error(), "cap") || len(s.gets) != 1 {
		t.Fatalf("err=%v gets=%d", err, len(s.gets))
	}
	// Advertised size differs from what the server sends: retried, then fails.
	s3 := &rangeServer{data: data, etag: `"e"`}
	b = &Baseline{Asset: "c", URL: "https://example.invalid/c", Size: 9_999}
	_, err = Download(context.Background(), b, dir, DownloadOptions{Transport: s3, Attempts: 3, Sleep: noSleep})
	if err == nil || len(s3.gets) != 3 {
		t.Fatalf("err=%v gets=%d", err, len(s3.gets))
	}
}

func TestDownloadRetriesServerErrorsButNot404(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls < 3 {
			return resp(r, 503, nil, nil), nil
		}
		return resp(r, 200, nil, []byte("hello")), nil
	})
	b := &Baseline{Asset: "a", URL: "https://example.invalid/a", Size: 5}
	if dl, err := Download(context.Background(), b, dir, DownloadOptions{Transport: rt, Sleep: noSleep}); err != nil || calls != 3 || dl.Size != 5 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	calls = 0
	rt404 := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return resp(r, 404, nil, nil), nil
	})
	b = &Baseline{Asset: "b", URL: "https://example.invalid/b", Size: 5}
	if _, err := Download(context.Background(), b, dir, DownloadOptions{Transport: rt404, Sleep: noSleep}); err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSnapshotDateFromName(t *testing.T) {
	d, ok := SnapshotDateFromName("/data/x/2026-11-13_all_CVEs_at_midnight.zip.zip")
	if !ok || !d.Equal(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(d, ok)
	}
	if _, ok := SnapshotDateFromName("cves.zip"); ok {
		t.Fatal("matched")
	}
}
