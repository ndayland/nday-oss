package cvelist_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// TestReplayMatchesPython is the fetch-logic parity harness: it runs the Go
// Fetch on a scenario recorded from real upstream files and compares with
// the Python fetch() on the very same scenario (testdata/replay_py.py).
//
//	CVELIST_REPLAY="<scenario.json>=<python_out.json>[,...]" go test -run Replay ./internal/collector/cvelist/
//
// Compared: ordered list of requested URLs (sorted when concurrency > 1,
// where the order is nondeterministic in both implementations), returned
// record keys + is_backfill + content hash, cursor JSON, error presence.
// Skipped when CVELIST_REPLAY is unset (the data is not in the repository).
func TestReplayMatchesPython(t *testing.T) {
	spec := os.Getenv("CVELIST_REPLAY")
	if spec == "" {
		t.Skip("CVELIST_REPLAY not set")
	}
	for _, pair := range strings.Split(spec, ",") {
		scen, pyOut, _ := strings.Cut(pair, "=")
		t.Run(filepath.Base(scen), func(t *testing.T) { replayOne(t, scen, pyOut) })
	}
}

var zipDayRe = regexp.MustCompile(`/cve_(\d{4}-\d{2}-\d{2})_at_end_of_day/`)

func readJSON(t *testing.T, path string) *pyjson.Object {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyjson.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*pyjson.Object)
}

func replayOne(t *testing.T, scenPath, pyPath string) {
	sc := readJSON(t, scenPath)
	want := readJSON(t, pyPath)
	data := sc.Get("data_dir").(string)
	var mu sync.Mutex
	fail := map[string][]int{}
	if f := sc.Get("fail"); f != nil {
		for _, k := range f.(*pyjson.Object).Keys() {
			for _, s := range f.(*pyjson.Object).Get(k).([]any) {
				var n int
				for _, ch := range string(s.(pyjson.Int)) {
					n = n*10 + int(ch-'0')
				}
				fail[k] = append(fail[k], n)
			}
		}
	}
	local := func(url string) string {
		switch {
		case url == cvelist.DeltaLogURL:
			return filepath.Join(data, "deltaLog.json")
		case strings.HasPrefix(url, cvelist.ReleaseBase) && zipDayRe.MatchString(url):
			return filepath.Join(data, "zips", zipDayRe.FindStringSubmatch(url)[1]+".zip")
		case strings.HasPrefix(url, cvelist.RawBase+"/") && strings.HasSuffix(url, ".json"):
			return filepath.Join(data, "records", url[strings.LastIndex(url, "/")+1:])
		}
		return ""
	}
	ft := &testutil.FakeTransport{Handler: func(r *http.Request) (int, http.Header, []byte, error) {
		url := r.URL.String()
		mu.Lock()
		if f := fail[url]; len(f) > 0 {
			fail[url] = f[1:]
			mu.Unlock()
			return f[0], nil, nil, nil
		}
		mu.Unlock()
		p := local(url)
		if p == "" {
			return 404, nil, nil, nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return 404, nil, nil, nil
		}
		return 200, nil, b, nil
	}}
	clock, err := time.Parse(time.RFC3339Nano, sc.Get("clock").(string))
	if err != nil {
		t.Fatal(err)
	}
	num := func(k string) *int {
		v := sc.Get(k).(pyjson.Int)
		n := 0
		for _, ch := range string(v) {
			n = n*10 + int(ch-'0')
		}
		return &n
	}
	conc := *num("concurrency")
	c, err := cvelist.New(cvelist.Options{Transport: ft, BootstrapDays: num("bootstrap_days"), MaxFiles: num("max_files"),
		BackfillRetryDays: num("backfill_retry_days"), Concurrency: conc,
		Clock: func() time.Time { return clock },
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	var wanted []string
	if w, ok := sc.Get("wanted").([]any); ok {
		for _, x := range w {
			wanted = append(wanted, x.(string))
		}
	}
	res, ferr := c.Fetch(context.Background(), model.CollectorState{Source: "cvelist", Cursor: sc.Get("cursor"), Wanted: wanted})

	var gotURLs []string
	for _, r := range ft.Requests {
		gotURLs = append(gotURLs, r.URL)
	}
	var wantURLs []string
	for _, u := range want.Get("urls").([]any) {
		wantURLs = append(wantURLs, u.(string))
	}
	if conc > 1 {
		sort.Strings(gotURLs)
		sort.Strings(wantURLs)
	}
	urlDiff := diffLines(wantURLs, gotURLs)

	gotRec := []any{}
	var gotCur any
	if ferr == nil {
		for _, r := range res.Records {
			h, _ := r.ContentHash()
			gotRec = append(gotRec, []any{r.SourceKey, r.IsBackfill, h})
		}
		gotCur = res.Cursor
	}
	recDiff := canon(t, gotRec) != canon(t, want.Get("records"))
	curDiff := canon(t, gotCur) != canon(t, want.Get("cursor"))
	errDiff := (ferr != nil) != (want.Get("error") != nil)

	t.Logf("python: %d requests, %d records, error=%v", len(wantURLs), len(want.Get("records").([]any)), want.Get("error"))
	t.Logf("go:     %d requests, %d records, error=%v", len(gotURLs), len(gotRec), ferr)
	t.Logf("diff: urls=%d lines, records differ=%v, cursor differs=%v, error differs=%v", len(urlDiff), recDiff, curDiff, errDiff)
	if len(urlDiff) > 0 {
		t.Errorf("URL diff:\n%s", strings.Join(urlDiff, "\n"))
	}
	if recDiff {
		t.Errorf("records differ")
	}
	if curDiff {
		t.Errorf("cursor:\n go  %s\n py  %s", canon(t, gotCur), canon(t, want.Get("cursor")))
	}
	if errDiff {
		t.Errorf("error: go %v, python %v", ferr, want.Get("error"))
	}
	if out := os.Getenv("CVELIST_REPLAY_GO_OUT"); out != "" {
		o := pyjson.NewObject()
		urls := []any{}
		for _, u := range gotURLs {
			urls = append(urls, u)
		}
		o.Set("urls", urls)
		o.Set("records", gotRec)
		o.Set("cursor", gotCur)
		s, _ := pyjson.Encode(o, pyjson.Options{SortKeys: true, Indent: 1})
		_ = os.WriteFile(filepath.Join(out, filepath.Base(scenPath)+".go.json"), []byte(s+"\n"), 0o644)
	}
}

func diffLines(a, b []string) []string {
	var out []string
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			out = append(out, "  #"+itoa(i)+" py="+x+"\n      go="+y)
		}
	}
	return out
}

func itoa(i int) string { return pyjson.Repr(pyjson.IntOf(int64(i))) }
