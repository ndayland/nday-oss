package ghsa

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// TestFetchHarness runs Fetch over a scenario spec of recorded responses
// (served in order, whatever the URL) and writes what happened, for a diff
// against the same spec run through Python's GhsaCollector.fetch with
// httpx.MockTransport. Ad hoc: GHSA_FETCH_SPEC=<spec.json> GHSA_FETCH_OUT=<out.json>.
// Spec/runner/diff live outside the repo (see the port report).
func TestFetchHarness(t *testing.T) {
	specPath, outPath := os.Getenv("GHSA_FETCH_SPEC"), os.Getenv("GHSA_FETCH_OUT")
	if specPath == "" || outPath == "" {
		t.Skip("GHSA_FETCH_SPEC / GHSA_FETCH_OUT not set")
	}
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := pyjson.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	results := pyjson.NewObject()
	for _, s := range spec.(*pyjson.Object).Get("scenarios").([]any) {
		sc := s.(*pyjson.Object)
		var queue []*pyjson.Object
		for _, r := range sc.Get("responses").([]any) {
			queue = append(queue, r.(*pyjson.Object))
		}
		ft := &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
			r := queue[0]
			queue = queue[1:]
			h := http.Header{}
			for _, kv := range r.Get("headers").([]any) {
				p := kv.([]any)
				h.Add(p[0].(string), p[1].(string))
			}
			var body []byte
			if f, ok := r.Get("body_file").(string); ok {
				if body, err = os.ReadFile(f); err != nil {
					t.Fatal(err)
				}
			}
			st, _ := intOf(r.Get("status"))
			return int(st), h, body, nil
		}}
		var sleeps []any
		now, ok := fromISOFormat(sc.Get("now").(string))
		if !ok {
			t.Fatalf("bad now %v", sc.Get("now"))
		}
		opt := func(k string, def int64) *int64 {
			if v, ok := intOf(sc.Get(k)); ok {
				return &v
			}
			return &def
		}
		tok, _ := sc.Get("token").(string)
		c, err := New(Options{Transport: ft, BootstrapDays: opt("bootstrap_days", 7), MaxRequests: opt("max_requests", 10),
			OverlapMinutes: opt("overlap_minutes", 60), Token: &tok, Clock: func() time.Time { return now },
			Sleep: func(_ context.Context, d time.Duration) error {
				sleeps = append(sleeps, d.Seconds())
				return nil
			}, Logger: slog.New(&logCapture{})})
		if err != nil {
			t.Fatal(err)
		}
		var cursor any
		switch {
		case sc.Get("cursor_from") != nil:
			cursor = results.Get(sc.Get("cursor_from").(string)).(*pyjson.Object).Get("cursor")
		case sc.Get("cursor_text") != nil:
			if cursor, err = pyjson.DecodeString(sc.Get("cursor_text").(string)); err != nil {
				t.Fatal(err)
			}
		default:
			cursor = sc.Get("cursor")
		}
		state := model.CollectorState{Source: Name, Cursor: cursor}
		if sc.Get("first_run") != true {
			ok := time.Date(2026, 11, 12, 15, 0, 26, 0, time.UTC)
			state.LastSuccessAt = &ok
		}
		out := pyjson.NewObject()
		out.Set("error", nil)
		out.Set("cursor", nil)
		recs := []any{}
		res, err := c.Fetch(context.Background(), state)
		if err != nil {
			out.Set("error", err.Error())
		} else {
			out.Set("cursor", res.Cursor)
			for _, r := range res.Records {
				h, _ := r.ContentHash()
				recs = append(recs, []any{r.SourceKey, h})
			}
		}
		out.Set("records", recs)
		urls, hdrs := []any{}, []any{}
		for _, r := range ft.Requests {
			urls = append(urls, r.URL)
			h := pyjson.NewObject()
			for _, k := range []string{"User-Agent", "Accept", "X-GitHub-Api-Version"} {
				if v := r.Header.Values(k); len(v) > 0 {
					h.Set(lower(k), v[0])
				} else {
					h.Set(lower(k), nil)
				}
			}
			switch a := r.Header.Values("Authorization"); {
			case len(a) == 0:
				h.Set("authorization", nil)
			case a[0] == "Bearer "+tok:
				h.Set("authorization", "Bearer <token>")
			default:
				h.Set("authorization", "OTHER")
			}
			hdrs = append(hdrs, h)
		}
		out.Set("urls", urls)
		out.Set("headers", hdrs)
		if sleeps == nil {
			sleeps = []any{}
		}
		out.Set("sleeps", sleeps)
		out.Set("requests_made", c.RequestsMade)
		out.Set("unused_responses", len(queue))
		results.Set(sc.Get("name").(string), out)
	}
	s, err := pyjson.Encode(results, pyjson.Options{Indent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func intOf(v any) (int64, bool) {
	n, ok := v.(pyjson.Int)
	if !ok {
		return 0, false
	}
	var x int64
	for _, c := range string(n) {
		x = x*10 + int64(c-'0')
	}
	return x, true
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
