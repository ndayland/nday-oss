package feed_test

// Port of tests/test_poc_feeds_pipeline.py (parametrized over the three
// sources, like the pytest fixture) and tests/test_poc_cross_source.py.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/feed/feedtest"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var (
	T0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	T1 = T0.Add(24 * time.Hour)
	T2 = T1.Add(24 * time.Hour)
)

func forEach(t *testing.T, f func(t *testing.T, a *feedtest.Adapter)) {
	for _, a := range feedtest.Adapters {
		t.Run(a.Name, func(t *testing.T) {
			t.Parallel()
			f(t, a)
		})
	}
}

func server(t *testing.T, a *feedtest.Adapter, data any, etag string) *feedtest.Server {
	return feedtest.NewServer(t, a.URL, a.Dump(t, data), etag)
}

func canonCursor(t *testing.T, d *testutil.TestDB) string {
	s, err := pyjson.Canonical(feedtest.Cursor(t, d))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The adapters serialize the fixtures byte-for-byte like poc_feed_helpers
// (sha256 of Python's a.dump(a.load()), a.dump(a.changed(...)),
// a.dump(a.without(...))).
func TestAdaptersDumpLikePython(t *testing.T) {
	want := map[string][3]string{
		"exploitdb":  {"f70d60d9a6d0d1602ef8fefa303fec2be89fd8802d43c14ebaaf4446e34d6d5b", "570a0647b651ada3efd32f601cad72ba6e2b08a66c9886a5db97efda6d9f93e7", "401d264a3e39522e6bf0ecde63e98ffaa23ad41eb78a4a15e9d68c6699cd3c2c"},
		"metasploit": {"ad19f72fbb888ea95de1153ebff11278ae7018de5dd699db21ee8cb8897b8742", "fcdc2408d55e5f12356b96c3144f004437a22ad577c04612939a7ddc47cade34", "72eb9ef0cbc10754e706f6045770de234e2b5b344abc9123a2f9aef883ec1864"},
		"nuclei":     {"e708179cd7813770b2f60106859103b1a8a292f295fb3dec40c0232936596f81", "4a3b83a5f0b8d6995ff35bccdbaedeb7feef7809fe1161d3951ed355aea5f82c", "cb242d3928d39044bd138a5cdda7c331b7d8a5cbea16ebb7092af91a55735986"},
	}
	for _, a := range feedtest.Adapters {
		got := [3]string{}
		for i, b := range [][]byte{
			a.Dump(t, a.Load(t)),
			a.Dump(t, a.Changed(t, a.Load(t), a.ChangeKey)),
			a.Dump(t, a.Without(a.Load(t), a.NewKey)),
		} {
			s := sha256.Sum256(b)
			got[i] = hex.EncodeToString(s[:])
		}
		if got != want[a.Name] {
			t.Errorf("%s: %v want %v", a.Name, got, want[a.Name])
		}
	}
}

func TestFirstRunThen304KeepsValidators(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		srv := server(t, a, a.Load(t), `W/"abc"`)
		srv.Gzip = true
		s1 := feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T0, false)
		if !s1.IsBackfill || s1.EventInserted == 0 || s1.VulnUpdated != 0 || s1.AliasInserted != 0 || s1.AffectedInserted != 0 {
			t.Errorf("s1 %+v", s1)
		}
		first := srv.Requests()[0].Header
		if first.Get("User-Agent") != "nday-collector/0.1.0" || first.Get("Accept-Encoding") != "gzip" || first.Values("If-None-Match") != nil {
			t.Errorf("first request headers %v", first)
		}
		cursor := feedtest.Cursor(t, d)
		if cursor.Get("etag") != `W/"abc"` || cursor.Get("url") != a.URL ||
			cursor.Get("last_run").(*pyjson.Object).Get("http_status") != pyjson.Int("200") {
			t.Errorf("cursor %s", pyjson.Repr(cursor))
		}
		if got, want := canonCursor(t, d), feedtest.PyCursors[a.Name+"/first_gzip"]; got != want {
			t.Errorf("cursor vs Python\n got  %s\n want %s", got, want)
		}
		before := feedtest.Counts(t, d)

		s2 := feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T1, false)

		if got := srv.Requests()[1].Header.Get("If-None-Match"); got != `W/"abc"` {
			t.Errorf("If-None-Match %q", got)
		}
		if s2.Fetched != 0 || s2.RawNew != 0 || s2.EventInserted != 0 || s2.EventUpdated != 0 {
			t.Errorf("s2 %+v", s2)
		}
		if feedtest.Counts(t, d) != before {
			t.Error("rows changed on 304")
		}
		status := feedtest.Strings(t, d, "SELECT last_status FROM collector_state")
		cur2 := feedtest.Cursor(t, d)
		if status[0] != "ok" || cur2.Get("etag") != `W/"abc"` {
			t.Errorf("%v %s", status, pyjson.Repr(cur2))
		}
		if lr, _ := pyjson.Canonical(cur2.Get("last_run")); lr != `{"attempts":1,"http_status":304}` {
			t.Errorf("last_run %s", lr)
		}
		f1, _ := pyjson.Canonical(cursor.Get("feed"))
		f2, _ := pyjson.Canonical(cur2.Get("feed"))
		if f1 != f2 {
			t.Errorf("feed counts not kept: %s vs %s", f2, f1)
		}
		if got, want := canonCursor(t, d), feedtest.PyCursors[a.Name+"/304"]; got != want {
			t.Errorf("304 cursor vs Python\n got  %s\n want %s", got, want)
		}
	})
}

func TestValidatorsNotSentForADifferentURL(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		srv := server(t, a, a.Load(t), `"v1"`)
		feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T0, false)
		if _, err := d.Conn.Exec(context.Background(), `UPDATE collector_state SET cursor = jsonb_set(cursor, '{url}', '"https://old.example/x"')`); err != nil {
			t.Fatal(err)
		}
		feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T1, false)
		if v := srv.Requests()[1].Header.Values("If-None-Match"); v != nil {
			t.Errorf("If-None-Match sent: %v", v)
		}
	})
}

func TestNewItemOnLaterRunIsLive(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		data := a.Load(t)
		srv := server(t, a, a.Without(data, a.NewKey), `"v1"`)
		if s1 := feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T0, false); !s1.IsBackfill {
			t.Error("first run must be backfill")
		}
		srv.Set(a.Dump(t, data), `"v2"`)

		s2 := feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T1, false)

		if s2.IsBackfill || s2.RawNew != 1 || s2.EventInserted < 1 || s2.EventUpdated != 0 {
			t.Errorf("s2 %+v", s2)
		}
		rows, err := d.Conn.Query(context.Background(), "SELECT dedupe_key, is_backfill, observed_at FROM event WHERE source = $1", a.Name)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		nNew, nOld := 0, 0
		for rows.Next() {
			var key string
			var bf bool
			var obs time.Time
			if err := rows.Scan(&key, &bf, &obs); err != nil {
				t.Fatal(err)
			}
			if key == a.NewKey {
				nNew++
				if bf || !obs.Equal(T1) {
					t.Errorf("new %s: %v %v", key, bf, obs)
				}
			} else {
				nOld++
				if !bf || !obs.Equal(T0) {
					t.Errorf("old %s: %v %v", key, bf, obs)
				}
			}
		}
		if nNew == 0 || nOld == 0 {
			t.Errorf("new %d old %d", nNew, nOld)
		}
	})
}

func eventSnapshot(t *testing.T, d *testutil.TestDB) []string {
	return feedtest.Strings(t, d, `SELECT id::text || '|' || detail::text || '|' || observed_at::text || '|' || is_backfill::text FROM event ORDER BY id`)
}

func TestSecondRunOnUnchanged200IsIdempotent(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		data := a.Load(t)
		feedtest.Run(t, d, feedtest.New(t, a, server(t, a, data, `"a"`), 0), T0, false)
		before, snap := feedtest.Counts(t, d), eventSnapshot(t, d)

		// different ETag (e.g. server ignored If-None-Match) but identical content
		s2 := feedtest.Run(t, d, feedtest.New(t, a, server(t, a, data, `"b"`), 0), T1, false)

		if s2.RawUnchanged != s2.Fetched || s2.Fetched == 0 || s2.RawNew+s2.VulnInserted+s2.EventInserted+s2.EventUpdated != 0 {
			t.Errorf("s2 %+v", s2)
		}
		if feedtest.Counts(t, d) != before || !reflect.DeepEqual(eventSnapshot(t, d), snap) {
			t.Error("rows changed")
		}
		feedtest.Run(t, d, feedtest.New(t, a, server(t, a, data, `"c"`), 0), T2, true)
		if feedtest.Counts(t, d) != before {
			t.Error("renormalize added rows")
		}
	})
}

func TestChangedItemUpdatesDetailWithoutNewEvent(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		data := a.Load(t)
		srv := server(t, a, data, `"v1"`)
		feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T0, false)
		nEvents := feedtest.Count(t, d, "SELECT count(*) FROM event")
		srv.Set(a.Dump(t, a.Changed(t, data, a.ChangeKey)), `"v2"`)

		s2 := feedtest.Run(t, d, feedtest.New(t, a, srv, 0), T1, false)

		if s2.RawNew != 1 || s2.EventInserted != 0 || s2.EventUpdated != 1 {
			t.Errorf("s2 %+v", s2)
		}
		if feedtest.Count(t, d, "SELECT count(*) FROM event") != nEvents {
			t.Error("event count changed")
		}
		var title string
		var obs time.Time
		var bf bool
		if err := d.Conn.QueryRow(context.Background(), `SELECT detail->>'title', observed_at, is_backfill FROM event
               WHERE source = $1 AND dedupe_key = $2 AND cve_id = $3`, a.Name, a.ChangeKey, a.CVEOfChange).Scan(&title, &obs, &bf); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(title, "(updated)") || !obs.Equal(T0) || !bf {
			t.Errorf("%q %v %v", title, obs, bf)
		}
		if n := feedtest.Count(t, d, "SELECT count(*) FROM raw_record WHERE source = $1 AND source_key = $2", a.Name, a.ChangeKey); n != 2 {
			t.Errorf("raw versions %d", n)
		}
	})
}

func TestSizeCapAbortsRunAndStoresNothing(t *testing.T) {
	for _, withCL := range []bool{true, false} {
		forEach(t, func(t *testing.T, a *feedtest.Adapter) {
			d := testutil.NewMigratedDB(t)
			body := a.Dump(t, a.Load(t))
			srv := feedtest.NewServer(t, a.URL, body, `"v1"`)
			srv.ContentLength = withCL
			_, err := feedtest.TryRun(d, feedtest.New(t, a, srv, int64(len(body)-1)), T0, false)
			var tl *feed.FeedTooLarge
			if !errors.As(err, &tl) {
				t.Fatalf("content_length=%v: want FeedTooLarge, got %v", withCL, err)
			}
			if c := feedtest.Counts(t, d); c != ([5]int64{}) {
				t.Errorf("counts %v", c)
			}
			var status, lastErr string
			var okAt *time.Time
			if err := d.Conn.QueryRow(context.Background(), "SELECT last_status, last_success_at, last_error FROM collector_state").Scan(&status, &okAt, &lastErr); err != nil {
				t.Fatal(err)
			}
			if status != "error" || okAt != nil || !strings.Contains(lastErr, "FeedTooLarge") {
				t.Errorf("%s %v %q", status, okAt, lastErr)
			}
			// exactly at the cap is fine
			s := feedtest.Run(t, d, feedtest.New(t, a, feedtest.NewServer(t, a.URL, body, `"v1"`), int64(len(body))), T1, false)
			if !s.IsBackfill || s.EventInserted == 0 {
				t.Errorf("%+v", s)
			}
		})
	}
}

func TestSizeCapAppliesToDecodedGzipBody(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		body := a.Dump(t, a.Load(t))
		srv := feedtest.NewServer(t, a.URL, body, `"v1"`)
		srv.Gzip = true // Content-Length = compressed size
		_, err := feedtest.TryRun(d, feedtest.New(t, a, srv, int64(len(body)-1)), T0, false)
		var tl *feed.FeedTooLarge
		if !errors.As(err, &tl) || !strings.Contains(tl.Msg, "body exceeds cap") {
			t.Fatalf("want FeedTooLarge (stream), got %v", err)
		}
	})
}

func TestRetries429And5xxThenSucceeds(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		srv := server(t, a, a.Load(t), `"v1"`)
		srv.Script = []int{429, 503}
		sl := &feedtest.NoSleep{}
		c, err := a.New(feed.Options{Transport: srv, Sleep: sl.Sleep})
		if err != nil {
			t.Fatal(err)
		}
		s := feedtest.Run(t, d, c, T0, false)
		if len(srv.Requests()) != 3 || s.EventInserted == 0 {
			t.Errorf("requests %d stats %+v", len(srv.Requests()), s)
		}
		if got := feedtest.Cursor(t, d).Get("last_run").(*pyjson.Object).Get("attempts"); got != pyjson.Int("3") {
			t.Errorf("attempts %v", got)
		}
		// Retry-After: 1 replaces the 1 s / 2 s backoff.
		if !reflect.DeepEqual(sl.Slept, []time.Duration{time.Second, time.Second}) {
			t.Errorf("slept %v", sl.Slept)
		}
		if got, want := canonCursor(t, d), feedtest.PyCursors[a.Name+"/retries"]; got != want {
			t.Errorf("cursor vs Python\n got  %s\n want %s", got, want)
		}
	})
}

func TestPersistent5xxFailsAndKeepsPreviousCursor(t *testing.T) {
	forEach(t, func(t *testing.T, a *feedtest.Adapter) {
		d := testutil.NewMigratedDB(t)
		feedtest.Run(t, d, feedtest.New(t, a, server(t, a, a.Load(t), `"v1"`), 0), T0, false)
		bad := server(t, a, a.Load(t), `"v1"`)
		bad.Script = []int{502, 502, 502, 502}
		_, err := feedtest.TryRun(d, feedtest.New(t, a, bad, 0), T1, false)
		var se *httpc.StatusError
		if !errors.As(err, &se) || se.Status != 502 || len(bad.Requests()) != 4 {
			t.Fatalf("want 502 StatusError after 4 attempts, got %v (%d requests)", err, len(bad.Requests()))
		}
		status := feedtest.Strings(t, d, "SELECT last_status FROM collector_state")
		if status[0] != "error" || feedtest.Cursor(t, d).Get("etag") != `"v1"` {
			t.Errorf("%v %s", status, pyjson.Repr(feedtest.Cursor(t, d)))
		}
	})
}

// test_poc_cross_source.py
func TestSameCVEFromThreeSources(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	for _, a := range feedtest.Adapters {
		feedtest.Run(t, d, feedtest.New(t, a, server(t, a, a.Load(t), `"v1"`), 0), T0, false)
	}
	const cve = "CVE-2026-9198"
	got := feedtest.Strings(t, d, `SELECT source || '|' || dedupe_key || '|' || coalesce(occurred_at::text, 'None') || '|' || (detail->>'kind')
           FROM event WHERE cve_id = $1 AND type = 'poc_published' ORDER BY source`, cve)
	want := []string{
		"exploitdb|52675|2026-09-02 00:00:00+00|exploit",
		"metasploit|exploit/multi/http/langflow_unauth_rce_cve_2026_9198|None|msf_module",
		"nuclei|CVE-2026-9198|None|detection_template",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events\n got  %q\n want %q", got, want)
	}
	if n := feedtest.Count(t, d, "SELECT count(*) FROM vuln WHERE cve_id = $1 AND title IS NULL", cve); n != 1 {
		t.Error("stub vuln missing or titled")
	}
	var hasPoc bool
	var stage string
	var pocAt time.Time
	var n int
	if err := d.Conn.QueryRow(context.Background(), "SELECT has_poc, stage, poc_at, event_count FROM vuln_state WHERE cve_id = $1", cve).Scan(&hasPoc, &stage, &pocAt, &n); err != nil {
		t.Fatal(err)
	}
	if !hasPoc || stage != "poc_published" || !pocAt.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) || n != 3 {
		t.Errorf("%v %s %v %d", hasPoc, stage, pocAt, n)
	}
}

// ------------------------------------------------------------ Go-only checks of _feed.py semantics

func TestDownloadHeadersAnd304UsesStoredValidators(t *testing.T) {
	// Exactly what production will do on takeover: the cursor Python stored
	// (ETag of the gzip variant, last_modified null) is sent back verbatim and
	// a 304 keeps it, with last_run {"http_status": 304, "attempts": 1}.
	t.Parallel()
	etag := `W/"e303f0dba7ae1e725105d88fd31d6fdec6da486a477b8d73123dcbafb64a6496"`
	prev, err := pyjson.DecodeString(`{"url": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", "etag": "W/\"e303f0dba7ae1e725105d88fd31d6fdec6da486a477b8d73123dcbafb64a6496\"", "feed": {"bytes": 2312968, "lines": 4606, "items_in_scope": 4606, "items_with_cve": 4606, "items_without_cve": 0, "malformed_skipped": 0, "items_nul_scrubbed": ["CVE-2021-32030"]}, "last_run": {"attempts": 1, "http_status": 304}, "last_modified": null}`)
	if err != nil {
		t.Fatal(err)
	}
	var seen http.Header
	ft := &testutil.FakeTransport{Handler: func(r *http.Request) (int, http.Header, []byte, error) {
		seen = r.Header.Clone()
		if r.Header.Get("If-None-Match") == etag {
			return 304, http.Header{"Etag": {etag}}, nil, nil
		}
		return 200, nil, []byte("unexpected"), nil
	}}
	c, err := feedtest.Nuclei.New(feed.Options{Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Fetch(context.Background(), modelState(prev))
	if err != nil {
		t.Fatal(err)
	}
	want := http.Header{"User-Agent": {"nday-collector/0.1.0"}, "Accept": {"*/*"}, "Accept-Encoding": {"gzip"}, "If-None-Match": {etag}}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("headers %v want %v", seen, want)
	}
	if len(res.Records) != 0 {
		t.Errorf("%d records on 304", len(res.Records))
	}
	got, _ := pyjson.Canonical(res.Cursor)
	wantCur := `{"etag":"W/\"e303f0dba7ae1e725105d88fd31d6fdec6da486a477b8d73123dcbafb64a6496\"","feed":{"bytes":2312968,"items_in_scope":4606,"items_nul_scrubbed":["CVE-2021-32030"],"items_with_cve":4606,"items_without_cve":0,"lines":4606,"malformed_skipped":0},"last_modified":null,"last_run":{"attempts":1,"http_status":304},"url":"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"}`
	if got != wantCur {
		t.Errorf("cursor\n got  %s\n want %s", got, wantCur)
	}
}

func modelState(cursor any) model.CollectorState {
	return model.CollectorState{Source: "nuclei", Cursor: cursor}
}
