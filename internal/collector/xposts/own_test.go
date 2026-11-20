package xposts_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

// ownResponse: alice (1001) quotes, replies to and mentions the site's own
// account (id 4000, @NdayLand) and one ordinary user (3001); a post by the
// own account (id 4000) arrives too.
const ownResponse = `{
  "data": [
    {"id": "2122000000000000002", "author_id": "4000", "created_at": "2026-11-12T18:00:00.000Z", "lang": "en",
     "text": "own post CVE-2026-5555", "edit_history_tweet_ids": ["2122000000000000002"]},
    {"id": "2122000000000000001", "author_id": "1001", "created_at": "2026-11-12T17:00:00.000Z", "lang": "en",
     "text": "CVE-2026-6666 @NdayLand @dave_vr",
     "entities": {"mentions": [
        {"start": 14, "end": 23, "id": "4000", "username": "NdayLand"},
        {"start": 24, "end": 32, "id": "3001", "username": "dave_vr"}]},
     "referenced_tweets": [{"type": "quoted", "id": "2120999000000000001"}, {"type": "replied_to", "id": "2120999000000000002"}],
     "edit_history_tweet_ids": ["2122000000000000001"]}
  ],
  "includes": {
    "users": [
      {"id": "1001", "name": "Alice", "username": "alice_sec"},
      {"id": "4000", "name": "nday", "username": "ndayland"},
      {"id": "3001", "name": "Dave", "username": "dave_vr"}
    ],
    "tweets": [
      {"id": "2120999000000000001", "author_id": "4000", "created_at": "2026-11-11T10:00:00.000Z", "text": "x"},
      {"id": "2120999000000000002", "author_id": "3001", "created_at": "2026-11-11T11:00:00.000Z", "text": "y"}
    ]
  },
  "meta": {"result_count": 2, "newest_id": "2122000000000000002", "oldest_id": "2122000000000000001"}
}`

func ownTransport() *testutil.FakeTransport {
	return &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
		return 200, nil, []byte(ownResponse), nil
	}}
}

// An enabled row for the own handle (inserted behind the admin / CLI checks)
// is left out of the search query with a log line; if it is the only
// account nothing is fetched; a post by the own account is dropped.
func TestFetchSkipsOwnAccount(t *testing.T) {
	own := xconfig.Account{UserID: "4000", Handle: "NdayLand", Enabled: true}
	log := &logBuf{}
	ft := ownTransport()
	c := newC(t, ft, nil, append([]xconfig.Account{own}, accounts...), token, log)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Requests) != 1 {
		t.Fatalf("%d requests", len(ft.Requests))
	}
	if q := query(t, ft.Requests[0].URL).Get("query"); q != "(from:alice_sec OR from:bob_sec) (CVE OR GHSA) -is:retweet" || strings.Contains(strings.ToLower(q), "ndayland") {
		t.Errorf("query %q", q)
	}
	if n := strings.Count(log.String(), "never collected"); n != 1 || !strings.Contains(log.String(), "4000") {
		t.Errorf("log lines about the own account: %d\n%s", n, log.String())
	}
	var keys []string
	for _, r := range res.Records {
		keys = append(keys, r.SourceKey)
	}
	if !slices.Equal(keys, []string{"2122000000000000001"}) {
		t.Errorf("records %v (the own account's post must be dropped)", keys)
	}
	if lr := lastRun(t, res.Cursor); lr.Get("accounts") != 2 || lr.Get("dropped_author") != 1 {
		t.Errorf("accounts / dropped_author: %v %v", lr.Get("accounts"), lr.Get("dropped_author"))
	}

	// only the own account enabled: skipped like an empty allowlist
	ft = script(t)
	c = newC(t, ft, nil, []xconfig.Account{own}, token, nil)
	res, err = c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Requests) != 0 || len(res.Records) != 0 || lastRun(t, res.Cursor).Get("skipped") != "no_accounts" {
		t.Errorf("own account alone: %d requests, %+v", len(ft.Requests), lastRun(t, res.Cursor))
	}

	// a post whose author's username is the own handle is dropped even when
	// its id is (wrongly) on the allowlist under another handle
	ft = ownTransport()
	c = newC(t, ft, nil, []xconfig.Account{{UserID: "4000", Handle: "renamed_own", Enabled: true}, accounts[1]}, token, nil)
	res, err = c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Records {
		if r.SourceKey == "2122000000000000002" {
			t.Error("a post by the own account was kept")
		}
	}
}

// A quoted / replied-to / mentioned user whose handle is the own one gives
// no candidate ref; the others still do.
func TestNoCandidateRefForOwnAccount(t *testing.T) {
	ft := ownTransport()
	c := newC(t, ft, nil, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("%d records", len(res.Records))
	}
	n, err := c.Normalize(res.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range n.CandidateRefs {
		got = append(got, r.UserID+" "+r.Kind)
	}
	// quoted post by 4000 (own): none; replied-to post by 3001 and the
	// mention of 3001: kept; the mention of 4000: none
	if want := []string{"3001 replied_to", "3001 mentioned"}; !slices.Equal(got, want) {
		t.Errorf("refs %v, want %v", got, want)
	}
}
