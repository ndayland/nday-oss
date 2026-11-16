package xlookup_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xlookup/xfake"
)

const token = "XTOKEN-SECRET-lookup-9f8e7d"

func fake() *xfake.Server {
	f := xfake.New(token)
	f.Add("2244994945", "XDevelopers")
	f.Add("783214", "X")
	f.Suspended["gone_bad"] = true
	f.RateLimited["too_fast"] = true
	f.Slow["sloth"] = true
	return f
}

func client(t *testing.T, f *xfake.Server, tok string, logs *bytes.Buffer) *xlookup.Client {
	t.Helper()
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	c, err := xlookup.New(xlookup.Options{Token: tok, BaseURL: ts.URL, Timeout: 300 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLookup(t *testing.T) {
	cases := []struct {
		name     string
		tok      string
		handles  []string
		wantErr  error
		want     map[string]xlookup.Result
		requests int
	}{
		{"found, canonical case", token, []string{"xdevelopers", "X"}, nil, map[string]xlookup.Result{
			"xdevelopers": {xlookup.Found, "2244994945", "XDevelopers"}, "x": {xlookup.Found, "783214", "X"}}, 1},
		{"not found", token, []string{"nobody_here"}, nil, map[string]xlookup.Result{"nobody_here": {Outcome: xlookup.NotFound}}, 1},
		{"suspended", token, []string{"Gone_Bad"}, nil, map[string]xlookup.Result{"gone_bad": {Outcome: xlookup.Unavailable}}, 1},
		{"mixed", token, []string{"X", "nobody", "gone_bad"}, nil, map[string]xlookup.Result{"x": {xlookup.Found, "783214", "X"},
			"nobody": {Outcome: xlookup.NotFound}, "gone_bad": {Outcome: xlookup.Unavailable}}, 1},
		{"429", token, []string{"X", "too_fast"}, xlookup.ErrRateLimited, nil, 1},
		{"401", "WRONG-" + token, []string{"X"}, xlookup.ErrAuth, nil, 1},
		{"timeout", token, []string{"sloth"}, xlookup.ErrUpstream, nil, 1},
		{"no token", "", []string{"X"}, xlookup.ErrNotConfigured, nil, 0},
		{"hostile handle", token, []string{"X", "a&usernames=b"}, xlookup.ErrBadHandle, nil, 0},
		{"too long", token, []string{"abcdefghijklmnop"}, xlookup.ErrBadHandle, nil, 0},
		{"at sign", token, []string{"@X"}, xlookup.ErrBadHandle, nil, 0},
		{"empty", token, []string{""}, xlookup.ErrBadHandle, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake()
			var logs bytes.Buffer
			c := client(t, f, tc.tok, &logs)
			got, err := c.Lookup(context.Background(), tc.handles)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if f.Requests() != tc.requests {
				t.Errorf("requests %d, want %d", f.Requests(), tc.requests)
			}
			for _, a := range f.Auths() {
				if a != "Bearer "+tc.tok {
					t.Errorf("Authorization %q", a)
				}
			}
			if err != nil && strings.Contains(err.Error(), token) || strings.Contains(logs.String(), token) {
				t.Error("the token reached an error or the logs")
			}
		})
	}
}

func TestBatching(t *testing.T) {
	f := fake()
	var hs []string
	for i := 0; i < 250; i++ {
		h := fmt.Sprintf("user_%d", i)
		if i%7 != 0 {
			f.Add(fmt.Sprint(5000+i), strings.ToUpper(h))
		}
		hs = append(hs, h)
	}
	hs = append(hs, "USER_1", "user_2") // duplicates in another case are asked once
	var logs bytes.Buffer
	c := client(t, f, token, &logs)
	got, err := c.Lookup(context.Background(), hs)
	if err != nil {
		t.Fatal(err)
	}
	if f.Requests() != 3 || len(got) != 250 {
		t.Fatalf("requests %d, results %d", f.Requests(), len(got))
	}
	for _, q := range f.Queries() {
		if n := len(strings.Split(q, ",")); n > xlookup.MaxPerRequest {
			t.Errorf("a request asked for %d usernames", n)
		}
	}
	if r := got["user_8"]; r.Outcome != xlookup.Found || r.ID != "5008" || r.Handle != "USER_8" {
		t.Errorf("user_8: %+v", r)
	}
	if r := got["user_7"]; r.Outcome != xlookup.NotFound {
		t.Errorf("user_7: %+v", r)
	}
}

func TestContextAndNil(t *testing.T) {
	var nilc *xlookup.Client
	if nilc.Configured() {
		t.Error("nil client configured")
	}
	if _, err := nilc.Lookup(context.Background(), []string{"X"}); !errors.Is(err, xlookup.ErrNotConfigured) {
		t.Errorf("nil client: %v", err)
	}
	f := fake()
	var logs bytes.Buffer
	c := client(t, f, token, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Lookup(ctx, []string{"X"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	if _, err := xlookup.New(xlookup.Options{Token: "a\nb"}); !errors.Is(err, xlookup.ErrBadToken) || strings.Contains(err.Error(), "a\nb") {
		t.Errorf("bad token: %v", err)
	}
	// the in-process transport (cli tests) answers like the server
	c2, _ := xlookup.New(xlookup.Options{Token: token, Transport: f.Transport()})
	if r, err := c2.LookupOne(context.Background(), "x"); err != nil || r.ID != "783214" {
		t.Errorf("transport: %+v %v", r, err)
	}
}

func TestOddResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
		out    xlookup.Outcome
	}{
		{"500", 500, `{}`, xlookup.ErrUpstream, ""},
		{"403", 403, `{"title":"Forbidden"}`, xlookup.ErrAuth, ""},
		{"not JSON", 200, `<html>`, xlookup.ErrUpstream, ""},
		{"bad id", 200, `{"data":[{"id":"01","username":"abc"}]}`, xlookup.ErrUpstream, ""},
		{"unasked user ignored", 200, `{"data":[{"id":"1","username":"other"}]}`, nil, xlookup.NotFound},
		{"unknown problem", 200, `{"errors":[{"value":"abc","type":"https://api.x.com/2/problems/something"}]}`, nil, xlookup.Unavailable},
		{"empty", 200, `{}`, nil, xlookup.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			c, _ := xlookup.New(xlookup.Options{Token: token, BaseURL: ts.URL})
			r, err := c.LookupOne(context.Background(), "abc")
			if !errors.Is(err, tc.want) || err == nil && r.Outcome != tc.out {
				t.Errorf("%+v %v", r, err)
			}
			if err != nil && strings.Contains(err.Error(), token) {
				t.Error("token in error")
			}
		})
	}
}
