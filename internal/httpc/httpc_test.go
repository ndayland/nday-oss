package httpc_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/testutil"
)

type sleeper struct{ slept []time.Duration }

func (s *sleeper) sleep(_ context.Context, d time.Duration) error {
	s.slept = append(s.slept, d)
	return nil
}

func script(steps ...func() (int, http.Header, []byte, error)) *testutil.FakeTransport {
	i := 0
	return &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
		s := steps[min(i, len(steps)-1)]
		i++
		return s()
	}}
}

func status(code int, hdr http.Header) func() (int, http.Header, []byte, error) {
	return func() (int, http.Header, []byte, error) { return code, hdr, []byte("body"), nil }
}

func TestRetryBackoffAndRetryAfter(t *testing.T) {
	sl := &sleeper{}
	ft := script(
		status(503, nil),
		status(429, http.Header{"Retry-After": {"7"}}),
		status(500, http.Header{"Retry-After": {"999"}}),
		status(200, nil),
	)
	c := httpc.New(httpc.Options{Transport: ft, Sleep: sl.sleep})
	resp, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{Header: http.Header{"Accept-Encoding": {"gzip"}}})
	if err != nil || resp.Status != 200 || string(resp.Body) != "body" || resp.Attempts != 4 {
		t.Fatalf("%+v %v", resp, err)
	}
	want := []time.Duration{time.Second, 7 * time.Second, 60 * time.Second}
	if len(sl.slept) != 3 || sl.slept[0] != want[0] || sl.slept[1] != want[1] || sl.slept[2] != want[2] {
		t.Errorf("slept %v want %v", sl.slept, want)
	}
	for _, r := range ft.Requests {
		if r.Header.Get("User-Agent") != "nday-collector/0.1.0" || r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("headers %v", r.Header)
		}
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	sl := &sleeper{}
	c := httpc.New(httpc.Options{Transport: script(status(502, nil)), Sleep: sl.sleep})
	_, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{})
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 502 || len(sl.slept) != 3 {
		t.Fatalf("%v slept=%v", err, sl.slept)
	}
	// MaxAttempts 1 = no retry (KEV policy, as in Python).
	sl = &sleeper{}
	c = httpc.New(httpc.Options{Transport: script(status(503, nil)), Sleep: sl.sleep, MaxAttempts: 1})
	if _, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{}); err == nil || len(sl.slept) != 0 {
		t.Fatalf("%v %v", err, sl.slept)
	}
}

func TestTransportErrorRetriedAnd404Accept(t *testing.T) {
	sl := &sleeper{}
	ft := script(func() (int, http.Header, []byte, error) { return 0, nil, nil, errors.New("conn reset") }, status(404, nil))
	c := httpc.New(httpc.Options{Transport: ft, Sleep: sl.sleep})
	_, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{})
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 404 || len(sl.slept) != 1 {
		t.Fatalf("%v %v", err, sl.slept)
	}
	ft = script(status(404, nil))
	c = httpc.New(httpc.Options{Transport: ft, Sleep: sl.sleep})
	resp, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{Accept: func(s int) bool { return s == 200 || s == 404 }})
	if err != nil || resp.Status != 404 {
		t.Fatalf("%v %v", resp, err)
	}
}

func TestSizeCap(t *testing.T) {
	big := make([]byte, 1000)
	ft := script(func() (int, http.Header, []byte, error) { return 200, nil, big, nil })
	c := httpc.New(httpc.Options{Transport: ft, MaxBytes: 999, Sleep: (&sleeper{}).sleep})
	_, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{})
	var tl *httpc.TooLargeError
	if !errors.As(err, &tl) || len(ft.Requests) != 1 {
		t.Fatalf("%v (requests %d)", err, len(ft.Requests))
	}
	// Also enforced while reading when Content-Length is unknown.
	ft2 := &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) { return 200, nil, big, nil }}
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := ft2.RoundTrip(r)
		if resp != nil {
			resp.ContentLength = -1
		}
		return resp, err
	})
	c = httpc.New(httpc.Options{Transport: rt, MaxBytes: 999})
	if _, err := c.Get(context.Background(), "https://example.invalid/x", httpc.GetOptions{}); !errors.As(err, &tl) {
		t.Fatalf("streaming cap: %v", err)
	}
}
