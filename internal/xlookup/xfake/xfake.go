// Package xfake is an in-process stand-in for the X API v2 user lookup
// (GET /2/users/by?usernames=…) used by the tests of internal/xlookup,
// internal/admin and internal/cli, and by tools/authdev. It never touches
// the network unless Start is called (then it listens on loopback only).
//
// It answers like the documented endpoint: found users in "data" (id, name,
// username in the account's own spelling), the others as partial errors in
// "errors" (problem types resource-not-found and resource-unavailable),
// HTTP 401 for a wrong bearer token, 429 when a request names a handle in
// RateLimited, 400 for more than 100 usernames.
package xfake

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// User is a known account.
type User struct {
	ID       string
	Username string // canonical spelling
	// Name ("" = "<username> (fake)") and Description (sent only when
	// user.fields=description is asked for, like the X API).
	Name, Description string
}

// Server is the fake API. Set the maps before serving; they are read
// under the lock.
type Server struct {
	Token string

	mu          sync.Mutex
	Users       map[string]User // lower-case handle -> user
	Suspended   map[string]bool // lower-case handles
	RateLimited map[string]bool // lower-case handles: any request naming one gets 429
	Slow        map[string]bool // lower-case handles: the answer waits for the client to give up
	requests    int
	queries     []string
	auths       []string
}

// TrialToken is the token tools/authdev configures (not a secret).
const TrialToken = "authdev-fake-x-token"

// New returns a fake that accepts token, with no users.
func New(token string) *Server {
	return &Server{Token: token, Users: map[string]User{}, Suspended: map[string]bool{},
		RateLimited: map[string]bool{}, Slow: map[string]bool{}}
}

// Trial is the fake tools/authdev serves (documented in
// tools/authdev/README.md): handles that resolve (two of them map to the
// sample accounts of -x-sample, one with a new spelling, one renamed), one
// suspended account and one handle that triggers HTTP 429. Every other
// handle is "not found".
func Trial() *Server {
	s := New(TrialToken)
	s.Add("1700000000000000001", "Nday_Demo")
	s.Add("1700000000000000002", "CVE_Watcher")
	s.Add("1001", "Alice_Sec") // -x-sample lists 1001 as alice_sec: same id, new spelling
	s.Add("1002", "bob_sec")   // -x-sample lists 1002 as bob_sec: already listed
	s.Add("1003", "carol_new") // -x-sample lists 1003 as carol_ir: renamed
	s.Suspended["suspended_acct"] = true
	s.RateLimited["ratelimited"] = true
	return s
}

// Add registers a user.
func (s *Server) Add(id, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users[strings.ToLower(username)] = User{ID: id, Username: username}
}

// Requests is how many requests reached the fake.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// Queries are the usernames parameters received, in order.
func (s *Server) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// Auths are the Authorization headers received, in order.
func (s *Server) Auths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ServeHTTP implements the endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("usernames")
	s.mu.Lock()
	s.requests++
	s.queries = append(s.queries, q)
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.Path != "/2/users/by" {
		writeJSON(w, http.StatusNotFound, map[string]any{"title": "Not Found", "type": "about:blank", "status": 404, "detail": "Not Found"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"title": "Unauthorized", "type": "about:blank", "status": 401, "detail": "Unauthorized"})
		return
	}
	names := strings.Split(q, ",")
	if q == "" || len(names) > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"title": "Invalid Request", "type": "https://api.x.com/2/problems/invalid-request",
			"detail": "One or more parameters to your request was invalid."})
		return
	}
	s.mu.Lock()
	var limited, slow bool
	for _, n := range names {
		limited = limited || s.RateLimited[strings.ToLower(n)]
		slow = slow || s.Slow[strings.ToLower(n)]
	}
	s.mu.Unlock()
	if slow {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Minute):
		}
		return
	}
	if limited {
		w.Header().Set("x-rate-limit-limit", "300")
		w.Header().Set("x-rate-limit-remaining", "0")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"title": "Too Many Requests", "type": "about:blank", "status": 429,
			"detail": "Too Many Requests"})
		return
	}
	var data, errs []map[string]any
	s.mu.Lock()
	for _, n := range names {
		k := strings.ToLower(n)
		switch u, ok := s.Users[k]; {
		case s.Suspended[k]:
			errs = append(errs, map[string]any{"value": n, "detail": "User has been suspended: [" + n + "].", "title": "Forbidden",
				"resource_type": "user", "parameter": "usernames", "resource_id": n,
				"type": "https://api.twitter.com/2/problems/resource-unavailable"})
		case ok:
			d := map[string]any{"id": u.ID, "name": u.Username + " (fake)", "username": u.Username}
			if u.Name != "" {
				d["name"] = u.Name
			}
			if r.URL.Query().Get("user.fields") == "description" {
				d["description"] = u.Description
			}
			data = append(data, d)
		default:
			errs = append(errs, map[string]any{"value": n, "detail": "Could not find user with usernames: [" + n + "].",
				"title": "Not Found Error", "resource_type": "user", "parameter": "usernames", "resource_id": n,
				"type": "https://api.twitter.com/2/problems/resource-not-found"})
		}
	}
	s.mu.Unlock()
	body := map[string]any{}
	if data != nil {
		body["data"] = data
	}
	if errs != nil {
		body["errors"] = errs
	}
	writeJSON(w, http.StatusOK, body)
}

// Transport serves every request in-process (no network), whatever its
// host: for xlookup.Options.Transport.
func (s *Server) Transport() http.RoundTripper {
	return roundTripper{s}
}

type roundTripper struct{ s *Server }

func (t roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.s.ServeHTTP(rec, r)
	}()
	select {
	case <-done:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

// Start serves the fake on a loopback port and returns its base URL (for
// xlookup.Options.BaseURL) and a function that stops it.
func (s *Server) Start() (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }, nil
}
