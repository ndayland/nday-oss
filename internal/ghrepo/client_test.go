package ghrepo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// apiServer is a TLS test server that serves as api.github.com (and
// other.example) to a Client built by its client method: the dial of
// api.github.com:443 is rewritten to the listener, the dial control allows
// only the listener, the certificate is trusted through RootCAs. Requests
// are recorded.
type apiServer struct {
	srv  *httptest.Server
	pool *x509.CertPool
	mu   sync.Mutex
	reqs []*http.Request
}

func newAPIServer(t *testing.T, h http.HandlerFunc) *apiServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames: []string{"api.github.com", "other.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a := &apiServer{pool: x509.NewCertPool()}
	a.pool.AddCert(cert)
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.reqs = append(a.reqs, r.Clone(context.Background()))
		a.mu.Unlock()
		h(w, r)
	}))
	a.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiServer) client(token string) *Client {
	lis := a.srv.Listener.Addr().String()
	return NewClient(ClientOptions{Token: token, RootCAs: a.pool,
		RewriteAddr: func(string) string { return lis },
		DialControl: func(network, address string, _ syscall.RawConn) error {
			if address != lis {
				return errors.New("test: not the listener")
			}
			return nil
		}})
}

func (a *apiServer) requests() []*http.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*http.Request(nil), a.reqs...)
}

const repoJSON = `{"id": 42, "full_name": "Alice/CVE-2026-1234_poc", "private": false, "visibility": "public",
 "owner": {"login": "Alice", "type": "User"}, "description": "PoC for CVE-2026-1234 &amp; cve-2026-5555 ‮evil",
 "stargazers_count": 1234, "forks_count": 5, "language": "Python", "topics": ["cve-2026-7777", "Bad Topic", "poc", "poc"],
 "fork": false, "archived": true, "created_at": "2026-01-02T03:04:05Z", "pushed_at": null}`

func TestParseURL(t *testing.T) {
	ok := map[string]string{
		"https://github.com/Alice/CVE-2026-1234":                    "alice/cve-2026-1234",
		"https://www.github.com/alice/repo/":                        "alice/repo",
		"http://GitHub.com/a-b/r.e_p-o/blob/main/x.py?raw=1#L3":     "a-b/r.e_p-o",
		"https://github.com/o/r.git":                                "o/r",
		"https://github.com/o/r/tree/main/sub":                      "o/r",
		"https://github.com/o/r/security/advisories/GHSA-xxxx":      "o/r",
		"https://github.com:443/o/r":                                "o/r",
		"https://github.com./o/r":                                   "o/r",
		"https://github.com/o/r/commit/abc":                         "o/r",
		"https://github.com/" + strings.Repeat("a", 39) + "/" + "r": strings.Repeat("a", 39) + "/r",
	}
	for u, want := range ok {
		if got, okk := KeyOf(u); !okk || got != want {
			t.Errorf("%q: %q %v, want %q", u, got, okk, want)
		}
	}
	bad := []string{"", "github.com/o/r", "ftp://github.com/o/r", "https://gist.github.com/o/abc", "https://api.github.com/repos/o/r",
		"https://github.com/o", "https://github.com/", "https://github.com/advisories/GHSA-1", "https://github.com/orgs/o/people",
		"https://github.com/settings/tokens", "https://github.com/topics/cve", "https://github.com/search?q=x",
		"https://github.com/features/actions", "https://github.com/sponsors/o", "https://github.com/marketplace/x",
		"https://github.com/Topics/cve", "https://u:p@github.com/o/r", "https://github.com:8443/o/r", "https://github.com/-o/r",
		"https://github.com/o/..", "https://github.com/o/.", "https://github.com/o%2Fx/r", "https://github.com/o/r%2F..",
		"https://github.com/o/r<script>", "https://github.com/" + strings.Repeat("a", 40) + "/r",
		"https://github.com/o/" + strings.Repeat("r", 101), "https://github.com.evil.example/o/r", "https://evilgithub.com/o/r",
		"javascript:alert(1)//github.com/o/r", "https://github.com/o//r", "https://github.com/o/r‮", "https://github.com/ö/r",
		"https://github.com/o/" + "%E2%80%AEr", "https://gitlab.com/o/r", "https://github.com/o/.git",
	}
	for _, u := range bad {
		if k, ok := KeyOf(u); ok {
			t.Errorf("%q accepted as %q", u, k)
		}
	}
}

func TestClientHeadersTokenAndRedirects(t *testing.T) {
	a := newAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "other.example":
			w.WriteHeader(200)
		case r.URL.Path == "/repos/old/name":
			http.Redirect(w, r, "https://api.github.com/repositories/42", http.StatusMovedPermanently)
		case r.URL.Path == "/repositories/42":
			w.Header().Set("ETag", `W/"abc"`)
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.Header().Set("X-RateLimit-Reset", "1794827424")
			w.Write([]byte(repoJSON))
		case r.URL.Path == "/repos/away/x":
			http.Redirect(w, r, "https://other.example/steal", http.StatusFound)
		case r.URL.Path == "/repos/plain/x":
			http.Redirect(w, r, "http://api.github.com/repos/plain/y", http.StatusFound)
		case r.URL.Path == "/repos/loop/x":
			http.Redirect(w, r, "/repos/loop/x", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(404)
		}
	})
	c := a.client("tok-SECRET")
	ctx := context.Background()
	r, err := c.Get(ctx, "/repos/old/name", "")
	if err != nil || r.Status != 200 || r.FinalPath != "/repositories/42" || r.ETag != `W/"abc"` || r.Remaining != 4999 ||
		r.Reset.Unix() != 1794827424 || len(r.Body) == 0 {
		t.Fatalf("rename: %+v %v", r, err)
	}
	for _, q := range a.requests() {
		if q.Header.Get("User-Agent") != UserAgent || q.Header.Get("Accept") != Accept || q.Header.Get("X-GitHub-Api-Version") != APIVersion ||
			q.Header.Get("Authorization") != "Bearer tok-SECRET" || q.Host != "api.github.com" || q.Method != "GET" {
			t.Errorf("request %s %s headers %v", q.Host, q.URL, q.Header)
		}
	}
	// redirects off https://api.github.com are refused before any request
	for _, p := range []string{"/repos/away/x", "/repos/plain/x", "/repos/loop/x"} {
		if _, err := c.Get(ctx, p, ""); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", p, err)
		}
	}
	n := 0
	for _, q := range a.requests() {
		if q.Host != "api.github.com" {
			t.Errorf("request to %s (headers %v)", q.Host, q.Header)
		}
		if q.URL.Path == "/repos/loop/x" {
			n++
		}
	}
	if n != MaxRedirects+1 {
		t.Errorf("loop: %d requests", n)
	}
	// no token: no Authorization header
	if _, err := a.client("").Get(ctx, "/repos/x/y", ""); err != nil {
		t.Fatal(err)
	}
	rs := a.requests()
	if last := rs[len(rs)-1]; last.Header.Get("Authorization") != "" {
		t.Error("Authorization without a token")
	}
	// a dial to anything but api.github.com:443 is refused
	if _, err := c.hc.Get("https://other.example/x"); !errors.Is(err, ErrRefused) {
		t.Errorf("other host dial: %v", err)
	}
}

func TestClientStatusBodyRateLimit(t *testing.T) {
	a := newAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/big/x":
			w.Write([]byte(strings.Repeat(" ", MaxBody+1)))
		case "/repos/limit/x":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(403)
		case "/repos/secondary/x":
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(403)
		case "/repos/many/x":
			w.WriteHeader(429)
		case "/repos/forbidden/x":
			w.Header().Set("X-RateLimit-Remaining", "10")
			w.WriteHeader(403)
		case "/repos/etag/x":
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(304)
				return
			}
			w.Write([]byte(repoJSON))
		}
	})
	c := a.client("")
	ctx := context.Background()
	if r, err := c.Get(ctx, "/repos/big/x", ""); err != nil || !r.TooBig || r.Body != nil {
		t.Errorf("big: %+v %v", r, err)
	}
	for p, want := range map[string]bool{"/repos/limit/x": true, "/repos/secondary/x": true, "/repos/many/x": true, "/repos/forbidden/x": false} {
		if r, err := c.Get(ctx, p, ""); err != nil || r.RateLimited() != want {
			t.Errorf("%s: %+v %v", p, r, err)
		}
	}
	if r, err := c.Get(ctx, "/repos/etag/x", `"e1"`); err != nil || r.Status != 304 || r.Body != nil {
		t.Errorf("etag: %+v %v", r, err)
	}
}

func TestDecodeRepo(t *testing.T) {
	r, err := DecodeRepo([]byte(repoJSON))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 42 || r.FullName != "Alice/CVE-2026-1234_poc" || r.OwnerLogin != "Alice" || r.OwnerType != "User" || !r.Public ||
		r.Description != "PoC for CVE-2026-1234 & cve-2026-5555 evil" || r.Stars != 1234 || r.Forks != 5 || r.Language != "Python" ||
		strings.Join(r.Topics, ",") != "cve-2026-7777,poc" || r.Fork || !r.Archived || r.CreatedAt == nil ||
		r.CreatedAt.Format(time.RFC3339) != "2026-01-02T03:04:05Z" || r.PushedAt != nil {
		t.Errorf("%+v", r)
	}
	as := r.Associations()
	if strings.Join(as[BasisName], ",") != "CVE-2026-1234" || strings.Join(as[BasisDescription], ",") != "CVE-2026-1234,CVE-2026-5555" ||
		strings.Join(as[BasisTopic], ",") != "CVE-2026-7777" {
		t.Errorf("associations %v", as)
	}
	for _, b := range []string{``, `null`, `[]`, `{"id": "42"}`, `{"id": 0, "full_name": "a/b", "fork": false, "archived": false}`,
		`{"id": 1, "full_name": "a/b/c", "fork": false, "archived": false}`, `{"id": 1, "full_name": "a/b", "archived": false}`,
		`{"id": 1, "full_name": "a/b", "fork": "no", "archived": false}`, `{"id": 1e30, "full_name": "a/b", "fork": false, "archived": false}`,
		`{"id": 1, "full_name": "<b>/x", "fork": false, "archived": false}`, `{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "stargazers_count": "9"}`,
		`{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "owner": "x"}`} {
		if _, err := DecodeRepo([]byte(b)); !errors.Is(err, errMalformed) {
			t.Errorf("%s: %v", b, err)
		}
	}
	// optional oddities are dropped, not fatal; private / internal / no
	// private field: not public
	r, err = DecodeRepo([]byte(`{"id": 7, "full_name": "a/b", "fork": true, "archived": false, "private": true, "topics": "x",
		"stargazers_count": 99999999999, "forks_count": -3, "created_at": "yesterday", "description": "�", "owner": {"login": "<x>", "type": "Admin"}}`))
	if err != nil || r.Public || r.Topics != nil || r.Stars != 2147483647 || r.Forks != 0 || r.CreatedAt != nil || r.Description != "" ||
		r.OwnerLogin != "" || r.OwnerType != "" {
		t.Errorf("%+v %v", r, err)
	}
	for _, b := range []string{`{"id": 7, "full_name": "a/b", "fork": true, "archived": false}`,
		`{"id": 7, "full_name": "a/b", "fork": true, "archived": false, "private": false, "visibility": "internal"}`} {
		if r, err := DecodeRepo([]byte(b)); err != nil || r.Public {
			t.Errorf("%s: %+v %v", b, r, err)
		}
	}
	if cleanETag(`W/"x"`) != `W/"x"` || cleanETag("a b") != "" || cleanETag(strings.Repeat("e", 201)) != "" {
		t.Error("cleanETag")
	}
}

// apiURL refuses everything but https://api.github.com on the default
// port without user info; a redirect to such a URL is refused by that
// check before any request or dial for the hop (a check that could pass
// through: a dial for anything but the listener fails the test, and the
// server must see only the first request).
func TestRedirectRefusedBeforeDial(t *testing.T) {
	for _, s := range []string{"https://api.github.com/repos/o/r", "https://api.github.com:443/x"} {
		u, _ := url.Parse(s)
		if err := apiURL(u); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	bad := []string{"https://api.github.com:8443/repos/o/r", "http://api.github.com/repos/o/r", "https://user@api.github.com/repos/o/r",
		"https://user:pw@api.github.com/repos/o/r", "https://evil.example/repos/o/r", "https://api.github.com.evil.example/x", "//evil.example/x"}
	for _, s := range bad {
		u, _ := url.Parse(s)
		if err := apiURL(u); !errors.Is(err, ErrRefused) {
			t.Errorf("%s accepted", s)
		}
	}
	for _, target := range bad {
		var mu sync.Mutex
		hits, dials := 0, 0
		a := newAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
		})
		lis := a.srv.Listener.Addr().String()
		c := NewClient(ClientOptions{Token: "tok", RootCAs: a.pool,
			RewriteAddr: func(addr string) string {
				if addr != APIHost+":443" {
					t.Errorf("%s: rewrite asked for %s", target, addr)
				}
				return lis
			},
			DialControl: func(network, address string, _ syscall.RawConn) error {
				mu.Lock()
				dials++
				mu.Unlock()
				if address != lis {
					t.Errorf("%s: dial of %s", target, address)
				}
				return nil
			}})
		_, err := c.Get(context.Background(), "/repos/o/r", "")
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not "+APIBase) {
			t.Errorf("%s: %v (want the URL check's refusal)", target, err)
		}
		mu.Lock()
		if hits != 1 || dials != 1 {
			t.Errorf("%s: %d requests, %d dials", target, hits, dials)
		}
		mu.Unlock()
	}
}

func TestRootKeyOf(t *testing.T) {
	for _, u := range []string{"https://github.com/O/R", "https://github.com/o/r/", "https://github.com/o/r.git", "https://www.github.com/o/r#readme"} {
		if k, ok := RootKeyOf(u); !ok || k != "o/r" {
			t.Errorf("%s: %q %v", u, k, ok)
		}
	}
	for _, u := range []string{"https://github.com/o/r/issues/3", "https://github.com/o/r/blob/main/x.py", "https://github.com/o/r/tree/main",
		"https://github.com/o/r/security/advisories/GHSA-1", "https://github.com/o/r/releases", "https://github.com/o/r?tab=readme",
		"https://github.com/o/r//", "https://github.com/o", "https://gist.github.com/o/r"} {
		if k, ok := RootKeyOf(u); ok {
			t.Errorf("%s: root %q", u, k)
		}
	}
}
