package pagefetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// testServer starts a server and a Client that reaches it as any name on
// port 80 (RewriteAddr), with a dial control that allows only the
// listener's address. hits counts requests per path.
func testServer(t *testing.T, h http.HandlerFunc) (*Client, func(string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	lis := srv.Listener.Addr().String()
	c := New(Options{UserAgent: "test-ua/1",
		RewriteAddr: func(addr string) string {
			if strings.HasSuffix(addr, ".test:80") {
				return lis
			}
			return addr
		},
		DialControl: func(network, address string, _ syscall.RawConn) error {
			if address != lis {
				return refused("test: not the listener: %s", address)
			}
			return nil
		}})
	return c, func(p string) int { mu.Lock(); defer mu.Unlock(); return hits[p] }
}

func TestCheckURL(t *testing.T) {
	ok := []string{"http://a.example/x", "https://a.example/", "https://a.example:443/p?q=1#f", "http://a.example:80/", "https://8.8.8.8/",
		"https://[2606:4700::1111]/"}
	bad := []string{"", "ftp://a.example/", "javascript:alert(1)", "//a.example/", "/x", "https://", "https://u@a.example/",
		"https://u:p@a.example/", "http://a.example:8080/", "https://a.example:80/", "http://a.example:443/", "https://a.example:/",
		"http://127.0.0.1/", "http://10.1.2.3/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://[fe80::1%25en0]/",
		"http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "https://a.example/" + strings.Repeat("x", MaxURL), "http:a.example"}
	for _, u := range ok {
		if _, err := CheckURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := CheckURL(u); !errors.Is(err, ErrRefused) {
			t.Errorf("%q accepted (%v)", u, err)
		}
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	big := "<html><head><title>Big</title></head><body>" + strings.Repeat("x", 2*MaxBody) + "</body></html>"
	c, hits := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "test-ua/1" || r.Header.Get("Accept") != "text/html" {
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Write([]byte("<title>Hello</title>"))
		case "/big":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(big))
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"title": "no"}`))
		case "/404":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			w.Write([]byte("<title>Not here</title>"))
		case "/r1":
			http.Redirect(w, r, "http://b.test/r2", http.StatusFound)
		case "/r2":
			http.Redirect(w, r, "/r3", http.StatusMovedPermanently)
		case "/r3":
			http.Redirect(w, r, "http://c.test/ok", http.StatusSeeOther)
		case "/r0":
			http.Redirect(w, r, "/r1", http.StatusFound) // 4 redirects in all
		case "/toport":
			http.Redirect(w, r, "http://a.test:8080/ok", http.StatusFound)
		case "/touser":
			http.Redirect(w, r, "http://user@a.test/ok", http.StatusFound)
		case "/toprivate":
			http.Redirect(w, r, "http://10.0.0.1/ok", http.StatusFound)
		case "/toloop":
			http.Redirect(w, r, "http://127.0.0.1/ok", http.StatusFound)
		case "/toftp":
			http.Redirect(w, r, "ftp://a.test/ok", http.StatusFound)
		default:
			w.WriteHeader(500)
		}
	})

	p, err := c.Get(ctx, "http://a.test/ok")
	if err != nil || p.Status != 200 || !p.IsHTML() || p.Charset != "utf-8" || string(p.Body) != "<title>Hello</title>" || p.URL != "http://a.test/ok" {
		t.Fatalf("ok: %+v %v", p, err)
	}
	p, err = c.Get(ctx, "http://a.test/big")
	if err != nil || !p.Truncated || len(p.Body) != MaxBody || ExtractMeta(p).Title != "Big" {
		t.Errorf("big: %v truncated=%v len=%d", err, p != nil && p.Truncated, len(p.Body))
	}
	p, err = c.Get(ctx, "http://a.test/json")
	if err != nil || p.IsHTML() || p.Body != nil || p.ContentType != "application/json" {
		t.Errorf("json: %+v %v", p, err)
	}
	p, err = c.Get(ctx, "http://a.test/404")
	if err != nil || p.Status != 404 || p.IsHTML() || p.Body != nil {
		t.Errorf("404: %+v %v", p, err)
	}
	// three redirects: followed, each hop through the guarded dialer
	p, err = c.Get(ctx, "http://a.test/r1")
	if err != nil || p.URL != "http://c.test/ok" || string(p.Body) != "<title>Hello</title>" {
		t.Errorf("redirect chain: %+v %v", p, err)
	}
	// four: refused, the fourth target not requested
	before := hits("/ok")
	if _, err = c.Get(ctx, "http://a.test/r0"); !errors.Is(err, ErrRefused) || hits("/ok") != before {
		t.Errorf("4 redirects: %v", err)
	}
	for _, p := range []string{"/toport", "/touser", "/toprivate", "/toloop", "/toftp"} {
		before := hits("/ok")
		if _, err := c.Get(ctx, "http://a.test"+p); !errors.Is(err, ErrRefused) || hits("/ok") != before {
			t.Errorf("%s: %v (ok hits %d -> %d)", p, err, before, hits("/ok"))
		}
	}
	// refused URLs are not requested at all
	for _, u := range []string{"http://a.test:8080/ok", "http://u@a.test/ok", "http://127.0.0.1/ok"} {
		before := hits("/ok")
		if _, err := c.Get(ctx, u); !errors.Is(err, ErrRefused) || hits("/ok") != before {
			t.Errorf("%s: %v", u, err)
		}
	}
	// an address the test dial control does not allow (refused before connect)
	if _, err := c.Get(ctx, "http://8.8.8.8/"); !errors.Is(err, ErrRefused) {
		t.Errorf("other address: %v", err)
	}
	// cancelled context
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Get(cctx, "http://a.test/ok"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// TestRealGuard: with the production dial control, a name that resolves
// to loopback is refused at connect time (no connection: GuardControl
// runs before connect).
func TestRealGuard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			got <- struct{}{}
			c.Close()
		}
	}()
	lis := ln.Addr().String()
	// the rewrite points the name at the listener; the real guard must
	// still refuse the loopback address
	c := New(Options{UserAgent: "t", RewriteAddr: func(string) string { return lis }})
	if _, err := c.Get(context.Background(), "http://localhost/"); !errors.Is(err, ErrRefused) {
		t.Fatalf("localhost: %v", err)
	}
	if _, err := c.Get(context.Background(), "http://a.test/"); !errors.Is(err, ErrRefused) {
		t.Fatalf("rewritten to loopback: %v", err)
	}
	select {
	case <-got:
		t.Fatal("a connection reached the loopback listener")
	default:
	}
}

// TestRedirectHeaders: no hop receives a Referer or Cookie header.
func TestRedirectHeaders(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	c, _ := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" referer="+r.Header.Get("Referer")+" cookie="+r.Header.Get("Cookie"))
		mu.Unlock()
		switch r.URL.Path {
		case "/a":
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
			http.Redirect(w, r, "http://b.test/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<title>C</title>"))
		}
	})
	if _, err := c.Get(context.Background(), "http://a.test/a"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, "|") != "/a referer= cookie=|/b referer= cookie=|/c referer= cookie=" {
		t.Errorf("hops: %v", seen)
	}
}
