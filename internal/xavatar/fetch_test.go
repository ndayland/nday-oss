package xavatar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"syscall"
	"testing"
	"time"

	"nday.land/nday/internal/pagefetch"
)

// tlsServer starts an https test server answering for pbs.twimg.com and
// evil.test on port 443 (RewriteAddr; the address guard would refuse the
// loopback listener, so DialControl lets exactly that listener through,
// like internal/siteicon's tests) and returns a Fetcher that trusts it.
// hits counts requests per host+path.
func tlsServer(t *testing.T, h http.HandlerFunc) (*Fetcher, func(string) int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xavatar test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{AvatarHost, "evil.test"},
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
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Host+r.URL.Path]++
		mu.Unlock()
		h(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	lis := srv.Listener.Addr().String()
	f := NewFetcher(pagefetch.Options{RootCAs: pool,
		RewriteAddr: func(addr string) string {
			if addr == AvatarHost+":443" || addr == "evil.test:443" {
				return lis
			}
			return addr
		},
		DialControl: func(network, address string, _ syscall.RawConn) error {
			if address != lis {
				return pagefetch.ErrRefused
			}
			return nil
		}})
	return f, func(k string) int { mu.Lock(); defer mu.Unlock(); return hits[k] }
}

func pngBytes(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{G: 200, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func jpegBytes(t testing.TB) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, 48, 48)), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const base = "https://" + AvatarHost + "/profile_images/1/"

func TestFetch(t *testing.T) {
	good, jpg := pngBytes(t, 48, 48), jpegBytes(t)
	big := append(pngBytes(t, 48, 48), make([]byte, MaxBytes)...)
	f, hits := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/profile_images/1/ok.png":
			w.Header().Set("Content-Type", "text/plain") // the header is never trusted
			w.Write(good)
		case "/profile_images/1/ok.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write(jpg)
		case "/profile_images/1/html.png":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("<!doctype html><script>alert(1)</script>"))
		case "/profile_images/1/svg.png":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`))
		case "/profile_images/1/fakepng.png": // the magic bytes alone are not enough
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("\x89PNG\r\n\x1a\nnot really"))
		case "/profile_images/1/huge.png":
			w.Write(big)
		case "/profile_images/1/away.png":
			http.Redirect(w, r, "https://evil.test/profile_images/1/ok.png", http.StatusFound)
		case "/profile_images/1/media.png":
			http.Redirect(w, r, "https://"+AvatarHost+"/media/x.png", http.StatusFound)
		case "/profile_images/1/moved.png":
			http.Redirect(w, r, "/profile_images/1/ok.png", http.StatusMovedPermanently)
		case "/profile_images/1/gone.png":
			http.NotFound(w, r)
		case "/profile_images/1/busy.png":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	})
	ctx := context.Background()
	for _, tc := range []struct {
		path, status, ct string
		refused          bool
	}{
		{"ok.png", StatusOK, "image/png", false},
		{"ok.jpg", StatusOK, "image/jpeg", false},
		{"html.png", StatusNone, "", false},
		{"svg.png", StatusNone, "", false},
		{"fakepng.png", StatusNone, "", false},
		{"huge.png", StatusNone, "", false},
		{"away.png", StatusNone, "", true},
		{"media.png", StatusNone, "", true},
		{"moved.png", StatusOK, "image/png", false},
		{"gone.png", StatusNone, "", false},
		{"busy.png", StatusError, "", false},
	} {
		got := f.Fetch(ctx, base+tc.path)
		if got.Status != tc.status || got.ContentType != tc.ct || got.Refused != tc.refused {
			t.Errorf("%s: %+v", tc.path, Fetched{Status: got.Status, ContentType: got.ContentType, Why: got.Why, Refused: got.Refused})
		}
		if got.Status == StatusOK && len(got.Image) == 0 {
			t.Errorf("%s: no bytes", tc.path)
		}
		if got.Status != StatusOK && got.Image != nil {
			t.Errorf("%s: bytes kept for %s", tc.path, got.Status)
		}
	}
	// the refused redirects never reached their target
	if n := hits("evil.test/profile_images/1/ok.png"); n != 0 {
		t.Errorf("redirect off %s followed (%d)", AvatarHost, n)
	}
	if n := hits(AvatarHost + "/media/x.png"); n != 0 {
		t.Errorf("redirect out of /profile_images/ followed (%d)", n)
	}
	// a URL that is not an avatar URL is never requested
	for _, u := range []string{"https://evil.test/profile_images/1/ok.png", "http://" + AvatarHost + "/profile_images/1/ok.png"} {
		if got := f.Fetch(ctx, u); got.Status != StatusNone || got.Why != "not an avatar URL" {
			t.Errorf("%s: %+v", u, got)
		}
	}
	if n := hits("evil.test/profile_images/1/ok.png"); n != 0 {
		t.Errorf("a refused URL was requested (%d)", n)
	}
}

// TestFetchGuard: the production guard refuses the loopback listener a
// name resolves to (no DialControl override).
func TestFetchGuard(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(pngBytes(t, 4, 4)) }))
	defer srv.Close()
	lis := srv.Listener.Addr().String()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	f := NewFetcher(pagefetch.Options{RootCAs: pool, RewriteAddr: func(string) string { return lis }})
	got := f.Fetch(context.Background(), base+"a.png")
	if got.Status == StatusOK {
		t.Fatalf("loopback fetched: %+v", got)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"png", pngBytes(t, 400, 400), true},
		{"too wide", pngBytes(t, MaxDim+1, 4), false},
		{"ico", []byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 1, 0, 0, 0, 22, 0, 0, 0}, false},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), false},
		{"empty", nil, false},
	} {
		_, err := Validate(tc.b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
