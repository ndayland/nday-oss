package siteicon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"nday.land/nday/internal/pagefetch"
)

// testNames are the host names the test certificate is valid for.
var testNames = []string{"ico.test", "png.test", "html.test", "svg.test", "svgico.test", "big.test", "redir.test",
	"link.test", "cross.test", "cdn.test", "err.test", "toolarge.test", "plain.test", "nolink.test", "a.test",
	"b.test", "c.test", "d.test", "e.test"}

// tlsServer starts an https test server for every name in testNames on
// port 443 (RewriteAddr) and returns a Fetcher that trusts its
// certificate and may dial only its listener. hits counts requests per
// host+path.
func tlsServer(t *testing.T, h http.HandlerFunc) (*Fetcher, func(string) int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siteicon test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: testNames,
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
		if r.Header.Get("User-Agent") != UserAgent || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
			w.WriteHeader(400)
			return
		}
		h(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	lis := srv.Listener.Addr().String()
	f := NewFetcher(pagefetch.Options{RootCAs: pool,
		RewriteAddr: func(addr string) string {
			if strings.HasSuffix(addr, ".test:443") || strings.HasSuffix(addr, ".test:80") {
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
	img.Set(0, 0, color.RGBA{R: 200, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// icoBytes is an ICO file with one PNG image.
func icoBytes(t testing.TB) []byte {
	return icoOf(pngBytes(t, 16, 16), 16)
}

func icoOf(img []byte, dim byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, []uint16{0, 1, 1})
	b.Write([]byte{dim, dim, 0, 0})
	binary.Write(&b, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&b, binary.LittleEndian, []uint32{uint32(len(img)), 22})
	b.Write(img)
	return b.Bytes()
}

// bmpICO is an ICO file with one 16x16 32-bit bitmap.
func bmpICO() []byte {
	var hdr bytes.Buffer
	binary.Write(&hdr, binary.LittleEndian, []uint32{40, 16, 32})
	binary.Write(&hdr, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&hdr, binary.LittleEndian, make([]uint32, 6))
	data := append(hdr.Bytes(), make([]byte, 16*16*4+16*4)...)
	return icoOf(data, 16)
}

// webpBytes is a minimal lossless WebP header of w x h pixels (enough for
// a header decode).
func webpBytes(w, h int) []byte {
	v := uint32(w-1) | uint32(h-1)<<14
	chunk := []byte{0x2f, byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	var b bytes.Buffer
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(4+8+len(chunk)+1))
	b.WriteString("WEBPVP8L")
	binary.Write(&b, binary.LittleEndian, uint32(len(chunk)))
	b.Write(chunk)
	b.WriteByte(0)
	return b.Bytes()
}

func TestValidate(t *testing.T) {
	var gb, jb bytes.Buffer
	img := image.NewPaletted(image.Rect(0, 0, 32, 32), []color.Color{color.Black, color.White})
	if err := gif.Encode(&gb, img, nil); err != nil {
		t.Fatal(err)
	}
	if err := jpeg.Encode(&jb, image.NewRGBA(image.Rect(0, 0, 48, 48)), nil); err != nil {
		t.Fatal(err)
	}
	ok := map[string][]byte{TypePNG: pngBytes(t, 32, 32), TypeICO: icoBytes(t), TypeGIF: gb.Bytes(), TypeJPEG: jb.Bytes(),
		TypeWebP: webpBytes(64, 64)}
	for want, b := range ok {
		if got, err := Validate(b); err != nil || got != want {
			t.Errorf("%s: %q %v", want, got, err)
		}
	}
	if got, err := Validate(bmpICO()); err != nil || got != TypeICO {
		t.Errorf("bitmap ico: %q %v", got, err)
	}
	cursor := icoBytes(t)
	cursor[2] = 2
	badOffset := icoBytes(t)
	binary.LittleEndian.PutUint32(badOffset[18:], 1<<20)
	badEntry := icoOf([]byte("<svg xmlns='http://www.w3.org/2000/svg'/>"), 16)
	truncPNG := pngBytes(t, 16, 16)[:20]
	oversize := append(pngBytes(t, 16, 16), make([]byte, MaxBytes)...)
	bad := map[string][]byte{
		"empty": nil, "html disguised": []byte("<!doctype html><html><title>x</title></html>"),
		"svg":        []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><script>alert(1)</script></svg>`),
		"svg xml":    []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>`),
		"too wide":   pngBytes(t, 600, 16),
		"oversize":   oversize,
		"cursor":     cursor,
		"ico offset": badOffset, "ico entry": badEntry, "truncated png": truncPNG,
		"webp huge": webpBytes(1024, 16), "riff not webp": append([]byte("RIFF\x00\x00\x00\x00AVI "), make([]byte, 16)...),
	}
	for name, b := range bad {
		if ct, err := Validate(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted as %q", name, ct)
		}
	}
}

func TestValidHost(t *testing.T) {
	for _, h := range []string{"github.com", "www.cve.org", "xn--bcher-kva.example", "a-b.c-d.io", "x.com"} {
		if !ValidHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"", "localhost", "GitHub.com", "github.com.", "github.com:443", "1.2.3.4", "0x7f.1", "[::1]",
		"a..b", "-a.com", "a-.com", "a_b.com", "bücher.example", "a.com/x", "a.com?v=1", "..", strings.Repeat("a.", 130) + "com"} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
	for raw, want := range map[string]string{"https://GitHub.com/a/b": "github.com", "http://www.cve.org:80/x": "www.cve.org",
		"https://example.com./": "example.com", "https://u@example.com/": "", "ftp://example.com/": "", "/vuln/X": "",
		"https://127.0.0.1/": "", "https://[2001:db8::1]/": "", "javascript:alert(1)": ""} {
		if got, _ := HostOf(raw); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestIconLinks(t *testing.T) {
	doc := `<html><head>
<link rel="stylesheet" href="/s.css">
<link rel="icon" type="image/svg+xml" href="/i.svg">
<LINK REL="Shortcut Icon" HREF="static/fav.png?x=1&amp;y=2">
<link href='//cdn.test/t.png' rel='apple-touch-icon'>
<link rel=icon href=http://plain.test/p.png>
<link rel="icon" href="/z.SVG#f">
<link rel="icon" href="static/fav.png?x=1&amp;y=2">
<link rel="alternate icon" href="data:image/png;base64,AAAA">
</head></html>`
	got := IconLinks([]byte(doc), "https://link.test/dir/page")
	want := []string{"https://link.test/dir/static/fav.png?x=1&y=2", "https://cdn.test/t.png"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %q", got)
	}
}

func TestFetch(t *testing.T) {
	ico, png16 := icoBytes(t), pngBytes(t, 16, 16)
	big := append(pngBytes(t, 16, 16), make([]byte, MaxBytes)...)
	f, hits := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		host, path := strings.TrimSuffix(r.Host, ":443"), r.URL.Path
		html := func(s string) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(s))
		}
		switch host + path {
		case "ico.test/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write(ico)
		case "png.test/favicon.ico":
			w.Header().Set("Content-Type", "image/vnd.microsoft.icon") // a PNG behind an ICO name: the bytes decide
			w.Write(png16)
		case "html.test/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write([]byte("<html><script>alert(1)</script></html>"))
		case "html.test/":
			html(`<title>no icon link here</title>`)
		case "svgico.test/favicon.ico":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
		case "svg.test/":
			html(`<link rel="icon" type="image/svg+xml" href="/a.svg"><link rel="icon" href="/b.svg">`)
		case "big.test/favicon.ico":
			w.Write(big)
		case "redir.test/favicon.ico":
			http.Redirect(w, r, "https://10.0.0.1/favicon.ico", http.StatusFound)
		case "redir.test/":
			http.Redirect(w, r, "http://redir.test/home", http.StatusFound)
		case "redir.test/home":
			html(`<link rel="icon" href="https://ico.test/favicon.ico">`)
		case "link.test/":
			html(`<link rel="icon" href="missing.png"><link rel="shortcut icon" href="static/i.png">`)
		case "link.test/static/i.png":
			w.Write(png16)
		case "cross.test/":
			html(`<link rel="apple-touch-icon" href="https://cdn.test/t.ico">`)
		case "cdn.test/t.ico":
			w.Write(ico)
		case "err.test/favicon.ico":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "plain.test/":
			html(`<link rel="icon" href="http://plain.test/p.png">`)
		case "plain.test/p.png":
			w.Write(png16)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	cases := []struct {
		host, status, ct, src string
		requests, refused     int
	}{
		{"ico.test", StatusOK, TypeICO, "https://ico.test/favicon.ico", 1, 0},
		{"png.test", StatusOK, TypePNG, "https://png.test/favicon.ico", 1, 0},
		{"html.test", StatusNone, "", "", 2, 0},
		{"svgico.test", StatusNone, "", "", 2, 0},
		{"svg.test", StatusNone, "", "", 2, 0},
		{"big.test", StatusNone, "", "", 2, 0},
		{"redir.test", StatusNone, "", "", 2, 2},
		{"link.test", StatusOK, TypePNG, "https://link.test/static/i.png", 4, 0},
		{"cross.test", StatusOK, TypeICO, "https://cdn.test/t.ico", 3, 0},
		{"err.test", StatusError, "", "", 1, 0},
		{"plain.test", StatusNone, "", "", 2, 0},
		{"localhost", StatusNone, "", "", 0, 0},
		{"10.0.0.1", StatusNone, "", "", 0, 0},
	}
	for _, c := range cases {
		got := f.Fetch(ctx, c.host)
		if got.Status != c.status || got.ContentType != c.ct || got.SourceURL != c.src || got.Requests != c.requests || got.Refused != c.refused {
			t.Errorf("%s: %+v (image %d bytes), want %+v", c.host, got.Status+" "+got.ContentType+" "+got.SourceURL+" "+got.Why,
				len(got.Image), c)
		}
		if got.Status == StatusOK {
			if ct, err := Validate(got.Image); err != nil || ct != c.ct {
				t.Errorf("%s: stored bytes do not validate: %v", c.host, err)
			}
		}
	}
	// refused hops made no request: the redirect targets were never asked,
	// SVG candidates were never requested, http was never used
	for _, k := range []string{"redir.test/home", "svg.test/a.svg", "svg.test/b.svg", "plain.test/p.png", "err.test/"} {
		if n := hits(k); n != 0 {
			t.Errorf("%s requested %d times", k, n)
		}
	}
}

// TestFetchRealGuard: with the production address guard, a host whose name
// leads to a loopback listener is refused before any connection.
func TestFetchRealGuard(t *testing.T) {
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
	f := NewFetcher(pagefetch.Options{RewriteAddr: func(string) string { return lis }})
	res := f.Fetch(context.Background(), "a.test")
	if res.Status != StatusNone || res.Refused != 2 {
		t.Errorf("got %+v", res)
	}
	select {
	case <-got:
		t.Fatal("a connection reached the loopback listener")
	default:
	}
}

func TestErrorDelay(t *testing.T) {
	want := []time.Duration{time.Hour, 4 * time.Hour, 16 * time.Hour, 64 * time.Hour, 256 * time.Hour, 30 * 24 * time.Hour, 30 * 24 * time.Hour}
	for i, w := range want {
		if got := ErrorDelay(i + 1); got != w {
			t.Errorf("ErrorDelay(%d) = %v, want %v", i+1, got, w)
		}
	}
}
