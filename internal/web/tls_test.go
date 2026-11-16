package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/web"
)

// testCA is a throw-away certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns PEM cert and key signed by the CA.
func (ca *testCA) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// startTLS serves a trivial handler with opts and returns the address.
func startTLS(t *testing.T, opts web.TLSOptions) string {
	t.Helper()
	cfg, err := opts.Config()
	if err != nil {
		t.Fatal(err)
	}
	addrc := make(chan net.Addr, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") })
	go func() {
		done <- web.ServeTLS(ctx, "127.0.0.1:0", h, slog.New(slog.NewTextHandler(io.Discard, nil)),
			func(a net.Addr) { addrc <- a }, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return (<-addrc).String()
}

func client(roots *x509.CertPool, certs []tls.Certificate, maxVersion uint16) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, Certificates: certs, MaxVersion: maxVersion}}}
}

func TestTLSOptions(t *testing.T) {
	dir := t.TempDir()
	serverCA := newCA(t, "server-ca")
	cert, key := serverCA.issue(t, "localhost", x509.ExtKeyUsageServerAuth)
	certFile, keyFile := write(t, dir, "srv.pem", cert), write(t, dir, "srv.key", key)
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)

	// Validation.
	if (web.TLSOptions{}).Enabled() {
		t.Error("empty options enabled")
	}
	if cfg, err := (web.TLSOptions{}).Config(); cfg != nil || err != nil {
		t.Error("empty options must mean plain HTTP")
	}
	for _, o := range []web.TLSOptions{{CertFile: certFile}, {KeyFile: keyFile}, {ClientCAFile: certFile}} {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	if _, err := (web.TLSOptions{CertFile: certFile, KeyFile: filepath.Join(dir, "missing")}).Config(); err == nil {
		t.Error("missing key file accepted")
	}
	if _, err := (web.TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: keyFile}).Config(); err == nil ||
		!strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("bad client CA: %v", err)
	}

	t.Run("server TLS", func(t *testing.T) {
		addr := startTLS(t, web.TLSOptions{CertFile: certFile, KeyFile: keyFile})
		resp, err := client(roots, nil, 0).Get("https://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "hello" || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
			t.Errorf("got %q %+v", b, resp.TLS)
		}
		if _, err := client(roots, nil, tls.VersionTLS11).Get("https://" + addr + "/"); err == nil {
			t.Error("TLS 1.1 accepted")
		}
		// Plain HTTP to the TLS port does not get the page.
		if resp, err := http.Get("http://" + addr + "/"); err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) == "hello" {
				t.Error("plain HTTP served on the TLS port")
			}
		}
	})

	t.Run("client certificates required", func(t *testing.T) {
		clientCA := newCA(t, "origin-pull-ca")
		caFile := write(t, dir, "client-ca.pem", clientCA.pem)
		addr := startTLS(t, web.TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})

		if _, err := client(roots, nil, 0).Get("https://" + addr + "/"); err == nil {
			t.Error("connection without client certificate accepted")
		}
		otherCA := newCA(t, "someone-else")
		oc, ok := otherCA.issue(t, "intruder", x509.ExtKeyUsageClientAuth)
		other, _ := tls.X509KeyPair(oc, ok)
		if _, err := client(roots, []tls.Certificate{other}, 0).Get("https://" + addr + "/"); err == nil {
			t.Error("client certificate from another CA accepted")
		}
		cc, ck := clientCA.issue(t, "cloudflare", x509.ExtKeyUsageClientAuth)
		good, _ := tls.X509KeyPair(cc, ck)
		resp, err := client(roots, []tls.Certificate{good}, 0).Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("valid client certificate rejected: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "hello" {
			t.Errorf("got %q", b)
		}
	})
}
