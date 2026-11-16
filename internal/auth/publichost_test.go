package auth_test

import (
	"bytes"
	"testing"

	"nday.land/nday/internal/auth"
)

func TestPublicHost(t *testing.T) {
	for _, c := range []struct {
		origin string
		yes    []string
		no     []string
	}{
		{"https://www.nday.land", []string{"www.nday.land", "WWW.NDAY.LAND", "www.nday.land:443", "www.nday.land:"},
			[]string{"", "nday.land", "api.nday.land", "www.nday.land:8443", "www.nday.land:80", "evil.example", "www.nday.land.evil"}},
		{"http://localhost:8090", []string{"localhost:8090", "LOCALHOST:8090"}, []string{"localhost", "localhost:80", "127.0.0.1:8090"}},
	} {
		cfg := &auth.Config{PublicOrigin: c.origin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)}, Passkeys: true,
			RPID: "nday.land", Origins: []string{c.origin}}
		svc, err := auth.New(cfg, auth.Options{Store: &auth.Store{}})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range c.yes {
			if !svc.PublicHost(h) {
				t.Errorf("%s: PublicHost(%q) = false", c.origin, h)
			}
		}
		for _, h := range c.no {
			if svc.PublicHost(h) {
				t.Errorf("%s: PublicHost(%q) = true", c.origin, h)
			}
		}
	}
	var nilSvc *auth.Service
	if nilSvc.PublicHost("www.nday.land") {
		t.Error("nil service: PublicHost = true")
	}
}
