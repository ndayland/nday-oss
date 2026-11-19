package web_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

// The detail response carries "credits" (sitetest.SeedCredits) on both the
// website API path and the API host's /v1 path; GitHub profile URLs are
// never part of it.
func TestVulnCreditsJSON(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	sitetest.SeedCredits(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	store := site.New(pool).WithClock(func() time.Time { return sitetest.Now })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	single := httptest.NewServer(gated(web.New(web.Config{Store: store, Logger: log})).Handler())
	t.Cleanup(single.Close)
	two := httptest.NewServer(gated(web.New(web.Config{Store: store, Logger: log, PublicURL: testPublic, APIURL: testAPI})).Handler())
	t.Cleanup(two.Close)
	want := `[{"key":"CVE-2026-102895","name":"Zhang Wei of Example Lab","role":"finder","source":"cvelist","type":"finder"},` +
		`{"key":"CVE-2026-102895","name":"Example PSIRT","role":"reporter","source":"cvelist","type":"reporter"},` +
		`{"key":"CVE-2026-102895","name":"Anonymous researcher","role":"credit","source":"cvelist","type":null},` +
		`{"key":"CVE-2026-102895","name":"\u003cimg src=x onerror=alert(1)\u003eEve","role":"finder","source":"cvelist","type":"finder"},` +
		`{"key":"GHSA-cred-0001","name":"zq-credit-login","role":"reporter","source":"ghsa","type":"reporter"},` +
		`{"key":"GHSA-cred-0001","name":"fixer-dev","role":"remediation_developer","source":"ghsa","type":"remediation_developer"}]`
	for _, c := range []struct {
		ts         *httptest.Server
		host, path string
	}{{single, "", "/api/vuln/CVE-2026-102895"}, {two, apiHost, "/v1/vuln/cve-2026-102895"}} {
		resp, b := do(t, c.ts, http.MethodGet, c.host, c.path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", c.path, resp.StatusCode, b)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		var v any
		_ = json.Unmarshal(m["credits"], &v)
		got, _ := json.Marshal(v) // sorted keys
		if string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s", c.path, got, want)
		}
		if strings.Contains(string(b), "api.github.com/users") || strings.Contains(string(b), "Old Version Person") {
			t.Errorf("%s: profile URL or stale credit in the response", c.path)
		}
	}
	resp, b := do(t, single, http.MethodGet, "", "/api/vuln/CVE-2026-1010")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"credits":[]`) {
		t.Errorf("CVE-2026-1010: %d %s", resp.StatusCode, b)
	}
}
