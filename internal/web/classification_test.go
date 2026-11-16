package web_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

// vulnGoldenFile holds /api/vuln/{cve} bodies captured BEFORE the
// classification object was added (NDAY_WRITE_VULN_GOLDEN=1 rewrites it;
// do that only on a tree without the classification change).
var vulnGoldenFile = filepath.Join("testdata", "vuln_pre_classification.json")

var vulnGoldenIDs = []string{"CVE-2026-102895", "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1010"}

// Every field that existed before migration 0009 keeps its value: the only
// differences are the new "classification" key, (migration 0011) the new
// "tags" array and the new "credits" array (credits.go; empty here, the
// standard fixture has no credits).
func TestVulnJSONUnchangedExceptClassification(t *testing.T) {
	e := newEnv(t, nil)
	got := map[string]map[string]any{}
	for _, id := range vulnGoldenIDs {
		resp, b := e.get(t, "/api/vuln/"+id)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", id, resp.StatusCode, b)
		}
		got[id] = decode(t, b)
	}
	if os.Getenv("NDAY_WRITE_VULN_GOLDEN") == "1" {
		for _, m := range got {
			if _, ok := m["classification"]; ok {
				t.Fatal("refusing to write the pre-classification golden from a tree that has the classification object")
			}
		}
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vulnGoldenFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("golden written")
	}
	raw, err := os.ReadFile(vulnGoldenFile)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for _, id := range vulnGoldenIDs {
		m := got[id]
		c, ok := m["classification"].(map[string]any)
		if !ok {
			t.Errorf("%s: no classification object", id)
		} else if _, ok := c["cwe"].([]any); !ok {
			t.Errorf("%s: classification.cwe is not an array: %v", id, c)
		} else if _, ok := c["cvss"].([]any); !ok {
			t.Errorf("%s: classification.cvss is not an array: %v", id, c)
		}
		delete(m, "classification")
		if _, ok := m["tags"].([]any); !ok {
			t.Errorf("%s: tags is not an array: %v", id, m["tags"])
		}
		delete(m, "tags")
		if c, ok := m["credits"].([]any); !ok || len(c) != 0 {
			t.Errorf("%s: credits is not an empty array: %v", id, m["credits"])
		}
		delete(m, "credits")
		if !reflect.DeepEqual(m, want[id]) {
			a, _ := json.Marshal(m)
			b, _ := json.Marshal(want[id])
			t.Errorf("%s: existing fields changed\n got %s\nwant %s", id, a, b)
		}
	}
}

// The classification object, filled from the classification layer, on both
// the website API path and the API host's /v1 path.
func TestVulnClassificationObject(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	ctx := context.Background()
	nvd := `{"id":"CVE-2026-102895","vulnStatus":"Analyzed",
	  "weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":"CWE-287"}]},
	                {"source":"security-advisories@github.com","type":"Secondary","description":[{"lang":"en","value":"CWE-287"},{"lang":"en","value":"NVD-CWE-noinfo"}]}],
	  "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}`
	if _, err := d.Conn.Exec(ctx, `INSERT INTO raw_record (source, source_key, content_hash, payload) VALUES ('nvd', 'CVE-2026-102895', 'h-nvd', $1::jsonb)`, nvd); err != nil {
		t.Fatal(err)
	}
	if _, err := classify.ByCVE(ctx, d.Conn, []string{"CVE-2026-102895"}, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	store := site.New(pool).WithClock(func() time.Time { return sitetest.Now })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	single := httptest.NewServer(web.New(web.Config{Store: store, Logger: log}).Handler())
	t.Cleanup(single.Close)
	two := httptest.NewServer(web.New(web.Config{Store: store, Logger: log, PublicURL: testPublic, APIURL: testAPI}).Handler())
	t.Cleanup(two.Close)
	want := `{"cvss":[{"base_score":9.8,"severity":"CRITICAL","source":"nvd-primary","source_org":"nvd@nist.gov","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","version":"3.1"}],` +
		`"cwe":[{"id":"CWE-287","sources":[{"source":"nvd-primary","source_org":"nvd@nist.gov"},{"source":"nvd-secondary","source_org":"security-advisories@github.com"}]}]}`
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
		_ = json.Unmarshal(m["classification"], &v)
		got, _ := json.Marshal(v) // sorted keys
		if string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s", c.path, got, want)
		}
		// the event-derived fields are untouched by the classification layer
		if !strings.Contains(string(m["cvss"]), `"source":"cvelist:cna"`) || !strings.Contains(string(m["cwes"]), `"CWE-20"`) {
			t.Errorf("%s: cvss %s cwes %s", c.path, m["cvss"], m["cwes"])
		}
	}
}
