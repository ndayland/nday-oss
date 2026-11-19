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
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

// tagServers: the seed data with tags, served in single-host and two-host mode.
func tagServers(t *testing.T) (single, two *httptest.Server) {
	t.Helper()
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	sitetest.SeedTags(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2})
	t.Cleanup(pool.Close)
	store := site.New(pool).WithClock(func() time.Time { return sitetest.Now })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	single = httptest.NewServer(gated(web.New(web.Config{Store: store, Logger: log})).Handler())
	t.Cleanup(single.Close)
	two = httptest.NewServer(gated(web.New(web.Config{Store: store, Logger: log, PublicURL: testPublic, APIURL: testAPI})).Handler())
	t.Cleanup(two.Close)
	return single, two
}

func TestTagsAPI(t *testing.T) {
	single, two := tagServers(t)
	type row struct {
		CVEID string   `json:"cve_id"`
		Tags  []string `json:"tags"`
	}
	type list struct {
		Tags []string `json:"tags"`
		Rows []row    `json:"rows"`
		Kind string   `json:"kind"`
	}
	ids := func(l list) string {
		var s []string
		for _, r := range l.Rows {
			s = append(s, r.CVEID)
		}
		return strings.Join(s, " ")
	}
	for _, c := range []struct {
		ts         *httptest.Server
		host, base string
	}{{single, "", "/api"}, {two, apiHost, "/v1"}} {
		get := func(path string, want int) []byte {
			t.Helper()
			resp, b := do(t, c.ts, http.MethodGet, c.host, c.base+path)
			if resp.StatusCode != want {
				t.Fatalf("%s%s: %d %s", c.base, path, resp.StatusCode, b)
			}
			return b
		}
		// hot: repeatable tag (AND), echoed canonical; rows carry their tags
		var h list
		_ = json.Unmarshal(get("/hot?since=30d&tag=no-auth&tag=REMOTE-UNAUTH", 200), &h)
		if strings.Join(h.Tags, ",") != "remote-unauth,no-auth" || ids(h) != sitetest.GPU {
			t.Errorf("hot tags %v rows %s", h.Tags, ids(h))
		}
		if len(h.Rows) == 1 && strings.Join(h.Rows[0].Tags, ",") != "auth-bypass,remote-unauth,network,no-auth,no-interaction,metasploit,exploit-db,nuclei" {
			t.Errorf("row tags %v", h.Rows[0].Tags)
		}
		_ = json.Unmarshal(get("/hot?since=30d&tag=ransomware", 200), &h)
		if ids(h) != "CVE-2026-1008" {
			t.Errorf("ransomware rows %s", ids(h))
		}
		_ = json.Unmarshal(get("/hot?since=30d", 200), &h)
		if len(h.Tags) != 0 || len(h.Rows) < 5 {
			t.Errorf("unfiltered %v %d", h.Tags, len(h.Rows))
		}
		for _, bad := range []string{"/hot?tag=nope", "/hot?tag=xss&tag=csrf&tag=ssrf&tag=xxe&tag=npm&tag=go", "/search?q=gpu&tag=nope"} {
			b := get(bad, 400)
			if !strings.Contains(string(b), `"param":"tag"`) {
				t.Errorf("%s: %s", bad, b)
			}
		}
		// search: query + tags, tags alone
		var s list
		_ = json.Unmarshal(get("/search?q=gpu&tag=auth-bypass", 200), &s)
		if ids(s) != sitetest.GPU || s.Kind != "text" {
			t.Errorf("search q+tag %s %s", s.Kind, ids(s))
		}
		_ = json.Unmarshal(get("/search?q=gpu&tag=xss", 200), &s)
		if len(s.Rows) != 0 {
			t.Errorf("search q+xss %s", ids(s))
		}
		_ = json.Unmarshal(get("/search?tag=network", 200), &s)
		if s.Kind != "tags" || ids(s) != sitetest.GPU+" CVE-2026-1002" && ids(s) != "CVE-2026-1002 "+sitetest.GPU {
			t.Errorf("search tags only %s %s", s.Kind, ids(s))
		}
		// the vocabulary with counts
		var tr struct {
			Note        string   `json:"note"`
			RuleVersion int      `json:"rule_version"`
			Dimensions  []string `json:"dimensions"`
			Tags        []struct {
				Slug, Dimension, Label, Rule string
				Count                        int64
			} `json:"tags"`
			CountsAt *time.Time `json:"counts_at"`
		}
		_ = json.Unmarshal(get("/tags", 200), &tr)
		if len(tr.Tags) != len(tags.Vocabulary) || tr.RuleVersion != tags.RuleVersion || tr.CountsAt == nil ||
			!strings.Contains(tr.Note, "not assigned by NVD") || len(tr.Dimensions) != len(tags.Dimensions) {
			t.Errorf("tags endpoint %+v", tr)
		}
		counts := map[string]int64{}
		for _, x := range tr.Tags {
			counts[x.Slug] = x.Count
			if x.Label == "" || x.Rule == "" || x.Dimension == "" {
				t.Errorf("tag entry %+v", x)
			}
		}
		// product tags (rule version 2): FortiOS from NVD's CPE, router from a type rule
		if counts["fortios"] != 1 || counts["firewall-vpn"] != 1 || counts["network-device"] != 1 || counts["windows"] != 0 {
			t.Errorf("product counts %v", counts)
		}
		if counts["network"] != 2 || counts["ransomware"] != 1 || counts["xss"] != 0 || counts["auth-bypass"] != 1 {
			t.Errorf("counts %v", counts)
		}
		get("/tags?x=1", 400)
		// vuln JSON: tags with slug, dimension, basis, origin
		var v struct {
			Tags []tags.View `json:"tags"`
		}
		_ = json.Unmarshal(get("/vuln/"+sitetest.GPU, 200), &v)
		var auth *tags.View
		for i := range v.Tags {
			if v.Tags[i].Slug == "auth-bypass" {
				auth = &v.Tags[i]
			}
		}
		if auth == nil || auth.Dimension != "type" || auth.Origin != "rule" || auth.RuleVersion == nil ||
			!strings.Contains(string(auth.Basis), `"source":"nvd-primary"`) || !strings.Contains(string(auth.Basis), `"id":"CWE-287"`) {
			t.Errorf("vuln tags %+v", v.Tags)
		}
		_ = json.Unmarshal(get("/vuln/CVE-2026-1005", 200), &v)
		if len(v.Tags) != 0 {
			t.Errorf("rejected CVE has tags %+v", v.Tags)
		}
	}
}
