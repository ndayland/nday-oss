package cli_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/testutil"
)

// nvdTransport serves the fixture as https://nvd.nist.gov/feeds/json/cve/2.0/
// nvdcve-2.0-modified.{meta,json.gz} (no network).
func nvdTransport(t *testing.T, doc []byte) http.RoundTripper {
	t.Helper()
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(doc)
	w.Close()
	h := sha256.Sum256(doc)
	meta := fmt.Sprintf("lastModifiedDate:2026-11-13T10:00:08-05:00\r\nsize:%d\r\nzipSize:1\r\ngzSize:%d\r\nsha256:%s\r\n",
		len(doc), z.Len(), strings.ToUpper(hex.EncodeToString(h[:])))
	return httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body []byte
		switch r.URL.String() {
		case "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta":
			body = []byte(meta)
		case "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz":
			body = z.Bytes()
		default:
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
			Header: http.Header{}, Request: r}, nil
	})
}

func TestCollectNVDAndClassify(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ctx := context.Background()
	// two CVEs the CVE List already delivered
	if _, err := d.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ('CVE-2018-0125'), ('CVE-2010-0157')`); err != nil {
		t.Fatal(err)
	}
	doc := testutil.ReadFile(t, "internal/collector/nvd/testdata/fixture.json")
	env := cli.Env{Transport: nvdTransport(t, doc), Now: func() time.Time { return time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC) }}
	code, out, errOut := runCLI(t, env, "collect", "nvd")
	if code != 0 {
		t.Fatalf("collect nvd: %d %s %s", code, out, errOut)
	}
	var st struct {
		Outcome string `json:"outcome"`
		Total   struct {
			New int `json:"raw_new"`
		} `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Outcome != "modified" || st.Total.New != 24 {
		t.Fatalf("%s %v", out, err)
	}
	// the post-run pass classified the two vulns; NVD created no vuln row
	var cwe, vulns, queue int
	d.Conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM vuln_cwe), (SELECT count(*) FROM vuln), (SELECT count(*) FROM classify_queue)`).Scan(&cwe, &vulns, &queue)
	if cwe != 3 || vulns != 2 || queue != 0 || !strings.Contains(errOut, "classification pass") {
		t.Errorf("cwe=%d vulns=%d queue=%d\n%s", cwe, vulns, queue, errOut)
	}
	// second run: .meta unchanged, nothing downloaded or written
	code, out, _ = runCLI(t, env, "collect", "nvd")
	if code != 0 || !strings.Contains(out, `"outcome": "unchanged"`) {
		t.Errorf("%d %s", code, out)
	}
	// renormalize nvd: no events, nothing written
	code, out, _ = runCLI(t, env, "renormalize", "nvd", "--dry-run")
	if code != 0 || !strings.Contains(out, `"fetched": 24,`) || !strings.Contains(out, `"event_inserted": 0,`) || !strings.Contains(out, `"vuln_inserted": 0,`) {
		t.Errorf("renormalize: %d %s", code, out)
	}
	// classify commands
	code, out, _ = runCLI(t, env, "classify", "--all", "--dry-run")
	if code != 0 || !strings.Contains(out, `"changed": 0`) || !strings.Contains(out, `"dry_run": true`) {
		t.Errorf("classify --all --dry-run: %d %s", code, out)
	}
	code, out, _ = runCLI(t, env, "classify", "--cve", "cve-2018-0125", "CVE-2010-0157")
	if code != 0 || !strings.Contains(out, `"cves": 2`) || !strings.Contains(out, `"unchanged": 2`) {
		t.Errorf("classify --cve: %d %s", code, out)
	}
	code, out, _ = runCLI(t, env, "classify", "--source", "nvd")
	if code != 0 || !strings.Contains(out, `"no_vuln": 22`) {
		t.Errorf("classify --source nvd: %d %s", code, out)
	}
	for _, bad := range [][]string{
		{"classify"}, {"classify", "--all", "--pending"}, {"classify", "--source", "kev"}, {"classify", "--cve"},
		{"classify", "--cve", "nope"}, {"classify", "--all", "CVE-2026-1"}, {"classify", "--all", "--batch-size", "0"},
		{"import-nvd-baseline"}, {"import-nvd-baseline", "--dir", "x", "--download"}, {"import-nvd-baseline", "--download", "--year", "1999"},
		{"import-nvd-baseline", "--dir", "/nonexistent-dir"},
	} {
		if code, _, errOut := runCLI(t, env, bad...); code != 2 {
			t.Errorf("%v: %d %s", bad, code, errOut)
		}
	}
}

func TestImportNVDBaselineDir(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	dir := t.TempDir()
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(testutil.ReadFile(t, "internal/collector/nvd/testdata/fixture.json"))
	w.Close()
	if err := os.WriteFile(filepath.Join(dir, "2010.json.gz"), z.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, cli.Env{}, "import-nvd-baseline", "--dir", dir, "--year", "2010", "--year=2011", "--batch-size", "7")
	if code != 0 || !strings.Contains(out, `"raw_new": 24`) || !strings.Contains(out, `"missing": [`) || !strings.Contains(out, `"unverified": [`) {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	code, out, _ = runCLI(t, cli.Env{}, "import-nvd-baseline", "--dir", dir, "--year", "2010")
	if code != 0 || !strings.Contains(out, `"raw_unchanged": 24`) {
		t.Errorf("second run %d %s", code, out)
	}
}
