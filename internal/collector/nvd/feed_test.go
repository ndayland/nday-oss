package nvd

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureJSON(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// metaFor renders a .meta for the unpacked document b and its gzip bytes.
func metaFor(b, gzb []byte, lastMod time.Time) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("lastModifiedDate:%s\r\nsize:%d\r\nzipSize:%d\r\ngzSize:%d\r\nsha256:%s\r\n",
		lastMod.In(time.FixedZone("EST", -5*3600)).Format(time.RFC3339), len(b), len(gzb)+136, len(gzb),
		strings.ToUpper(hex.EncodeToString(h[:])))
}

func TestParseMeta(t *testing.T) {
	// the real modified-feed .meta of 2026-11-13 (CRLF as served)
	m, err := ParseMeta([]byte("lastModifiedDate:2026-11-13T10:00:08-05:00\r\nsize:106839794\r\nzipSize:9449760\r\ngzSize:9449616\r\nsha256:8D334DC83C27DF108B4AE1DABAEB31285CD8FF66F923EF6BFAE8E5C0641B0ADF\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !m.LastModified.Equal(time.Date(2026, 11, 13, 15, 0, 8, 0, time.UTC)) || m.Size != 106839794 || m.GzSize != 9449616 ||
		m.SHA256 != "8d334dc83c27df108b4ae1dabaeb31285cd8ff66f923ef6bfae8e5c0641b0adf" {
		t.Errorf("%+v", m)
	}
	for _, bad := range []string{"", "size:1\ngzSize:1\nsha256:" + strings.Repeat("A", 64),
		"lastModifiedDate:x\nsize:1\ngzSize:1\nsha256:" + strings.Repeat("A", 64),
		"lastModifiedDate:2026-11-13T10:00:08-05:00\nsize:1\ngzSize:1\nsha256:ZZ",
		"lastModifiedDate:2026-11-13T10:00:08-05:00\nsize:0\ngzSize:1\nsha256:" + strings.Repeat("A", 64),
		"<html>blocked</html>"} {
		if _, err := ParseMeta([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseFixture(t *testing.T) {
	b := fixtureJSON(t)
	var ids []string
	h, n, err := Parse(bytes.NewReader(b), 0, func(e Entry) error {
		ids = append(ids, e.ID)
		if len(e.CVE) == 0 || e.Offset <= 0 {
			t.Errorf("entry %+v", e.ID)
		}
		return nil
	})
	if err != nil || n != 24 || len(ids) != 24 || h.Format != "NVD_CVE" || h.Version != "2.0" || *h.TotalResults != 24 {
		t.Fatalf("%+v %d %v", h, n, err)
	}
	if ids[0] != "CVE-2010-20125" || ids[23] != "CVE-2010-99998" {
		t.Errorf("%v", ids)
	}
}

func TestParseErrors(t *testing.T) {
	b := fixtureJSON(t)
	cases := map[string][]byte{
		"truncated":       b[:len(b)/2],
		"not an object":   []byte(`[1,2]`),
		"no list":         []byte(`{"format":"NVD_CVE"}`),
		"list not array":  []byte(`{"vulnerabilities":{}}`),
		"wrong format":    []byte(`{"format":"X","vulnerabilities":[]}`),
		"count mismatch":  []byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-1000"}}]}`),
		"trailing broken": []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-1000"}}`),
	}
	for name, doc := range cases {
		if _, _, err := Parse(bytes.NewReader(doc), 0, func(Entry) error { return nil }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	stop := errors.New("stop")
	if _, n, err := Parse(bytes.NewReader(b), 0, func(Entry) error { return stop }); !errors.Is(err, stop) || n != 1 {
		t.Errorf("callback error: %d %v", n, err)
	}
}

// countingReader counts the bytes handed out.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	// fill p as far as possible (a file or network read does): the
	// decoder's read-ahead is then as large as it asks for
	n, err := io.ReadFull(c.r, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	c.n += int64(n)
	return n, err
}

// genFeed streams a document of n entries of about size bytes each,
// never materialised.
func genFeed(n, size int) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		pad := strings.Repeat("x", size)
		fmt.Fprintf(pw, `{"resultsPerPage":%d,"startIndex":0,"totalResults":%d,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-13T10:00:00.000","vulnerabilities":[`, n, n)
		for i := 0; i < n; i++ {
			if i > 0 {
				io.WriteString(pw, ",")
			}
			fmt.Fprintf(pw, `{"cve":{"id":"CVE-2026-%06d","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"%s"}]}}`, i+100000, pad)
		}
		io.WriteString(pw, "]}")
		pw.Close()
	}()
	return pr
}

// Bounded memory: over a 120 MB generated document the parser never holds
// more than 1 MiB beyond the entry it hands out (and the guard with a
// 64 KiB record cap never trips on 2 KB entries).
func TestParseBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	const n, size, limit = 60000, 2000, 1 << 20
	cr := &countingReader{r: genFeed(n, size)}
	maxAhead := int64(0)
	_, got, err := Parse(cr, 64<<10, func(e Entry) error {
		if ahead := cr.n - e.Offset; ahead > maxAhead {
			maxAhead = ahead
		}
		if cr.n-e.Offset > limit {
			return fmt.Errorf("buffered %d bytes beyond entry %s", cr.n-e.Offset, e.ID)
		}
		return nil
	})
	if err != nil || got != n {
		t.Fatalf("%d %v", got, err)
	}
	if cr.n < int64(n*size) {
		t.Fatalf("read only %d bytes", cr.n)
	}
	t.Logf("read %d bytes, at most %d bytes ahead of the parser", cr.n, maxAhead)
}

func TestParseRecordCap(t *testing.T) {
	doc := `{"vulnerabilities":[{"cve":{"id":"CVE-2026-1000","x":"` + strings.Repeat("y", 200<<10) + `"}}]}`
	if _, _, err := Parse(strings.NewReader(doc), 64<<10, func(Entry) error { return nil }); !errors.Is(err, ErrRecordTooLarge) {
		t.Errorf("want ErrRecordTooLarge, got %v", err)
	}
	if _, _, err := Parse(strings.NewReader(doc), 1<<20, func(Entry) error { return nil }); err != nil {
		t.Errorf("1 MiB cap: %v", err)
	}
}

func TestVerify(t *testing.T) {
	b := fixtureJSON(t)
	z := gz(t, b)
	m, err := ParseMeta([]byte(metaFor(b, z, time.Now())))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(bytes.NewReader(z), m); err != nil {
		t.Fatalf("good: %v", err)
	}
	wrong := m
	wrong.SHA256 = strings.Repeat("0", 64)
	var ce *ChecksumError
	if err := Verify(bytes.NewReader(z), wrong); !errors.As(err, &ce) {
		t.Errorf("wrong checksum: %v", err)
	}
	if err := Verify(bytes.NewReader(z[:len(z)-40]), m); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("truncated gzip: %v", err)
	}
	small := m
	small.Size = 1000 // decompression cap: more unpacked bytes than announced
	if err := Verify(bytes.NewReader(z), small); err == nil || !strings.Contains(err.Error(), "decompression cap") {
		t.Errorf("bomb cap: %v", err)
	}
	big := m
	big.Size = m.Size + 1
	if err := Verify(bytes.NewReader(z), big); !errors.As(err, &ce) {
		t.Errorf("short: %v", err)
	}
	if err := Verify(strings.NewReader("not gzip"), m); err == nil {
		t.Error("not gzip accepted")
	}
	// a gzip bomb (1 GiB of zeros, ~1 MB compressed) stops at the cap
	if testing.Short() {
		return
	}
	pr, pw := io.Pipe()
	go func() {
		w := gzip.NewWriter(pw)
		zero := make([]byte, 1<<20)
		for i := 0; i < 1024; i++ {
			if _, err := w.Write(zero); err != nil {
				return
			}
		}
		w.Close()
		pw.Close()
	}()
	r, err := Unpack(pr, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, r)
	pr.CloseWithError(errors.New("done"))
	if err == nil || n > 9<<20 {
		t.Errorf("bomb: %d bytes, %v", n, err)
	}
}
