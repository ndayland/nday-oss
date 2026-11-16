package nvd

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Limits.
const (
	// MaxRecordBytes caps one feed entry (the largest seen in the 2010 and
	// 2018 files is 347 KB, CVE-2018-12207): the parser never buffers more
	// than this beyond the current position.
	MaxRecordBytes = 16 << 20
	// MaxUnpackedBytes caps a decompressed feed when no .meta size is known
	// (the 2026 file was 44 MB compressed); with a .meta the cap is its size.
	MaxUnpackedBytes = 4 << 30
)

// ErrRecordTooLarge: a single entry (or header value) exceeds the cap.
var ErrRecordTooLarge = errors.New("nvd feed: entry larger than the record cap")

// Meta is a feed's .meta file:
//
//	lastModifiedDate:2026-11-13T10:00:08-05:00
//	size:106839794        (bytes of the UNPACKED .json)
//	zipSize:9449760
//	gzSize:9449616        (bytes of the .json.gz)
//	sha256:8D33...        (upper-case hex SHA-256 of the UNPACKED .json)
//
// The size and checksum semantics were verified on 2026-11-14 by gunzipping
// the modified and recent feeds and hashing the output (docs/nvd.md).
type Meta struct {
	LastModified time.Time // UTC
	Raw          string    // lastModifiedDate as delivered
	Size         int64
	GzSize       int64
	SHA256       string // lower-case hex
}

// ParseMeta parses a .meta body; every field above is required.
func ParseMeta(b []byte) (Meta, error) {
	var m Meta
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return m, fmt.Errorf("nvd meta: bad line %q", line)
		}
		v = strings.TrimSpace(v)
		var err error
		switch k {
		case "lastModifiedDate":
			m.Raw = v
			var t time.Time
			if t, err = time.Parse(time.RFC3339, v); err == nil {
				m.LastModified = t.UTC()
			}
		case "size":
			m.Size, err = strconv.ParseInt(v, 10, 64)
		case "gzSize":
			m.GzSize, err = strconv.ParseInt(v, 10, 64)
		case "sha256":
			if len(v) != 64 {
				err = errors.New("not 64 hex digits")
			} else if _, err = hex.DecodeString(v); err == nil {
				m.SHA256 = strings.ToLower(v)
			}
		default:
			continue // zipSize and anything new
		}
		if err != nil {
			return m, fmt.Errorf("nvd meta: %s: %v", k, err)
		}
		seen[k] = true
	}
	for _, k := range []string{"lastModifiedDate", "size", "gzSize", "sha256"} {
		if !seen[k] {
			return m, fmt.Errorf("nvd meta: missing %s", k)
		}
	}
	if m.Size <= 0 || m.GzSize <= 0 {
		return m, errors.New("nvd meta: non-positive size")
	}
	return m, nil
}

// ChecksumError: the unpacked feed does not match its .meta.
type ChecksumError struct{ Msg string }

func (e *ChecksumError) Error() string { return "nvd feed checksum: " + e.Msg }

// cappedReader fails once more than max bytes were read.
type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("nvd feed: unpacked data exceeds %d bytes (decompression cap)", c.max)
	}
	return n, err
}

// Unpack returns a reader of the decompressed feed, failing after max bytes
// (use the .meta size when known). A truncated gzip stream surfaces as an
// error (io.ErrUnexpectedEOF) from Read.
func Unpack(gz io.Reader, max int64) (io.Reader, error) {
	zr, err := gzip.NewReader(gz)
	if err != nil {
		return nil, fmt.Errorf("nvd feed: %w", err)
	}
	zr.Multistream(false)
	return &cappedReader{r: zr, max: max}, nil
}

// Verify reads the whole gzip stream and checks the unpacked size and
// SHA-256 against m. It never holds more than a small buffer.
func Verify(gz io.Reader, m Meta) error {
	r, err := Unpack(gz, m.Size)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return fmt.Errorf("nvd feed: %w", err)
	}
	if n != m.Size {
		return &ChecksumError{Msg: fmt.Sprintf("unpacked %d bytes, .meta says %d", n, m.Size)}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		return &ChecksumError{Msg: fmt.Sprintf("sha256 %s, .meta says %s", got, m.SHA256)}
	}
	return nil
}

// Header is the top level of a feed document (everything but the entries).
type Header struct {
	Format       string `json:"format"`
	Version      string `json:"version"`
	Timestamp    string `json:"timestamp"`
	TotalResults *int   `json:"totalResults"`
}

// Entry is one element of "vulnerabilities".
type Entry struct {
	// ID is cve.id ("" if absent or not a string).
	ID string
	// CVE is the "cve" object exactly as delivered (nil if absent).
	CVE json.RawMessage
	// Offset is the input offset just after the entry (bytes of the
	// unpacked document consumed so far).
	Offset int64
}

// guard fails a read when the decoder holds more than max unconsumed
// bytes, i.e. when the value being decoded is larger than max.
type guard struct {
	r    io.Reader
	dec  *json.Decoder
	read int64
	max  int64
}

func (g *guard) Read(p []byte) (int, error) {
	if g.dec != nil && g.read-g.dec.InputOffset() > g.max {
		return 0, ErrRecordTooLarge
	}
	// never read more than the cap allows past the current position
	n, err := g.r.Read(p)
	g.read += int64(n)
	return n, err
}

// Parse streams a feed document (unpacked JSON) and calls fn for every entry
// of "vulnerabilities", in order, with bounded memory: one entry at a time
// (json.Decoder token streaming), never more than maxRecord bytes buffered.
// fn's error stops parsing and is returned. The document must be an object
// whose "vulnerabilities" is an array; when "totalResults" is present the
// entry count must equal it (a second guard against truncation). Returns the
// header and the number of entries.
func Parse(r io.Reader, maxRecord int64, fn func(Entry) error) (Header, int, error) {
	var h Header
	if maxRecord <= 0 {
		maxRecord = MaxRecordBytes
	}
	g := &guard{r: r, max: maxRecord}
	dec := json.NewDecoder(g)
	g.dec = dec
	tok, err := dec.Token()
	if err != nil {
		return h, 0, fmt.Errorf("nvd feed: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return h, 0, errors.New("nvd feed: document is not a JSON object")
	}
	n := 0
	sawList := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return h, n, fmt.Errorf("nvd feed: %w", err)
		}
		key, _ := tok.(string)
		switch key {
		case "vulnerabilities":
			sawList = true
			tok, err := dec.Token()
			if err != nil {
				return h, n, fmt.Errorf("nvd feed: %w", err)
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return h, n, errors.New("nvd feed: vulnerabilities is not an array")
			}
			for dec.More() {
				var item struct {
					CVE json.RawMessage `json:"cve"`
				}
				if err := dec.Decode(&item); err != nil {
					return h, n, fmt.Errorf("nvd feed: entry %d: %w", n, err)
				}
				e := Entry{CVE: item.CVE, Offset: dec.InputOffset()}
				if len(item.CVE) > 0 {
					var idOnly struct {
						ID any `json:"id"`
					}
					if json.Unmarshal(item.CVE, &idOnly) == nil {
						e.ID, _ = idOnly.ID.(string)
					}
				}
				n++
				if err := fn(e); err != nil {
					return h, n, err
				}
			}
			if _, err := dec.Token(); err != nil { // ']'
				return h, n, fmt.Errorf("nvd feed: %w", err)
			}
		case "format", "version", "timestamp", "totalResults":
			var v any
			if err := dec.Decode(&v); err != nil {
				return h, n, fmt.Errorf("nvd feed: %s: %w", key, err)
			}
			switch key {
			case "format":
				h.Format, _ = v.(string)
			case "version":
				h.Version, _ = v.(string)
			case "timestamp":
				h.Timestamp, _ = v.(string)
			case "totalResults":
				if f, ok := v.(float64); ok {
					t := int(f)
					h.TotalResults = &t
				}
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return h, n, fmt.Errorf("nvd feed: %s: %w", key, err)
			}
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return h, n, fmt.Errorf("nvd feed: %w", err)
	}
	if !sawList {
		return h, n, errors.New("nvd feed: no vulnerabilities array")
	}
	if h.Format != "" && h.Format != "NVD_CVE" {
		return h, n, fmt.Errorf("nvd feed: format %q, want NVD_CVE", h.Format)
	}
	if h.TotalResults != nil && *h.TotalResults != n {
		return h, n, fmt.Errorf("nvd feed: %d entries, totalResults says %d (truncated?)", n, *h.TotalResults)
	}
	return h, n, nil
}
