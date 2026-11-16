// Package feed is the shared plumbing of the collectors that download ONE
// curated feed file per run (exploitdb, metasploit, nuclei). It is the Go
// port of src/nday/collectors/_feed.py; it is not a collector itself.
//
// What it does (identical to Python):
//   - Download: one GET with the generic User-Agent, a fixed
//     "Accept-Encoding: gzip" (raw.githubusercontent.com gives the gzip variant
//     a different, weak ETag than the identity variant; pinning the encoding
//     keeps the stored validator valid), connect 15 s / read 120 s timeouts,
//     MaxAttempts=4 with 1/2/4 s backoff on 429 / 5xx / transport errors
//     (Retry-After honoured up to 60 s), and a hard cap on the DECODED body
//     (checked against the declared Content-Length first, then while
//     streaming the decoded bytes).
//   - Conditional requests: ETag / Last-Modified of the response are stored
//     in the cursor and sent back as If-None-Match / If-Modified-Since (only
//     when the cursor's "url" equals the feed URL). A 304 yields zero records
//     and keeps the validators and the "feed" counts of the last download.
//   - Items without any CVE-looking token are not returned (only counted in
//     cursor.last_run.items_without_cve).
//   - U+0000 in strings (and keys) is replaced by the 6-character text
//     `\u0000` (PostgreSQL rejects NUL); affected keys (first 20) are listed
//     in items_nul_scrubbed.
//
// Content decoding: Go's http.Transport only decompresses transparently when
// the caller did NOT set Accept-Encoding. Because the header is pinned here,
// decoding is done by decodingTransport (gzip / deflate / identity, the
// decoders httpx has without the optional brotli/zstandard packages), which
// keeps resp.ContentLength = the declared (compressed) Content-Length, so
// httpc's Content-Length pre-check and its streaming cap apply exactly where
// Python applies them.
package feed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// Constants of _feed.py.
const (
	DefaultMaxBytes = 64 * 1024 * 1024
	MaxAttempts     = 4
	BackoffBase     = time.Second
	MaxRetryAfter   = 60 * time.Second
	ConnectTimeout  = 15 * time.Second
	ReadTimeout     = 120 * time.Second
)

// NulReplacement is the 6-char text '\u0000' (as the upstream JSON spells it).
const NulReplacement = `\u0000`

// FeedTooLarge is Python's FeedTooLarge (the feed exceeded the size cap;
// nothing is stored). The type name ends up in collector_state.last_error.
type FeedTooLarge struct{ Msg string }

func (e *FeedTooLarge) Error() string { return e.Msg }

// Item is one in-scope upstream item: (source_key, payload).
type Item struct {
	Key     string
	Payload any
}

// Parser is what a concrete feed collector provides (Python subclass hooks).
type Parser interface {
	// ParseItems: body -> in-scope items (upstream order) and the extra counts
	// for cursor.last_run (an ordered object of pyjson.Int). An error fails
	// the run (Python: ValueError / JSONDecodeError / UnicodeDecodeError).
	ParseItems(body []byte) ([]Item, *pyjson.Object, error)
	// CVETokens: candidate CVE strings of one item (unvalidated; empty = no CVE).
	CVETokens(payload any) []any
}

// Options configures a Base.
type Options struct {
	Transport http.RoundTripper // nil: real network (HTTP/1.1, like httpx)
	URL       string            // "" = the collector's default feed URL
	// MaxBytes: decoded body cap; 0 = DefaultMaxBytes. Python raises
	// ValueError for an explicit value < 1; New returns an error for < 0.
	MaxBytes int64
	Sleep    func(ctx context.Context, d time.Duration) error // tests: no-op
	Logger   *slog.Logger
}

// Base implements Name and Fetch of a feed collector (Python FeedCollector).
type Base struct {
	name     string
	URL      string
	MaxBytes int64
	HTTP     *httpc.Client
	Logger   *slog.Logger
	parser   Parser
}

// NewBase builds the shared part of a feed collector.
func NewBase(name, defaultURL string, p Parser, o Options) (*Base, error) {
	if o.MaxBytes < 0 {
		return nil, fmt.Errorf("max_bytes must be >= 1, got %d", o.MaxBytes)
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.URL == "" {
		o.URL = defaultURL
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	base := o.Transport
	if base == nil {
		base = defaultTransport()
	}
	return &Base{
		name:     name,
		URL:      o.URL,
		MaxBytes: o.MaxBytes,
		Logger:   o.Logger,
		parser:   p,
		HTTP: httpc.New(httpc.Options{
			Transport:     decodingTransport{base: base},
			MaxAttempts:   MaxAttempts,
			BackoffBase:   BackoffBase,
			MaxRetryAfter: MaxRetryAfter,
			MaxBytes:      o.MaxBytes,
			ConnTimeout:   ConnectTimeout,
			ReadTimeout:   ReadTimeout,
			Sleep:         o.Sleep,
			Logger:        o.Logger,
		}),
	}, nil
}

// defaultTransport mirrors httpc's default transport (its constructor is not
// exported) except that it speaks HTTP/1.1 only, like httpx's default client.
func defaultTransport() http.RoundTripper {
	dialer := &net.Dialer{Timeout: ConnectTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   ConnectTimeout,
		ResponseHeaderTimeout: ReadTimeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}
}

// Name implements collector.Collector.
func (b *Base) Name() string { return b.name }

// Response is Python's FeedResponse.
type Response struct {
	Status       int
	Body         []byte // nil on 304
	ETag         any    // string or nil (Python: str | None)
	LastModified any
	Attempts     int
}

// NotModified reports a 304.
func (r *Response) NotModified() bool { return r.Status == http.StatusNotModified }

// headerValue is httpx's headers.get(name): all values joined with ", ", or
// nil when the header is absent (an empty value is "" — not None).
func headerValue(h http.Header, name string) any {
	vs := h.Values(name)
	if len(vs) == 0 {
		return nil
	}
	return strings.Join(vs, ", ")
}

// validator turns a cursor value into the header to send: Python sends it
// when truthy (`if etag:`). A truthy non-string would make httpx fail.
func validator(v any) (string, bool, error) {
	if !Truthy(v) {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, fmt.Errorf("Header value must be str or bytes, not %T", v)
	}
	return s, true, nil
}

// Download is Python's download(): one conditional GET with retries.
// etag / lastModified are the raw cursor values (nil when not same feed).
func (b *Base) Download(ctx context.Context, etag, lastModified any) (*Response, error) {
	hdr := http.Header{}
	// httpx sends Accept: */* by default; User-Agent is set by httpc.
	hdr.Set("Accept", "*/*")
	hdr.Set("Accept-Encoding", "gzip")
	if v, ok, err := validator(etag); err != nil {
		return nil, err
	} else if ok {
		hdr.Set("If-None-Match", v)
	}
	if v, ok, err := validator(lastModified); err != nil {
		return nil, err
	} else if ok {
		hdr.Set("If-Modified-Since", v)
	}
	resp, err := b.HTTP.Get(ctx, b.URL, httpc.GetOptions{
		Header: hdr,
		// httpx raise_for_status() passes 2xx only; 304 is handled before it.
		Accept: func(s int) bool { return s == http.StatusNotModified || (s >= 200 && s < 300) },
	})
	if err != nil {
		var tl *httpc.TooLargeError
		if errors.As(err, &tl) {
			if strings.HasPrefix(tl.Msg, "Content-Length ") {
				return nil, &FeedTooLarge{Msg: fmt.Sprintf("%s: %s > cap %d", b.URL, tl.Msg, b.MaxBytes)}
			}
			return nil, &FeedTooLarge{Msg: fmt.Sprintf("%s: body exceeds cap %d bytes", b.URL, b.MaxBytes)}
		}
		return nil, err
	}
	if resp.Status == http.StatusNotModified {
		e := headerValue(resp.Header, "ETag")
		if !Truthy(e) {
			e = etag
		}
		lm := headerValue(resp.Header, "Last-Modified")
		if !Truthy(lm) {
			lm = lastModified
		}
		return &Response{Status: resp.Status, ETag: e, LastModified: lm, Attempts: resp.Attempts}, nil
	}
	body := resp.Body
	if body == nil {
		body = []byte{}
	}
	return &Response{Status: resp.Status, Body: body, ETag: headerValue(resp.Header, "ETag"),
		LastModified: headerValue(resp.Header, "Last-Modified"), Attempts: resp.Attempts}, nil
}

// Fetch is FeedCollector.fetch.
func (b *Base) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	// Python: prev = dict(state.cursor or {})
	var prev *pyjson.Object
	switch c := state.Cursor.(type) {
	case *pyjson.Object:
		prev = c
	default:
		if Truthy(c) {
			return nil, fmt.Errorf("cursor is not an object: %s", pyjson.Repr(c))
		}
		prev = pyjson.NewObject()
	}
	sameFeed := false
	if u, ok := prev.Get("url").(string); ok && u == b.URL {
		sameFeed = true
	}
	var etag, lastModified any
	if sameFeed {
		etag, lastModified = prev.Get("etag"), prev.Get("last_modified")
	}
	resp, err := b.Download(ctx, etag, lastModified)
	if err != nil {
		return nil, err
	}
	cursor := pyjson.NewObject()
	cursor.Set("url", b.URL)
	cursor.Set("etag", resp.ETag)
	cursor.Set("last_modified", resp.LastModified)
	if resp.NotModified() {
		cursor.Set("feed", prev.Get("feed"))
		lr := pyjson.NewObject()
		lr.Set("http_status", pyjson.IntOf(int64(resp.Status)))
		lr.Set("attempts", pyjson.IntOf(int64(resp.Attempts)))
		cursor.Set("last_run", lr)
		return &model.FetchResult{Records: nil, Cursor: cursor}, nil
	}
	items, extra, err := b.parser.ParseItems(resp.Body)
	if err != nil {
		return nil, err
	}
	var records []model.RawRecord
	withoutCVE := 0
	nulScrubbed := []any{}
	for _, it := range items {
		if len(b.parser.CVETokens(it.Payload)) == 0 {
			withoutCVE++
			continue
		}
		payload, n := ScrubNul(it.Payload)
		if n > 0 {
			nulScrubbed = append(nulScrubbed, it.Key)
			b.Logger.Warn(fmt.Sprintf("%s: %s contains NUL characters; stored as literal '\\u0000'", b.name, it.Key))
		}
		records = append(records, model.RawRecord{Source: b.name, SourceKey: it.Key, Payload: payload})
	}
	feed := pyjson.NewObject()
	feed.Set("bytes", pyjson.IntOf(int64(len(resp.Body))))
	if extra != nil {
		for _, k := range extra.Keys() {
			feed.Set(k, extra.Get(k))
		}
	}
	feed.Set("items_in_scope", pyjson.IntOf(int64(len(items))))
	feed.Set("items_with_cve", pyjson.IntOf(int64(len(records))))
	feed.Set("items_without_cve", pyjson.IntOf(int64(withoutCVE)))
	feed.Set("items_nul_scrubbed", nulScrubbed[:min(len(nulScrubbed), 20)])
	cursor.Set("feed", feed)
	lr := pyjson.NewObject()
	lr.Set("http_status", pyjson.IntOf(int64(resp.Status)))
	lr.Set("attempts", pyjson.IntOf(int64(resp.Attempts)))
	for _, k := range feed.Keys() {
		lr.Set(k, feed.Get(k))
	}
	cursor.Set("last_run", lr)
	return &model.FetchResult{Records: records, Cursor: cursor}, nil
}

// ScrubNul is Python's scrub_nul: U+0000 in strings and object keys becomes
// the 6-char text `\u0000`; returns the (copied where changed) value and the
// number of strings changed.
func ScrubNul(v any) (any, int) {
	switch x := v.(type) {
	case string:
		if strings.IndexByte(x, 0) >= 0 {
			return strings.ReplaceAll(x, "\x00", NulReplacement), 1
		}
		return x, 0
	case []any:
		out, n := make([]any, len(x)), 0
		for i, e := range x {
			var k int
			out[i], k = ScrubNul(e)
			n += k
		}
		return out, n
	case *pyjson.Object:
		res, n := pyjson.NewObject(), 0
		for _, key := range x.Keys() {
			k2, k1 := ScrubNul(key)
			val, k := ScrubNul(x.Get(key))
			res.Set(k2.(string), val)
			n += k1 + k
		}
		return res, n
	default:
		return v, 0
	}
}

// Truthy is Python's bool() for a pyjson value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case pyjson.Int:
		return x != "0"
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case []any:
		return len(x) > 0
	case *pyjson.Object:
		return x.Len() > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// Text is _feed.text (= collector.Text): a stripped non-empty string or nil,
// returned as a pyjson value for event detail.
func Text(v any) any {
	if s := collector.Text(v); s != nil {
		return *s
	}
	return nil
}

// upper is Python's str.upper() as far as CVE ids are concerned. Go's
// per-rune mapping differs from Python's full case mapping only for
// characters whose Python upper-case is NOT one of "C", "V", "E", "-" or a
// decimal digit (verified over all code points with Python 3.13 / Unicode
// 15.1: no character other than c/v/e/C/V/E/- upper-cases to text containing
// C, V, E or -), so the startswith("CVE") test and is_valid_cve_id of the
// result are identical; invalid tokens are reported verbatim, not upper-cased.
func upper(s string) string { return strings.ToUpper(s) }

// HasCVEPrefix is Python's tok.strip().upper().startswith("CVE").
func HasCVEPrefix(tok string) bool { return strings.HasPrefix(upper(pystr.Strip(tok)), "CVE") }

// SplitCVEIDs is Python's split_cve_ids: valid ids stripped, upper-cased,
// deduped in upstream order; dropped tokens verbatim (repr() for non-strings).
func SplitCVEIDs(tokens []any) (valid []string, dropped []string) {
	seen := map[string]bool{}
	for _, tok := range tokens {
		s := ""
		ts, isStr := tok.(string)
		if isStr {
			s = upper(pystr.Strip(ts))
		}
		if model.IsValidCVEID(s) {
			if !seen[s] {
				seen[s] = true
				valid = append(valid, s)
			}
			continue
		}
		if isStr {
			dropped = append(dropped, ts)
		} else {
			dropped = append(dropped, pyjson.Repr(tok))
		}
	}
	return valid, dropped
}

// RequireCVEs is Python's require_cves: SplitCVEIDs, but an item with no
// valid id is a NormalizeError "<key>: no valid CVE id among [...]".
func RequireCVEs(sourceKey string, tokens []any) ([]string, []string, error) {
	valid, dropped := SplitCVEIDs(tokens)
	if len(valid) == 0 {
		return nil, nil, collector.NormalizeErrorf("%s: no valid CVE id among %s", sourceKey, pyjson.Repr(Strings(dropped)))
	}
	return valid, dropped, nil
}

// Strings converts []string to a pyjson list ([]any, never nil).
func Strings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
