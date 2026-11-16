package nvd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"nday.land/nday/internal/httpc"
)

// Feed locations (https://nvd.nist.gov/feeds/json/cve/2.0/, checked with
// curl on 2026-11-14; docs/nvd.md).
const (
	BaseURL = "https://nvd.nist.gov/feeds/json/cve/2.0"
	// FirstYear: the first yearly file (it also holds CVE-1999..2001).
	FirstYear = 2002
	// MaxGzBytes caps one downloaded .json.gz (the largest, 2026, was 44 MB).
	MaxGzBytes   = 512 << 20
	maxMetaBytes = 64 << 10
)

// FeedName of a year ("2010") or "modified" / "recent".
func yearName(y int) string { return fmt.Sprintf("%d", y) }

// Fetcher downloads .meta and .json.gz files. Download and parse/import are
// separate steps: Fetcher only returns bytes it verified.
type Fetcher struct {
	Base string
	meta *httpc.Client
	feed *httpc.Client
	log  *slog.Logger
}

// FetcherOptions configures NewFetcher.
type FetcherOptions struct {
	Base      string            // default BaseURL
	Transport http.RoundTripper // tests: httptest / fake; nil = real network
	Sleep     func(ctx context.Context, d time.Duration) error
	MaxGz     int64 // default MaxGzBytes
	Logger    *slog.Logger
}

// NewFetcher builds a Fetcher. Policy (httpc): generic User-Agent, 15 s
// connect, 120 s idle read timeout, 4 attempts with 1/2/4 s backoff on 429,
// 5xx and transport errors (Retry-After honoured up to 60 s), a hard body cap
// (64 KiB for .meta, MaxGz for feeds) and a 20 min overall deadline per feed
// download attempt.
func NewFetcher(o FetcherOptions) *Fetcher {
	if o.Base == "" {
		o.Base = BaseURL
	}
	if o.MaxGz <= 0 {
		o.MaxGz = MaxGzBytes
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Fetcher{
		Base: o.Base,
		meta: httpc.New(httpc.Options{Transport: o.Transport, MaxBytes: maxMetaBytes, Sleep: o.Sleep,
			TotalTimeout: 60 * time.Second, Logger: o.Logger}),
		feed: httpc.New(httpc.Options{Transport: o.Transport, MaxBytes: o.MaxGz, Sleep: o.Sleep,
			TotalTimeout: 20 * time.Minute, Logger: o.Logger}),
		log: o.Logger,
	}
}

func (f *Fetcher) url(name, ext string) string { return f.Base + "/nvdcve-2.0-" + name + ext }

// MetaResult is a fetched .meta.
type MetaResult struct {
	Meta        Meta
	ETag        string
	NotModified bool // 304 for If-None-Match etag
}

// Meta fetches nvdcve-2.0-<name>.meta; etag (may be "") is sent as
// If-None-Match and a 304 returns NotModified.
func (f *Fetcher) Meta(ctx context.Context, name, etag string) (MetaResult, error) {
	h := http.Header{}
	if etag != "" {
		h.Set("If-None-Match", etag)
	}
	resp, err := f.meta.Get(ctx, f.url(name, ".meta"), httpc.GetOptions{Header: h,
		Accept: func(s int) bool { return s == http.StatusOK || s == http.StatusNotModified }})
	if err != nil {
		return MetaResult{}, err
	}
	if resp.Status == http.StatusNotModified {
		return MetaResult{ETag: etag, NotModified: true}, nil
	}
	m, err := ParseMeta(resp.Body)
	if err != nil {
		return MetaResult{}, fmt.Errorf("%s: %w", f.url(name, ".meta"), err)
	}
	return MetaResult{Meta: m, ETag: resp.Header.Get("ETag")}, nil
}

// Feed downloads nvdcve-2.0-<name>.json.gz and verifies it against m: the
// compressed length equals gzSize, the gzip stream is complete, the
// unpacked length equals size (also the decompression cap) and its SHA-256
// equals sha256. Anything else is an error and nothing is returned.
func (f *Fetcher) Feed(ctx context.Context, name string, m Meta) ([]byte, error) {
	u := f.url(name, ".json.gz")
	resp, err := f.feed.Get(ctx, u, httpc.GetOptions{})
	if err != nil {
		return nil, err
	}
	if int64(len(resp.Body)) != m.GzSize {
		return nil, &ChecksumError{Msg: fmt.Sprintf("%s: %d bytes, .meta gzSize %d (truncated or changed)", u, len(resp.Body), m.GzSize)}
	}
	if err := Verify(bytes.NewReader(resp.Body), m); err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	return resp.Body, nil
}

// MetaAndFeed fetches the .meta and the verified feed. NVD regenerates the
// files every few hours; when the feed does not match the .meta read just
// before (regenerated in between), the pair is fetched once more.
func (f *Fetcher) MetaAndFeed(ctx context.Context, name string) (Meta, []byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		mr, err := f.Meta(ctx, name, "")
		if err != nil {
			return Meta{}, nil, err
		}
		body, err := f.Feed(ctx, name, mr.Meta)
		if err == nil {
			return mr.Meta, body, nil
		}
		var ce *ChecksumError
		if !errors.As(err, &ce) {
			return Meta{}, nil, err
		}
		lastErr = err
		f.log.Warn("nvd feed does not match its .meta, fetching both again", "feed", name, "err", err)
	}
	return Meta{}, nil, lastErr
}
