// Package cveimport is the one-off bulk import of the complete CVE history
// (the cvelistV5 "all CVEs at midnight" baseline) into nday, through the
// cvelist collector's own Normalize and the pipeline's own write functions,
// so imported rows are indistinguishable from what the collector would have
// produced for the same records (see Import for the exact rules).
//
// Upstream facts (verified with curl, 2026-11-13):
//   - every hourly release cve_<YYYY-MM-DD>_<HH>00Z carries the asset
//     <YYYY-MM-DD>_all_CVEs_at_midnight.zip.zip (~662 MB): an outer zip with
//     ONE deflated member cves.zip (~732 MB), itself a zip of
//     cves/<year>/<N>xxx/CVE-<year>-<N>.json (~425k records) plus
//     cves/delta.json and cves/deltaLog.json;
//   - https://github.com/CVEProject/cvelistV5/releases/latest is a plain
//     302 to …/releases/tag/<tag> (github.com, not the rate-limited REST API);
//   - release download URLs 302 to a CDN (Azure blob) that supports Range
//     requests and sends Content-Length and ETag, but no checksum.
package cveimport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nday.land/nday/internal/collector/cvelist"
)

// Upstream locations.
const (
	LatestURL = "https://github.com/CVEProject/cvelistV5/releases/latest"
)

// Baseline identifies one published full baseline.
type Baseline struct {
	Tag   string    // e.g. cve_2026-11-13_0400Z
	Asset string    // e.g. 2026-11-13_all_CVEs_at_midnight.zip.zip
	Date  time.Time // midnight UTC of the snapshot
	URL   string
	Size  int64  // Content-Length reported by the CDN (0 if unknown)
	ETag  string // CDN ETag (may be empty)
}

// AssetName is the baseline asset of a day.
func AssetName(day time.Time) string {
	return day.UTC().Format("2006-01-02") + "_all_CVEs_at_midnight.zip.zip"
}

// HourlyTag is the release tag of a day's hourly release.
func HourlyTag(day time.Time, hour int) string {
	return fmt.Sprintf("cve_%s_%02d00Z", day.UTC().Format("2006-01-02"), hour)
}

// AssetURL is the download URL of asset in release tag.
func AssetURL(tag, asset string) string {
	return cvelist.ReleaseBase + "/" + tag + "/" + asset
}

var (
	tagRe       = regexp.MustCompile(`/releases/tag/(cve_(\d{4}-\d{2}-\d{2})_(\d{2})00Z)$`)
	baseNameRe  = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight`)
	errNotFound = errors.New("not found")
)

// SnapshotDateFromName extracts the snapshot day from a baseline file name
// (…YYYY-MM-DD_all_CVEs_at_midnight…).
func SnapshotDateFromName(name string) (time.Time, bool) {
	m := baseNameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	d, err := time.Parse("2006-01-02", m[1])
	if err != nil {
		return time.Time{}, false
	}
	return d.UTC(), true
}

// LocateOptions for Locate.
type LocateOptions struct {
	Transport http.RoundTripper // nil: http.DefaultTransport
	Now       func() time.Time
	// MaxDays is how many days back the probe goes (default 3).
	MaxDays int
	Logger  *slog.Logger
}

// Locate finds the newest published baseline without the GitHub REST API:
//  1. GET /releases/latest without following the redirect; its Location
//     names the newest tag; HEAD that tag's baseline asset;
//  2. if that fails, probe hourly tags newest first (today from the current
//     hour down to 00, then previous days 23..00, MaxDays days) with HEAD
//     until one has the baseline asset.
//
// A HEAD follows the download redirect to the CDN; 200 with a
// Content-Length means the asset exists.
func Locate(ctx context.Context, o LocateOptions) (*Baseline, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxDays <= 0 {
		o.MaxDays = 3
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	client := &http.Client{Transport: o.Transport, Timeout: 60 * time.Second}
	if tag, day, err := latestTag(ctx, o.Transport); err == nil {
		b, err := probe(ctx, client, tag, day)
		if err == nil {
			return b, nil
		}
		o.Logger.Warn("latest release has no usable baseline asset; probing hourly tags", "tag", tag, "err", err)
	} else {
		o.Logger.Warn("could not read the latest release tag; probing hourly tags", "err", err)
	}
	now := o.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	tried := 0
	for d := 0; d < o.MaxDays; d++ {
		day := today.AddDate(0, 0, -d)
		top := 23
		if d == 0 {
			top = now.Hour()
		}
		for h := top; h >= 0; h-- {
			tried++
			b, err := probe(ctx, client, HourlyTag(day, h), day)
			if err == nil {
				return b, nil
			}
			if !errors.Is(err, errNotFound) {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("no baseline asset found in %d hourly releases over the last %d days", tried, o.MaxDays)
}

func latestTag(ctx context.Context, rt http.RoundTripper) (string, time.Time, error) {
	client := &http.Client{Transport: rt, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, LatestURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode/100 != 3 || loc == "" {
		return "", time.Time{}, fmt.Errorf("GET %s: status %d, no redirect", LatestURL, resp.StatusCode)
	}
	m := tagRe.FindStringSubmatch(strings.TrimRight(loc, "/"))
	if m == nil {
		return "", time.Time{}, fmt.Errorf("unexpected latest release location %q", loc)
	}
	day, err := time.Parse("2006-01-02", m[2])
	if err != nil {
		return "", time.Time{}, err
	}
	return m[1], day.UTC(), nil
}

// probe HEADs the baseline asset of tag (snapshot day).
func probe(ctx context.Context, client *http.Client, tag string, day time.Time) (*Baseline, error) {
	asset := AssetName(day)
	url := AssetURL(tag, asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", url, err)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("HEAD %s: %w", url, errNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HEAD %s: status %d", url, resp.StatusCode)
	}
	return &Baseline{Tag: tag, Asset: asset, Date: day, URL: url,
		Size: resp.ContentLength, ETag: resp.Header.Get("ETag")}, nil
}
