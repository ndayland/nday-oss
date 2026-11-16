package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/stats"
)

// Sample statistics for the back office (-stats-sample DIR): a few days of
// plausible access-log lines (docs/logging.md format) and an error log for
// today are written into DIR, then rolled up into the (local) database with
// internal/stats, exactly as `nday stats-rollup --dir DIR --all` would.
// Development only; the generator is deterministic (fixed seed).

type sampleLine struct {
	Time        string  `json:"time"`
	ClientIP    string  `json:"client_ip"`
	RemoteAddr  string  `json:"remote_addr"`
	Domain      string  `json:"domain"`
	Host        string  `json:"host"`
	Method      string  `json:"method"`
	URI         string  `json:"uri"`
	Status      int     `json:"status"`
	Referer     string  `json:"referer"`
	RequestTime float64 `json:"request_time"`
	BytesSent   int64   `json:"bytes_sent"`
	Proto       string  `json:"proto"`
	UserAgent   string  `json:"user_agent"`
	CFRay       string  `json:"cf_ray"`
	Country     string  `json:"country"`
}

var (
	sampleBrowsers = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	}
	sampleBots = []string{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "curl/8.7.1",
		"python-requests/2.32.3", "Mozilla/5.0 (compatible; bingbot/2.0)", "GPTBot/1.2"}
	samplePages = []string{"/", "/hot", "/vuln/CVE-2024-3094", "/vuln/CVE-2026-0001", "/vuln/CVE-2025-1974", "/vuln?q=openssl",
		"/vuln?q=xz", "/zh-hans/", "/zh-hans/vuln/CVE-2024-3094", "/ja/vuln/CVE-2025-1974", "/src", "/stats", "/about",
		"/wp-login.php", "/.env"}
	sampleAPI       = []string{"/v1/hot", "/v1/vuln/CVE-2024-3094", "/v1/search?q=openssl", "/v1/sources", "/v1/stats"}
	sampleReferrers = []string{"", "", "", "https://news.ycombinator.com/item?id=1", "https://www.google.com/", "https://t.co/x"}
	// sampleCountries is drawn from uniformly, so repeats weight it into a
	// heavy tail for the world map: outlines (US, CN, ...), marker-only
	// territories (SG, HK, MO) and codes the map cannot place (T1 = Tor,
	// XX = unknown).
	sampleCountries = []string{"US", "US", "US", "US", "US", "US", "US", "US", "US", "US", "US", "US",
		"CN", "CN", "CN", "CN", "CN", "CN", "CN", "CN", "SG", "SG", "SG", "SG", "JP", "JP", "JP",
		"DE", "DE", "DE", "FR", "FR", "KR", "KR", "GB", "GB", "IN", "BR", "NO", "HK", "HK", "MO", "AU", "T1", "XX"}
)

// writeSampleLogs writes access-YYYY-MM-DD.log for the last days days
// (local dates; one day in the middle is skipped, so the dashboard shows a
// gap) and error-<today>.log.
func writeSampleLogs(dir string, now time.Time, days int) error {
	if !filepath.IsAbs(dir) {
		return errors.New("-stats-sample: the directory must be an absolute path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rng := rand.New(rand.NewPCG(1, 2))
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for d := days - 1; d >= 0; d-- {
		if d == days/2 {
			continue // a gap
		}
		day := today.AddDate(0, 0, -d)
		end := day.Add(24 * time.Hour)
		if d == 0 {
			end = now // today is partial
		}
		f, err := os.Create(filepath.Join(dir, "access-"+day.Format("2006-01-02")+".log"))
		if err != nil {
			return err
		}
		n := 400 + rng.IntN(600) + (days-d)*30
		step := end.Sub(day) / time.Duration(n)
		enc := json.NewEncoder(f)
		for i := 0; i < n; i++ {
			at := day.Add(time.Duration(i) * step)
			l := sampleLine{Time: at.Format("2006-01-02T15:04:05.000Z07:00"), RemoteAddr: "172.68.0.1", Method: "GET",
				Domain: "www.nday.land", Proto: "HTTP/2.0", Status: 200, RequestTime: 0.002 + rng.Float64()*0.05,
				BytesSent: 2000 + rng.Int64N(30000), CFRay: fmt.Sprintf("8e%06x-SIN", rng.IntN(1<<24)),
				Country: sampleCountries[rng.IntN(len(sampleCountries))]}
			l.ClientIP = fmt.Sprintf("198.51.100.%d", rng.IntN(60))
			l.UserAgent = sampleBrowsers[rng.IntN(len(sampleBrowsers))]
			switch r := rng.IntN(100); {
			case r < 20: // bots and scripts
				l.UserAgent = sampleBots[rng.IntN(len(sampleBots))]
				l.URI = samplePages[rng.IntN(len(samplePages))]
			case r < 35: // the API host
				l.Domain = "api.nday.land"
				l.URI = sampleAPI[rng.IntN(len(sampleAPI))]
			default:
				l.URI = samplePages[rng.IntN(len(samplePages))]
				l.Referer = sampleReferrers[rng.IntN(len(sampleReferrers))]
			}
			l.Host = l.Domain
			switch {
			case strings.HasSuffix(l.URI, ".php") || strings.HasSuffix(l.URI, ".env"):
				l.Status = 404
			case rng.IntN(200) == 0:
				l.Status = 500
			case rng.IntN(40) == 0:
				l.Status = 304
			}
			if err := enc.Encode(l); err != nil {
				f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	var b strings.Builder
	for i, m := range []string{"auth: rate limited", "http 5xx", "discuss: rate limited", "page timed out"} {
		level := "WARN"
		if m == "http 5xx" {
			level = "ERROR"
		}
		at := now.Add(-time.Duration(4-i) * time.Hour)
		b.WriteString(fmt.Sprintf(`{"time":%q,"level":%q,"msg":%q,"path":"/vuln/CVE-2024-3094","cf_ray":"8e0000%02d-SIN"}`+"\n",
			at.Format("2006-01-02T15:04:05.000Z07:00"), level, m, i))
	}
	return os.WriteFile(filepath.Join(dir, "error-"+today.Format("2006-01-02")+".log"), []byte(b.String()), 0o600)
}

// sampleStats writes the sample logs and rolls them up into dbURL (already
// checked to be a local database).
func sampleStats(ctx context.Context, dbURL, dir string, log *slog.Logger) error {
	if err := writeSampleLogs(dir, time.Now(), 10); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := stats.Rollup(ctx, conn, stats.Options{Dir: dir, All: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return fmt.Errorf("stats roll-up: %w", err)
	}
	log.Info("authdev: sample statistics rolled up", "dir", dir, "days", len(res.Days))
	return nil
}
