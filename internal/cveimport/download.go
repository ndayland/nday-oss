package cveimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/httpc"
)

const userAgent = httpc.UserAgent

// DefaultMaxDownloadBytes caps the baseline download (today ~662 MB).
const DefaultMaxDownloadBytes int64 = 4 << 30

// DownloadOptions for Download.
type DownloadOptions struct {
	Transport http.RoundTripper
	// MaxBytes caps the file size (default DefaultMaxDownloadBytes).
	MaxBytes int64
	// Attempts per download (default 8); each retry resumes with Range.
	Attempts int
	// Backoff before retry n is Backoff * 2^(n-1), at most 60 s (default 2 s).
	Backoff time.Duration
	// IdleTimeout aborts an attempt when no byte arrives for this long (default 120 s).
	IdleTimeout time.Duration
	Sleep       func(ctx context.Context, d time.Duration) error
	Logger      *slog.Logger
}

func (o *DownloadOptions) defaults() {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxDownloadBytes
	}
	if o.Attempts <= 0 {
		o.Attempts = 8
	}
	if o.Backoff <= 0 {
		o.Backoff = 2 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 120 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// partMeta is stored next to the .part file so a resume only continues the
// same upstream object.
type partMeta struct {
	URL  string `json:"url"`
	Size int64  `json:"size"`
	ETag string `json:"etag"`
}

// Downloaded describes a completed download.
type Downloaded struct {
	Path   string
	Size   int64
	SHA256 string
	// Resumed is true if bytes of an earlier interrupted download were reused.
	Resumed bool
}

// Download fetches b.URL into dir/b.Asset:
//   - the data goes to <asset>.part (+ <asset>.part.json with url/size/etag);
//     an interrupted download (crash, signal, network) is resumed with a
//     Range request on the next call or retry, provided the part file
//     belongs to the same url and the CDN still reports the same size/ETag;
//   - transport errors, 429/5xx and stalled transfers (IdleTimeout) are
//     retried with exponential backoff (Attempts);
//   - the size is capped (MaxBytes, checked against Content-Length before
//     and against the bytes written while downloading) and the final size
//     must equal the advertised total; the SHA-256 is computed for the log
//     (upstream publishes no checksum; the zip CRC-32s are verified when
//     the archive is read);
//   - on success the part file is renamed to dir/<asset>; an existing
//     complete file of the expected size is reused without downloading.
func Download(ctx context.Context, b *Baseline, dir string, o DownloadOptions) (*Downloaded, error) {
	o.defaults()
	if b.Size > o.MaxBytes {
		return nil, fmt.Errorf("baseline %s is %d bytes > cap %d", b.Asset, b.Size, o.MaxBytes)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	final := filepath.Join(dir, b.Asset)
	part := final + ".part"
	metaPath := part + ".json"
	if fi, err := os.Stat(final); err == nil && b.Size > 0 && fi.Size() == b.Size {
		o.Logger.Info("baseline already downloaded", "path", final, "bytes", fi.Size())
		sum, err := fileSHA256(final)
		if err != nil {
			return nil, err
		}
		return &Downloaded{Path: final, Size: fi.Size(), SHA256: sum}, nil
	}
	// Discard a part file that belongs to another object.
	if !metaMatches(metaPath, b) {
		_ = os.Remove(part)
	}
	mb, _ := json.Marshal(partMeta{URL: b.URL, Size: b.Size, ETag: b.ETag})
	if err := os.WriteFile(metaPath, mb, 0o644); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: o.Transport}
	resumed := false
	var lastErr error
	for attempt := 1; attempt <= o.Attempts; attempt++ {
		if attempt > 1 {
			d := o.Backoff << (attempt - 2)
			if d > 60*time.Second {
				d = 60 * time.Second
			}
			o.Logger.Warn("baseline download failed, retrying", "attempt", attempt, "in", d, "err", lastErr)
			if err := o.Sleep(ctx, d); err != nil {
				return nil, err
			}
		}
		done, res, err := downloadAttempt(ctx, client, b, part, o)
		if res {
			resumed = true
		}
		if err == nil && done {
			break
		}
		if err != nil {
			var pe *permanentError
			if errors.As(err, &pe) || ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
		}
		if attempt == o.Attempts {
			return nil, fmt.Errorf("baseline download failed after %d attempts: %w", o.Attempts, lastErr)
		}
	}
	fi, err := os.Stat(part)
	if err != nil {
		return nil, err
	}
	if b.Size > 0 && fi.Size() != b.Size {
		return nil, fmt.Errorf("downloaded %d bytes, expected %d", fi.Size(), b.Size)
	}
	sum, err := fileSHA256(part)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(part, final); err != nil {
		return nil, err
	}
	_ = os.Remove(metaPath)
	return &Downloaded{Path: final, Size: fi.Size(), SHA256: sum, Resumed: resumed}, nil
}

type permanentError struct{ msg string }

func (e *permanentError) Error() string { return e.msg }

func metaMatches(path string, b *Baseline) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var m partMeta
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	return m.URL == b.URL && m.Size == b.Size && m.ETag == b.ETag
}

// downloadAttempt appends to part from its current size. done reports the
// file is complete; resumed reports a Range request was honoured.
func downloadAttempt(ctx context.Context, client *http.Client, b *Baseline, part string, o DownloadOptions) (done, resumed bool, err error) {
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, false, &permanentError{err.Error()}
	}
	defer f.Close()
	have, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return false, false, &permanentError{err.Error()}
	}
	if b.Size > 0 && have == b.Size {
		return true, false, nil
	}
	if b.Size > 0 && have > b.Size {
		if err := f.Truncate(0); err != nil {
			return false, false, &permanentError{err.Error()}
		}
		have = 0
	}
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, b.URL, nil)
	if err != nil {
		return false, false, &permanentError{err.Error()}
	}
	req.Header.Set("User-Agent", userAgent)
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
		if b.ETag != "" {
			req.Header.Set("If-Range", b.ETag)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
		start, total, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !ok || start != have || (b.Size > 0 && total != b.Size) {
			if err := f.Truncate(0); err != nil {
				return false, false, &permanentError{err.Error()}
			}
			return false, false, fmt.Errorf("unexpected Content-Range %q for resume at %d; restarting", resp.Header.Get("Content-Range"), have)
		}
		resumed = true
		o.Logger.Info("resuming baseline download", "from", have, "total", total)
	case resp.StatusCode == http.StatusOK:
		if have > 0 { // server ignored Range: start over
			if err := f.Truncate(0); err != nil {
				return false, false, &permanentError{err.Error()}
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return false, false, &permanentError{err.Error()}
			}
			have = 0
		}
		if resp.ContentLength > o.MaxBytes {
			return false, false, &permanentError{fmt.Sprintf("Content-Length %d > cap %d", resp.ContentLength, o.MaxBytes)}
		}
		if b.Size > 0 && resp.ContentLength >= 0 && resp.ContentLength != b.Size {
			return false, false, fmt.Errorf("Content-Length %d != advertised size %d", resp.ContentLength, b.Size)
		}
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		if err := f.Truncate(0); err != nil {
			return false, false, &permanentError{err.Error()}
		}
		return false, false, fmt.Errorf("range not satisfiable at %d; restarting", have)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return false, false, fmt.Errorf("GET %s: status %d", b.URL, resp.StatusCode)
	default:
		return false, false, &permanentError{fmt.Sprintf("GET %s: status %d", b.URL, resp.StatusCode)}
	}
	// Copy with an idle watchdog and the size cap.
	timer := time.AfterFunc(o.IdleTimeout, cancel)
	defer timer.Stop()
	buf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			timer.Reset(o.IdleTimeout)
			if have+int64(n) > o.MaxBytes {
				return false, resumed, &permanentError{fmt.Sprintf("download exceeds cap %d bytes", o.MaxBytes)}
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return false, resumed, &permanentError{err.Error()}
			}
			have += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if ctx.Err() == nil && actx.Err() != nil {
				rerr = fmt.Errorf("no data for %s: %w", o.IdleTimeout, rerr)
			}
			return false, resumed, rerr
		}
	}
	if err := f.Sync(); err != nil {
		return false, resumed, &permanentError{err.Error()}
	}
	if b.Size > 0 && have != b.Size {
		return false, resumed, fmt.Errorf("transfer ended at %d of %d bytes", have, b.Size)
	}
	return true, resumed, nil
}

// parseContentRange parses "bytes start-end/total".
func parseContentRange(s string) (start, total int64, ok bool) {
	s, found := strings.CutPrefix(s, "bytes ")
	if !found {
		return 0, 0, false
	}
	rng, tot, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, false
	}
	a, _, found := strings.Cut(rng, "-")
	if !found {
		return 0, 0, false
	}
	start, err1 := strconv.ParseInt(a, 10, 64)
	total, err2 := strconv.ParseInt(tot, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return start, total, true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
