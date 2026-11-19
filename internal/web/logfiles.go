package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Log files (NDAY_LOG_DIR). Unset: everything goes to stderr as before.
// Set: two files per local calendar day inside the directory,
//
//	access-YYYY-MM-DD.log  one JSON object per request (both hosts), only here
//	error-YYYY-MM-DD.log   every WARN+ record of the serve process (also on
//	                       stderr), panics with stack, one record per 5xx
//
// The day is that of the process's local time zone (time.Local, i.e.
// /etc/localtime). A line always lands in the file named after the date its
// own "time" field shows: both come from the same instant of LogOptions.Now
// in LogOptions.Location. nday never deletes anything in the directory.
const EnvLogDir = "NDAY_LOG_DIR"

// logTimeLayout is the "time" format of both files (RFC 3339, ms, offset).
const logTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// LogOptions configure OpenLogFiles.
type LogOptions struct {
	Dir string // absolute, must exist (it is never created)
	// Now is the clock (default time.Now) and Location the zone of the file
	// dates and "time" fields (default time.Local). Tests inject both.
	Now      func() time.Time
	Location *time.Location
	// Stderr receives the sink's own problems (a failed rollover); default
	// slog.Default().
	Stderr *slog.Logger
}

// LogFiles are the access and error files of `nday serve`.
type LogFiles struct {
	Access *DailyFile
	Error  *DailyFile

	opts LogOptions
}

// OpenLogFiles checks the directory and opens today's two files
// (appending; a restart on the same day continues them).
func OpenLogFiles(o LogOptions) (*LogFiles, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	if o.Stderr == nil {
		o.Stderr = slog.Default()
	}
	if !filepath.IsAbs(o.Dir) {
		return nil, fmt.Errorf("%s must be an absolute path, got %q", EnvLogDir, o.Dir)
	}
	st, err := os.Stat(o.Dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s: directory %s does not exist (create it, e.g. nday:nday 0750)", EnvLogDir, o.Dir)
	case err != nil:
		return nil, fmt.Errorf("%s: %w", EnvLogDir, err)
	case !st.IsDir():
		return nil, fmt.Errorf("%s: %s is not a directory", EnvLogDir, o.Dir)
	}
	l := &LogFiles{opts: o}
	now := l.Now()
	if l.Access, err = openDaily(o.Dir, "access", now, o.Stderr); err != nil {
		return nil, fmt.Errorf("%s: %w", EnvLogDir, err)
	}
	if l.Error, err = openDaily(o.Dir, "error", now, o.Stderr); err != nil {
		_ = l.Access.close()
		return nil, fmt.Errorf("%s: %w", EnvLogDir, err)
	}
	return l, nil
}

// Now is the log clock, in the log time zone.
func (l *LogFiles) Now() time.Time { return l.opts.Now().In(l.opts.Location) }

// Close closes both files.
func (l *LogFiles) Close() error { return errors.Join(l.Access.close(), l.Error.close()) }

// DailyFile is an append-only file named <prefix>-YYYY-MM-DD.log that
// follows the date (in the timestamp's own zone) of the lines written to it.
type DailyFile struct {
	dir, prefix string
	stderr      *slog.Logger

	mu      sync.Mutex
	f       *os.File
	day     string
	lastErr time.Time // last reported rollover failure (rate limit)
	// open is os.OpenFile (tests replace it to make a rollover fail).
	open func(name string, flag int, perm os.FileMode) (*os.File, error)
}

func openDaily(dir, prefix string, now time.Time, stderr *slog.Logger) (*DailyFile, error) {
	d := &DailyFile{dir: dir, prefix: prefix, stderr: stderr, open: os.OpenFile}
	day := now.Format("2006-01-02")
	f, err := d.open(d.path(day), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	d.f, d.day = f, day
	return d, nil
}

func (d *DailyFile) path(day string) string {
	return filepath.Join(d.dir, d.prefix+"-"+day+".log")
}

// Name is the path of the file currently written.
func (d *DailyFile) Name() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Name()
}

// SetOpenFunc replaces os.OpenFile for later rollovers (tests).
func (d *DailyFile) SetOpenFunc(f func(name string, flag int, perm os.FileMode) (*os.File, error)) {
	d.mu.Lock()
	d.open = f
	d.mu.Unlock()
}

// WriteAt writes one complete line whose timestamp is t into the file of
// t's date (in t's location, which LogFiles.Now sets), switching files
// first if needed: open the new file, then close the old one. If the new file cannot be
// opened the line goes to the current file and the failure is reported on
// stderr at most once a minute.
func (d *DailyFile) WriteAt(t time.Time, p []byte) (int, error) {
	day := t.Format("2006-01-02")
	d.mu.Lock()
	defer d.mu.Unlock()
	if day != d.day {
		nf, err := d.open(d.path(day), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			if now := time.Now(); now.Sub(d.lastErr) >= time.Minute {
				d.lastErr = now
				d.stderr.Error("log rollover failed; still writing the previous file",
					"file", d.path(day), "current", d.f.Name(), "err", err)
			}
		} else {
			old := d.f
			d.f, d.day = nf, day
			_ = old.Close()
		}
	}
	n, err := d.f.Write(p)
	if err != nil { // e.g. disk full: say so on stderr, at most once a minute
		if now := time.Now(); now.Sub(d.lastErr) >= time.Minute {
			d.lastErr = now
			d.stderr.Error("log write failed; lines are being lost", "file", d.f.Name(), "err", err)
		}
	}
	return n, err
}

func (d *DailyFile) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Close()
}

// AccessLine is one access-file record (nginx-style). Keys are always
// present and in this order; values are JSON-escaped, so control characters
// from clients cannot forge lines. See docs/logging.md.
type AccessLine struct {
	Time              string  `json:"time"`
	ClientIP          string  `json:"client_ip"`
	RemoteAddr        string  `json:"remote_addr"`
	Domain            string  `json:"domain"`
	Host              string  `json:"host"`
	Method            string  `json:"method"`
	URI               string  `json:"uri"`
	Status            int     `json:"status"`
	Referer           string  `json:"referer"`
	HTTPXForwardedFor string  `json:"http_x_forwarded_for"`
	ServerPort        int     `json:"server_port"`
	RequestLength     int64   `json:"request_length"`
	RequestTime       float64 `json:"request_time"`
	SSLProtocol       string  `json:"ssl_protocol"`
	SSLCipher         string  `json:"ssl_cipher"`
	BytesSent         int64   `json:"bytes_sent"`
	Proto             string  `json:"proto"`
	UserAgent         string  `json:"user_agent"`
	CFRay             string  `json:"cf_ray"`
	Country           string  `json:"country"`
}

// countingBody counts the request body bytes the handler actually read.
type countingBody struct {
	io.ReadCloser
	n int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// AccessLogFile is AccessLog for log files: one AccessLine per request to
// files.Access (nothing goes to log), and for every status >= 500 an ERROR
// record on log (which serve tees to stderr and the error file). origins
// are the configured site and API origins (for "domain" and for redacting
// same-site referers). Never logged: cookies, Authorization, bodies,
// query values RedactQuery hides.
func AccessLogFile(files *LogFiles, log *slog.Logger, origins ...string) Middleware {
	type site struct{ scheme, host string }
	var ours []site
	for _, o := range origins {
		if sch, h, ok := splitOrigin(o); ok && o != "" {
			ours = append(ours, site{sch, h})
		}
	}
	match := func(host string) string { // canonical configured host, or ""
		for _, s := range ours {
			if canonicalHost(s.scheme, strings.ToLower(host)) == s.host {
				return s.host
			}
		}
		return ""
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			var body *countingBody
			if r.Body != nil && r.Body != http.NoBody {
				body = &countingBody{ReadCloser: r.Body}
				r.Body = body
			}
			reqLen := requestHeadLength(r) // before handlers can touch the headers
			defer func() {
				status := sw.status
				if status == 0 {
					status = http.StatusOK
				}
				elapsed := time.Since(start)
				t := files.Now()
				peer := remoteIP(r.RemoteAddr)
				cip := clientIP(r) // CF-Connecting-IP; a direct connection has none
				if cip == "" {
					cip = peer
				}
				ln := AccessLine{Time: t.Format(logTimeLayout), ClientIP: cip, RemoteAddr: peer,
					Domain: match(r.Host), Host: trunc(strings.ToLower(r.Host), 255), Method: trunc(r.Method, 20),
					URI: trunc(redactedURI(r), 2000), Status: status, Referer: trunc(redactReferer(r.Referer(), match), 500),
					HTTPXForwardedFor: trunc(strings.Join(r.Header.Values("X-Forwarded-For"), ", "), 500),
					ServerPort:        localPort(r), RequestLength: reqLen,
					RequestTime: math.Round(elapsed.Seconds()*1000) / 1000,
					BytesSent:   sw.bytes, Proto: trunc(r.Proto, 20), UserAgent: trunc(r.UserAgent(), 300),
					CFRay: trunc(r.Header.Get("CF-Ray"), 64), Country: trunc(r.Header.Get("CF-IPCountry"), 8)}
				if body != nil && body.n > 0 {
					ln.RequestLength += body.n
				} else if r.ContentLength > 0 {
					ln.RequestLength += r.ContentLength
				}
				if r.TLS != nil {
					ln.SSLProtocol = tlsVersionName(r.TLS.Version)
					ln.SSLCipher = tls.CipherSuiteName(r.TLS.CipherSuite)
				}
				// EncodeJSON: control characters, quotes and backslashes are
				// escaped; HTML characters (& < >) are kept readable.
				if b, err := EncodeJSON(ln); err == nil {
					_, _ = files.Access.WriteAt(t, b)
				}
				if status >= 500 {
					log.Error("http 5xx", "method", ln.Method, "host", ln.Host, "path", trunc(r.URL.Path, 300),
						"status", status, "dur_ms", float64(elapsed.Microseconds())/1000, "cf_ray", ln.CFRay)
				}
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// requestHeadLength reconstructs the size of the request line and header
// block as sent: "METHOD URI PROTO\r\n", one "Name: value\r\n" per header
// value (Host included; Go moves it out of r.Header), and the blank line.
// Go does not expose wire bytes, so this is a reconstruction: exact for
// ordinary HTTP/1.1 requests, approximate for HTTP/2 (HPACK-compressed
// headers, pseudo-headers). The body bytes are added by the caller.
func requestHeadLength(r *http.Request) int64 {
	n := len(r.Method) + 1 + len(r.RequestURI) + 1 + len(r.Proto) + 2
	if r.Host != "" {
		n += len("Host: ") + len(r.Host) + 2
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			n += len(k) + 2 + len(v) + 2
		}
	}
	return int64(n + 2)
}

// redactedURI is nginx's $request_uri with RedactQuery applied.
func redactedURI(r *http.Request) string {
	u := r.URL.EscapedPath()
	if q := r.URL.RawQuery; q != "" {
		u += "?" + RedactQuery(r.URL.Path, q)
	}
	return u
}

// redactReferer logs a referer as sent, except that its query goes
// through RedactQuery: on one of our own hosts the whole URL is rebuilt
// (and loses any fragment); on any other host, or when the URL does not
// parse, the part between the first "?" and the first "#" after it is
// redacted in place (so a credential in it never reaches the log).
func redactReferer(v string, ours func(string) string) string {
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err == nil && u.Host != "" && ours(u.Host) != "" {
		out := u.Scheme + "://" + u.Host + u.EscapedPath()
		if u.RawQuery != "" {
			out += "?" + RedactQuery(u.Path, u.RawQuery)
		}
		return out
	}
	base, rest, ok := strings.Cut(v, "?")
	if !ok {
		return v
	}
	q, frag, hasFrag := strings.Cut(rest, "#")
	path := ""
	if err == nil {
		path = u.Path
	}
	out := base + "?" + RedactQuery(path, q)
	if hasFrag {
		out += "#" + frag
	}
	return out
}

func remoteIP(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func localPort(r *http.Request) int {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ta, ok := a.(*net.TCPAddr); ok {
			return ta.Port
		}
		if _, p, err := net.SplitHostPort(a.String()); err == nil {
			n, _ := strconv.Atoi(p)
			return n
		}
	}
	return 0
}

// tlsVersionName is nginx's $ssl_protocol spelling.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return tls.VersionName(v)
}

// ErrorHandler is the slog handler of the error file: JSON, WARN and above,
// the record's time replaced by the log clock (local zone, ms) so the line
// and the file name agree.
func (l *LogFiles) ErrorHandler() slog.Handler {
	return &errorFileHandler{files: l}
}

type errorFileHandler struct {
	files *LogFiles
	ops   []func(slog.Handler) slog.Handler // WithAttrs / WithGroup, replayed per record
}

func (h *errorFileHandler) Enabled(_ context.Context, lv slog.Level) bool {
	return lv >= slog.LevelWarn
}

func (h *errorFileHandler) Handle(ctx context.Context, r slog.Record) error {
	t := h.files.Now()
	r.Time = t
	var buf bytes.Buffer
	var jh slog.Handler = slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				return slog.String(slog.TimeKey, a.Value.Time().Format(logTimeLayout))
			}
			return a
		}})
	for _, op := range h.ops {
		jh = op(jh)
	}
	if err := jh.Handle(ctx, r); err != nil {
		return err
	}
	_, err := h.files.Error.WriteAt(t, buf.Bytes())
	return err
}

func (h *errorFileHandler) with(op func(slog.Handler) slog.Handler) *errorFileHandler {
	ops := append(append([]func(slog.Handler) slog.Handler(nil), h.ops...), op)
	return &errorFileHandler{files: h.files, ops: ops}
}

func (h *errorFileHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return h.with(func(x slog.Handler) slog.Handler { return x.WithAttrs(as) })
}

func (h *errorFileHandler) WithGroup(name string) slog.Handler {
	return h.with(func(x slog.Handler) slog.Handler { return x.WithGroup(name) })
}

// TeeHandler sends every record to each handler that is enabled for its
// level (serve: stderr at INFO+ as before, plus the error file at WARN+).
func TeeHandler(hs ...slog.Handler) slog.Handler { return teeHandler(hs) }

type teeHandler []slog.Handler

func (t teeHandler) Enabled(ctx context.Context, lv slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, lv) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range t {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (t teeHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}
