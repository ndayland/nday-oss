// Package cvelist is the CVE List (CVE JSON 5, GitHub CVEProject/cvelistV5)
// collector, a port of src/nday/collectors/cvelist.py (the specification;
// read its module docstring for the upstream facts).
//
// Strategy (identical to Python):
//   - First run (no cursor.last_fetch_time): the last BootstrapDays full UTC
//     days come from the daily end-of-day delta zips (one download per day,
//     oldest first, stopping at the first day whose release is 404); that day
//     onward comes from deltaLog.json via per-record files. The cursor points
//     at the newest deltaLog fetchTime.
//   - Later runs: change sets with fetchTime > cursor; their ids (deduplicated,
//     oldest change set first) are fetched as individual files, at most
//     MaxFiles per run. Ids over the cap and ids whose fetch failed after
//     retries go to cursor.pending and are fetched first next run.
//   - On-demand backfill (incremental runs only): state.Wanted ids are queued
//     after pending + change-set ids, in the room left under MaxFiles; never
//     persisted as pending; flagged RawRecord.IsBackfill. A wanted id whose
//     file is 404 is recorded in cursor.backfill_missing and not requested
//     again for BackfillRetryDays.
//   - Falling behind (oldest deltaLog entry newer than the cursor) is logged
//     and appended to cursor.gaps.
//
// Normalization: one disclosed event per CVE; RESERVED -> nothing; REJECTED ->
// vuln dates only + rejection facts; CVSS / CISA-ADP SSVC / KEV marker in
// detail; GHSA alias from containers.cna.source.advisory.
package cvelist

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// Name is the source name (raw_record.source, event.source, collector_state.source).
const Name = "cvelist"

// URLs, identical to Python.
const (
	RawBase     = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
	DeltaLogURL = RawBase + "/deltaLog.json"
	ReleaseBase = "https://github.com/CVEProject/cvelistV5/releases/download"
	CVEOrgURL   = "https://www.cve.org/CVERecord?id="
)

// Constants, identical to Python.
const (
	DefaultBootstrapDays     = 7
	MaxBootstrapDays         = 30
	DefaultMaxFiles          = 1000
	Concurrency              = 4
	MaxAttempts              = 4 // 1 try + 3 retries
	BackoffBase              = time.Second
	MaxRetryAfter            = 60 * time.Second
	MaxZipBytes              = 100 * 1024 * 1024
	MaxMemberBytes           = 20 * 1024 * 1024
	MaxGapsKept              = 50
	DefaultBackfillRetryDays = 7
	MaxBackfillMissing       = 5000
	// bodyCap is the httpc size cap. Python has none (deltaLog.json is ~41 MB
	// today, zips are checked against MaxZipBytes after download); Go needs
	// one, so it is generous.
	bodyCap = 1 << 30
)

// Environment variables, identical to Python.
const (
	EnvBootstrapDays     = "NDAY_CVELIST_BOOTSTRAP_DAYS"
	EnvMaxFiles          = "NDAY_CVELIST_MAX_FILES"
	EnvBackfillRetryDays = "NDAY_CVELIST_BACKFILL_RETRY_DAYS"
)

// zipMemberRe is ZIP_MEMBER_RE used with search: Python's `$` also matches
// before a trailing newline, and `\d` is any Unicode decimal digit.
var zipMemberRe = regexp.MustCompile(`(?:^|/)(CVE-\p{Nd}{4}-\p{Nd}{4,})\.json\n?\z`)

// Options configures New. nil settings are read from Env (like Python reads
// os.environ when the keyword argument is None).
type Options struct {
	Transport         http.RoundTripper
	Env               collector.Env
	BootstrapDays     *int
	MaxFiles          *int
	BackfillRetryDays *int
	// Clock is the collector clock (Python clock=); default time.Now.
	Clock func() time.Time
	// Sleep waits between retries (Python sleep=); default context-aware sleep.
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
	// Concurrency of record downloads; default Concurrency (4). Tests and the
	// replay harness use 1 to get a deterministic request order.
	Concurrency int
	// MaxBackfillMissing overrides the module constant (tests monkeypatch it
	// in Python); 0 = MaxBackfillMissing.
	MaxBackfillMissing int
}

// Collector implements collector.Collector and collector.WantsMissingCVEs.
type Collector struct {
	http          *httpc.Client
	log           *slog.Logger
	clock         func() time.Time
	sleep         func(ctx context.Context, d time.Duration) error
	concurrency   int
	maxMissing    int
	BootstrapDays int
	MaxFiles      int
	// retryUS is backfill_retry in microseconds (saturated, see New).
	retryUS int64
	// RequestsMade counts HTTP requests incl. retries over the collector's
	// lifetime (Python requests_made).
	requestsMade atomic.Int64
}

// envInt is env_int.
func envInt(env collector.Env, name string, def int64) (*big.Int, error) {
	var raw string
	var ok bool
	if env != nil {
		raw, ok = env(name)
	}
	if !ok || pystr.Strip(raw) == "" {
		return big.NewInt(def), nil
	}
	n, ok := parsePyInt(raw)
	if !ok {
		return nil, fmt.Errorf("%s must be an integer, got %s", name, pyjson.StrRepr(raw))
	}
	return n, nil
}

func setting(v *int, env collector.Env, name string, def int64) (*big.Int, error) {
	if v != nil {
		return big.NewInt(int64(*v)), nil
	}
	return envInt(env, name, def)
}

// New builds the collector, validating settings exactly like Python's
// constructor (same order, same messages; a ValueError there is an error here).
func New(o Options) (*Collector, error) {
	days, err := setting(o.BootstrapDays, o.Env, EnvBootstrapDays, DefaultBootstrapDays)
	if err != nil {
		return nil, err
	}
	if days.Sign() < 0 || days.Cmp(big.NewInt(MaxBootstrapDays)) > 0 {
		return nil, fmt.Errorf("bootstrap_days must be 0..%d, got %s", MaxBootstrapDays, days)
	}
	capN, err := setting(o.MaxFiles, o.Env, EnvMaxFiles, DefaultMaxFiles)
	if err != nil {
		return nil, err
	}
	if capN.Cmp(big.NewInt(1)) < 0 {
		return nil, fmt.Errorf("max_files must be >= 1, got %s", capN)
	}
	retry, err := setting(o.BackfillRetryDays, o.Env, EnvBackfillRetryDays, DefaultBackfillRetryDays)
	if err != nil {
		return nil, err
	}
	if retry.Sign() < 0 {
		return nil, fmt.Errorf("backfill_retry_days must be >= 0, got %s", retry)
	}
	// timedelta(days=retry) raises OverflowError above 999999999 days.
	if retry.Cmp(big.NewInt(999_999_999)) > 0 {
		return nil, fmt.Errorf("days=%s; must have magnitude <= 999999999", retry)
	}
	// Any difference of two datetimes is < 3.2e17 us, so saturating the
	// window at MaxInt64 us keeps every comparison identical to Python.
	retryUS := int64(1<<63 - 1)
	if retry.Cmp(big.NewInt(100_000_000)) < 0 {
		retryUS = retry.Int64() * 86_400_000_000
	}
	c := &Collector{
		log:           o.Logger,
		clock:         o.Clock,
		sleep:         o.Sleep,
		concurrency:   o.Concurrency,
		maxMissing:    o.MaxBackfillMissing,
		BootstrapDays: int(days.Int64()),
		MaxFiles:      clampInt(capN),
		retryUS:       retryUS,
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.sleep == nil {
		c.sleep = func(ctx context.Context, d time.Duration) error {
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
	if c.concurrency <= 0 {
		c.concurrency = Concurrency
	}
	if c.maxMissing <= 0 {
		c.maxMissing = MaxBackfillMissing
	}
	// httpx.Client(timeout=Timeout(120, connect=15), follow_redirects=True).
	// Retries are done here (get), like Python's _get, so MaxAttempts is 1.
	c.http = httpc.New(httpc.Options{
		Transport:   o.Transport,
		MaxAttempts: 1,
		ConnTimeout: 15 * time.Second,
		ReadTimeout: 120 * time.Second,
		MaxBytes:    bodyCap,
		Logger:      c.log,
	})
	return c, nil
}

// Factory is the registry entry: settings from the environment.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport, Env: d.LookupEnv})
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// WantedLimit implements collector.WantsMissingCVEs (Python: cap + MAX_BACKFILL_MISSING).
func (c *Collector) WantedLimit() int { return c.MaxFiles + c.maxMissing }

// RequestsMade is the number of HTTP requests incl. retries so far.
func (c *Collector) RequestsMade() int64 { return c.requestsMade.Load() }

// RecordURL is record_url: cves/<year>/<N // 1000>xxx/<id>.json.
func RecordURL(cveID string) string {
	parts := strings.Split(cveID, "-")
	var digits strings.Builder
	for _, r := range parts[2] { // int(num) accepts any Unicode decimal digit
		d, _ := digitValue(r)
		digits.WriteByte(byte('0' + d))
	}
	n, _ := new(big.Int).SetString(digits.String(), 10)
	n.Quo(n, big.NewInt(1000))
	return fmt.Sprintf("%s/%s/%sxxx/%s.json", RawBase, parts[1], n, cveID)
}

// EODZipURL is eod_zip_url.
func EODZipURL(day time.Time) string {
	d := day.Format("2006-01-02")
	return fmt.Sprintf("%s/cve_%s_at_end_of_day/%s_delta_CVEs_at_end_of_day.zip", ReleaseBase, d, d)
}

// ------------------------------------------------------------------ HTTP

// valueError marks failures Python raises as ValueError (caught per record).
type valueError struct{ msg string }

func (e *valueError) Error() string { return e.msg }

// pyIsDigit is str.isdigit() on a latin-1 decoded header value (httpx):
// ASCII digits plus superscripts two, three and one.
func pyIsDigit(s string) (digits, ascii bool) {
	if s == "" {
		return false, false
	}
	ascii = true
	for i := 0; i < len(s); i++ {
		switch b := s[i]; {
		case b >= '0' && b <= '9':
		case b == 0xb2 || b == 0xb3 || b == 0xb9:
			ascii = false
		default:
			return false, false
		}
	}
	return true, ascii
}

// get is Python's _get: bounded retries with exponential backoff on
// 429/5xx/transport errors, Retry-After honoured up to MaxRetryAfter.
// 404 -> (nil, nil) if allow404; other non-2xx -> *httpc.StatusError.
func (c *Collector) get(ctx context.Context, url string, allow404 bool) (*httpc.Response, error) {
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		delay := BackoffBase << (attempt - 1)
		c.requestsMade.Add(1)
		resp, err := c.http.Get(ctx, url, httpc.GetOptions{Accept: func(int) bool { return true }})
		if err != nil {
			var tl *httpc.TooLargeError
			if ctx.Err() != nil || errors.As(err, &tl) || attempt == MaxAttempts {
				return nil, err
			}
			c.log.Warn(fmt.Sprintf("GET %s failed (%s), retry %d in %.0fs", url, err, attempt, delay.Seconds()))
			if err := c.sleep(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		if resp.Status == http.StatusNotFound && allow404 {
			return nil, nil
		}
		if resp.Status == http.StatusTooManyRequests || resp.Status >= 500 {
			if attempt == MaxAttempts {
				return nil, &httpc.StatusError{Status: resp.Status, URL: url}
			}
			ra := resp.Header.Get("Retry-After")
			if isDigit, ascii := pyIsDigit(ra); isDigit {
				if !ascii { // float('²') raises ValueError
					return nil, &valueError{fmt.Sprintf("could not convert string to float: %s", pyjson.StrRepr(ra))}
				}
				f, _ := strconv.ParseFloat(ra, 64)
				delay = MaxRetryAfter
				if f < MaxRetryAfter.Seconds() {
					delay = time.Duration(f * float64(time.Second))
				}
			}
			c.log.Warn(fmt.Sprintf("GET %s -> %d, retry %d in %.0fs", url, resp.Status, attempt, delay.Seconds()))
			if err := c.sleep(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		if resp.Status < 200 || resp.Status >= 300 { // raise_for_status
			return nil, &httpc.StatusError{Status: resp.Status, URL: url}
		}
		return resp, nil
	}
	panic("unreachable")
}

type changeSet struct {
	obj  *pyjson.Object
	ft   any // fetchTime, verbatim
	when int64
}

// deltaLog is _delta_log: the change sets, oldest first.
func (c *Collector) deltaLog(ctx context.Context) ([]changeSet, error) {
	resp, err := c.get(ctx, DeltaLogURL, false)
	if err != nil {
		return nil, err
	}
	data, err := pyjson.Decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("deltaLog.json: %w", err)
	}
	list, ok := data.([]any)
	if ok {
		for _, e := range list {
			o := asObject(e)
			if o == nil {
				ok = false
				break
			}
			if _, isStr := o.Get("fetchTime").(string); !isStr {
				ok = false
				break
			}
		}
	}
	if !ok {
		return nil, &valueError{"deltaLog.json: expected a list of change sets with fetchTime"}
	}
	if len(list) == 0 {
		return nil, &valueError{"deltaLog.json is empty"}
	}
	out := make([]changeSet, 0, len(list))
	for _, e := range list {
		o := e.(*pyjson.Object)
		t, ok := parseTS(o.Get("fetchTime"))
		if !ok {
			return nil, &valueError{fmt.Sprintf("deltaLog.json: bad fetchTime %s", pyjson.Repr(o.Get("fetchTime")))}
		}
		out = append(out, changeSet{obj: o, ft: o.Get("fetchTime"), when: t.micro()})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].when < out[j].when })
	return out, nil
}

// idsOf is _ids_of: valid CVE ids of new[] then updated[].
func idsOf(cs *pyjson.Object) ([]string, error) {
	var out []string
	for _, key := range []string{"new", "updated"} {
		items, err := iterOr(cs.Get(key))
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			o := asObject(it)
			if o == nil {
				continue
			}
			if id := collector.Text(o.Get("cveId")); id != nil && model.IsValidCVEID(*id) {
				out = append(out, *id)
			}
		}
	}
	return out, nil
}

func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

type fetchStatus int

const (
	statusOK fetchStatus = iota
	statusMissing
	statusFailed
)

// fetchRecord is _fetch_record.
func (c *Collector) fetchRecord(ctx context.Context, id string) (fetchStatus, *pyjson.Object, error) {
	resp, err := c.get(ctx, RecordURL(id), true)
	if err == nil && resp == nil {
		return statusMissing, nil, nil
	}
	if err == nil {
		var v any
		if v, err = pyjson.Decode(resp.Body); err == nil {
			if o := asObject(v); o != nil {
				return statusOK, o, nil
			}
			err = &valueError{"record is not a JSON object"}
		}
	}
	if ctx.Err() != nil {
		return statusFailed, nil, ctx.Err()
	}
	c.log.Warn(fmt.Sprintf("could not fetch %s: %s", id, err))
	return statusFailed, nil, nil
}

// fetchRecords is _fetch_records: CONCURRENCY workers, results in input order.
func (c *Collector) fetchRecords(ctx context.Context, ids []string) (got *pyjson.Object, missing, failed []string, err error) {
	type res struct {
		st  fetchStatus
		obj *pyjson.Object
		err error
	}
	results := make([]res, len(ids))
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(c.concurrency, max(len(ids), 1)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				st, obj, err := c.fetchRecord(ctx, ids[i])
				results[i] = res{st, obj, err}
			}
		}()
	}
	for i := range ids {
		next <- i
	}
	close(next)
	wg.Wait()
	got = pyjson.NewObject()
	for i, r := range results {
		if r.err != nil {
			return nil, nil, nil, r.err
		}
		switch r.st {
		case statusOK:
			got.Set(ids[i], r.obj)
		case statusMissing:
			missing = append(missing, ids[i])
		default:
			failed = append(failed, ids[i])
		}
	}
	return got, missing, failed, nil
}

// zipRecords is _zip_records: records of the end-of-day delta zip of day;
// nil if not published.
func (c *Collector) zipRecords(ctx context.Context, day time.Time) (*pyjson.Object, error) {
	url := EODZipURL(day)
	resp, err := c.get(ctx, url, true)
	if err != nil || resp == nil {
		return nil, err
	}
	if len(resp.Body) > MaxZipBytes {
		return nil, &valueError{fmt.Sprintf("%s: %d bytes > limit", url, len(resp.Body))}
	}
	zr, err := zip.NewReader(bytes.NewReader(resp.Body), int64(len(resp.Body)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	out := pyjson.NewObject()
	for _, f := range zr.File {
		m := zipMemberRe.FindStringSubmatch(f.Name)
		if m == nil || strings.HasSuffix(f.Name, "/") {
			continue
		}
		if f.UncompressedSize64 > MaxMemberBytes {
			c.log.Warn(fmt.Sprintf("skipping oversized zip member %s", f.Name))
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", url, f.Name, err)
		}
		var buf bytes.Buffer
		_, err = buf.ReadFrom(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", url, f.Name, err)
		}
		v, err := pyjson.Decode(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", url, f.Name, err)
		}
		if o := asObject(v); o != nil {
			out.Set(m[1], o)
		}
	}
	return out, nil
}

// ------------------------------------------------------------------ fetch

// Fetch implements collector.Collector (Python fetch).
func (c *Collector) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	var cursor *pyjson.Object
	switch cur := state.Cursor; {
	case !truthy(cur):
		cursor = pyjson.NewObject()
	case asObject(cur) != nil:
		cursor = asObject(cur).Clone()
	default:
		return nil, &TypeError{fmt.Sprintf("collector_state.cursor is a %s, not a dict", pyTypeName(cur))}
	}
	if !truthy(cursor.Get("last_fetch_time")) {
		return c.bootstrap(ctx)
	}
	return c.incremental(ctx, cursor, state.Wanted)
}

func (c *Collector) now() pyTime { return utcPyTime(c.clock()) }

func (c *Collector) gap(missedFrom, logStarts any, now pyTime) *pyjson.Object {
	c.log.Warn(fmt.Sprintf("cvelist fell behind: change sets between %s and %s are no longer in "+
		"deltaLog.json (it keeps ~30 days); records changed only in that interval "+
		"were NOT fetched. Recorded in collector_state.cursor.gaps.", pyStr(missedFrom), pyStr(logStarts)))
	g := pyjson.NewObject()
	g.Set("missed_from", missedFrom)
	g.Set("log_starts", logStarts)
	g.Set("detected_at", now.isoformat())
	return g
}

// pyStr is str(v) for log messages (%s formatting).
func pyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return pyjson.Repr(v)
}

func (c *Collector) bootstrap(ctx context.Context) (*model.FetchResult, error) {
	now := c.now()
	changes, err := c.deltaLog(ctx)
	if err != nil {
		return nil, err
	}
	today := time.Date(now.year, time.Month(now.month), now.day, 0, 0, 0, 0, time.UTC)
	records := pyjson.NewObject()
	zipDays := []any{}
	boundaryDay := today
	for i := c.BootstrapDays; i > 0; i-- {
		day := today.AddDate(0, 0, -i)
		recs, err := c.zipRecords(ctx, day)
		if err != nil {
			return nil, err
		}
		if recs == nil {
			c.log.Info(fmt.Sprintf("no end-of-day zip for %s; using deltaLog from that day", day.Format("2006-01-02")))
			boundaryDay = day
			break
		}
		for _, k := range recs.Keys() { // later days override earlier versions
			records.Set(k, recs.Get(k))
		}
		zipDays = append(zipDays, day.Format("2006-01-02"))
	}
	boundary := utcPyTime(boundaryDay)
	bmicro := boundary.micro()

	gaps := []any{}
	if changes[0].when > bmicro {
		gaps = append(gaps, c.gap(boundary.isoformat(), changes[0].ft, now))
	}
	var ids []string
	nChange := 0
	for _, e := range changes {
		if e.when >= bmicro {
			nChange++
			x, err := idsOf(e.obj)
			if err != nil {
				return nil, err
			}
			ids = append(ids, x...)
		}
	}
	bs := pyjson.NewObject()
	bs.Set("days", pyjson.IntOf(int64(c.BootstrapDays)))
	bs.Set("zip_days", zipDays)
	bs.Set("deltalog_from", boundary.isoformat())
	bs.Set("at", now.isoformat())
	cur := pyjson.NewObject()
	cur.Set("last_fetch_time", changes[len(changes)-1].ft)
	cur.Set("bootstrap", bs)
	cur.Set("gaps", gaps)
	res, err := c.fetchAndBuild(ctx, records, dedupe(ids), nil, cur, nChange, nil, nil)
	if err != nil {
		return nil, err
	}
	res.Cursor.(*pyjson.Object).Get("last_run").(*pyjson.Object).Set("zip_records", pyjson.IntOf(int64(records.Len())))
	return res, nil
}

// pyList is list(v or []) for cursor values (dict -> keys, str -> chars).
func pyList(v any) ([]any, error) {
	items, err := iterOr(v)
	return append([]any{}, items...), err
}

func (c *Collector) incremental(ctx context.Context, cursor *pyjson.Object, wanted []string) (*model.FetchResult, error) {
	now := c.now()
	changes, err := c.deltaLog(ctx)
	if err != nil {
		return nil, err
	}
	last := cursor.Get("last_fetch_time")
	lastDT, ok := parseTS(last)
	if !ok {
		return nil, &valueError{fmt.Sprintf("cursor.last_fetch_time is not a timestamp: %s", pyjson.Repr(last))}
	}
	gaps, err := pyList(cursor.Get("gaps"))
	if err != nil {
		return nil, err
	}
	if changes[0].when > lastDT.micro() {
		gaps = append(gaps, c.gap(last, changes[0].ft, now))
	}
	var newer []changeSet
	for _, e := range changes {
		if e.when > lastDT.micro() {
			newer = append(newer, e)
		}
	}
	newLast := last
	if len(newer) > 0 {
		newLast = newer[len(newer)-1].ft
	}
	rawPending, err := iterOr(cursor.Get("pending"))
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, p := range rawPending {
		if s, ok := p.(string); ok && model.IsValidCVEID(s) { // only a str can pass is_valid_cve_id(str(p))
			pending = append(pending, s)
		}
	}
	var ids []string
	for _, e := range newer {
		x, err := idsOf(e.obj)
		if err != nil {
			return nil, err
		}
		ids = append(ids, x...)
	}
	out := pyjson.NewObject()
	for _, k := range cursor.Keys() {
		if k != "pending" && k != "last_run" {
			out.Set(k, cursor.Get(k))
		}
	}
	out.Set("last_fetch_time", newLast)
	if len(gaps) > MaxGapsKept {
		gaps = gaps[len(gaps)-MaxGapsKept:]
	}
	out.Set("gaps", gaps)
	if wanted == nil {
		wanted = []string{}
	}
	return c.fetchAndBuild(ctx, pyjson.NewObject(), dedupe(ids), pending, out, len(newer), wanted, &now)
}

// missingMap is _missing_map: cursor.backfill_missing -> {cve: time of last 404}.
func missingMap(raw any) map[string]pyTime {
	out := map[string]pyTime{}
	if o := asObject(raw); o != nil {
		for _, k := range o.Keys() {
			if t, ok := parseTS(o.Get(k)); ok && model.IsValidCVEID(k) {
				out[k] = t
			}
		}
	}
	return out
}

func ints(n int) pyjson.Int { return pyjson.IntOf(int64(n)) }

func strList(ids []string) []any {
	out := make([]any, 0, len(ids))
	for _, s := range ids {
		out = append(out, s)
	}
	return out
}

// fetchAndBuild is _fetch_and_build. wanted == nil on bootstrap (backfill
// ignored, no backfill state touched); non-nil on incremental runs.
func (c *Collector) fetchAndBuild(ctx context.Context, records *pyjson.Object, ids, pending []string,
	cursorIn *pyjson.Object, changeSets int, wanted []string, now *pyTime) (*model.FetchResult, error) {
	queue := dedupe(append(append([]string{}, pending...), ids...)) // backlog first
	batch, rest := queue, []string(nil)
	if len(queue) > c.MaxFiles {
		batch, rest = queue[:c.MaxFiles], queue[c.MaxFiles:]
	}
	if len(rest) > 0 {
		c.log.Warn(fmt.Sprintf("cvelist: %d CVE ids queued, fetching %d this run (max_files); %d left pending",
			len(queue), len(batch), len(rest)))
	}

	// On-demand backfill: only in the room left under the cap, never pending.
	cursor := cursorIn.Clone()
	mm := missingMap(cursor.Get("backfill_missing"))
	var validWanted []string
	for _, w := range wanted {
		if model.IsValidCVEID(w) {
			validWanted = append(validWanted, w)
		}
	}
	wantedAll := dedupe(validWanted)
	inQueue := make(map[string]bool, len(queue))
	for _, q := range queue {
		inQueue[q] = true
	}
	var retryWindow []string
	skip := map[string]bool{}
	for _, w := range wantedAll {
		if t, ok := mm[w]; ok && now != nil && now.micro()-t.micro() < c.retryUS {
			retryWindow = append(retryWindow, w)
			skip[w] = true
		}
	}
	var candidates []string
	for _, w := range wantedAll {
		if !inQueue[w] && !skip[w] {
			candidates = append(candidates, w)
		}
	}
	room := max(c.MaxFiles-len(batch), 0)
	backfill, dropped := candidates, []string(nil)
	if len(candidates) > room {
		backfill, dropped = candidates[:room], candidates[room:]
	}

	got, missing, failed, err := c.fetchRecords(ctx, append(append([]string{}, batch...), backfill...))
	if err != nil {
		return nil, err
	}
	bf := make(map[string]bool, len(backfill))
	for _, b := range backfill {
		bf[b] = true
	}
	var batchFailed, batchMissing, bfMissing, bfFailed, bfGot []string
	for _, x := range failed {
		if bf[x] {
			bfFailed = append(bfFailed, x)
		} else {
			batchFailed = append(batchFailed, x)
		}
	}
	bfGotAny := false
	for _, k := range got.Keys() {
		if bf[k] {
			bfGotAny = true
			bfGot = append(bfGot, k)
		}
	}
	if len(batch) > 0 && len(batchFailed) == len(batch) && !bfGotAny {
		// upstream looks down: judged on change-set ids only
		return nil, fmt.Errorf("all %d record fetches failed", len(batch))
	}
	for _, x := range missing {
		if bf[x] {
			bfMissing = append(bfMissing, x)
		} else {
			batchMissing = append(batchMissing, x)
		}
	}
	for _, id := range batchMissing {
		c.log.Warn(fmt.Sprintf("cvelist: %s listed in deltaLog but its file is 404; dropped", id))
	}

	// records = {**records, **got}: a NEW dict (the caller's zip map keeps its
	// size, which bootstrap reports as last_run.zip_records); the per-file
	// version is newer than the zip one.
	records = records.Clone()
	for _, k := range got.Keys() {
		records.Set(k, got.Get(k))
	}
	newPending := dedupe(append(append([]string{}, rest...), batchFailed...))
	cursor.Set("pending", strList(newPending))
	lastRun := pyjson.NewObject()
	lastRun.Set("change_sets", ints(changeSets))
	lastRun.Set("ids_queued", ints(len(queue)))
	lastRun.Set("files_fetched", ints(got.Len()))
	lastRun.Set("files_missing", strList(batchMissing))
	lastRun.Set("files_failed", ints(len(batchFailed)))
	lastRun.Set("pending", ints(len(newPending)))
	lastRun.Set("http_requests", pyjson.IntOf(c.requestsMade.Load()))
	cursor.Set("last_run", lastRun)
	if wanted != nil {
		if now != nil {
			for _, x := range bfMissing {
				mm[x] = *now
			}
		}
		for _, k := range got.Keys() { // exists upstream now (via backfill or a change set)
			delete(mm, k)
		}
		if len(wanted) < c.WantedLimit() {
			// complete list: entries no longer wanted are obsolete
			keep := make(map[string]bool, len(wantedAll))
			for _, w := range wantedAll {
				keep[w] = true
			}
			for k := range mm {
				if !keep[k] {
					delete(mm, k)
				}
			}
		}
		if len(mm) > c.maxMissing { // keep the most recent 404s
			type kv struct {
				k string
				t pyTime
			}
			all := make([]kv, 0, len(mm))
			for k, t := range mm {
				all = append(all, kv{k, t})
			}
			sort.Slice(all, func(i, j int) bool { // (t, c) descending
				if a, b := all[i].t.micro(), all[j].t.micro(); a != b {
					return a > b
				}
				return all[i].k > all[j].k
			})
			mm = map[string]pyTime{}
			for _, e := range all[:c.maxMissing] {
				mm[e.k] = e.t
			}
		}
		keys := make([]string, 0, len(mm))
		for k := range mm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		bm := pyjson.NewObject()
		for _, k := range keys {
			bm.Set(k, mm[k].isoformat())
		}
		cursor.Set("backfill_missing", bm)
		lastRun.Set("backfill_wanted", ints(len(wanted)))
		lastRun.Set("backfill_skipped_missing", ints(len(retryWindow)))
		lastRun.Set("backfill_queued", ints(len(backfill)))
		lastRun.Set("backfill_fetched", ints(len(bfGot)))
		lastRun.Set("backfill_missing", ints(len(bfMissing)))
		lastRun.Set("backfill_failed", ints(len(bfFailed)))
		lastRun.Set("backfill_dropped", ints(len(dropped)))
		lastRun.Set("backfill_missing_tracked", ints(len(mm)))
		if len(wantedAll) > 0 {
			c.log.Info(fmt.Sprintf("cvelist backfill: %d wanted, %d queued, %d fetched, %d 404, %d failed, "+
				"%d over cap (retried next run), %d in 404 retry window",
				len(wanted), len(backfill), len(bfGot), len(bfMissing), len(bfFailed), len(dropped), len(retryWindow)))
		}
	}
	keys := append([]string{}, records.Keys()...)
	sort.Strings(keys)
	raw := make([]model.RawRecord, 0, len(keys))
	for _, k := range keys {
		raw = append(raw, model.RawRecord{Source: Name, SourceKey: k, Payload: records.Get(k), IsBackfill: bf[k]})
	}
	return &model.FetchResult{Records: raw, Cursor: cursor}, nil
}
