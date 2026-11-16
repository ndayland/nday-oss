package ghsa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// ------------------------------------------------------------------ URLs

// paramEscape is httpx's query-parameter encoding (httpx.URL(url, params=)):
// unreserved characters kept, space -> '+', everything else %XX (uppercase),
// UTF-8 bytes for non-ASCII.
func paramEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// EncodeParams renders key/value pairs in order like httpx.URL(..., params=).
func EncodeParams(kv ...string) string {
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, paramEscape(kv[i])+"="+paramEscape(kv[i+1]))
	}
	return strings.Join(parts, "&")
}

// ListURL is ghsa.py's list_url(since): reviewed advisories updated at/after
// since, oldest first. Parameter order and encoding are Python's (the URL is
// stored verbatim in cursor.pending).
func ListURL(since time.Time) (string, error) {
	z, err := isoZ(since)
	if err != nil {
		return "", err
	}
	return AdvisoriesURL + "?" + EncodeParams(
		"type", "reviewed",
		"sort", "updated",
		"direction", "asc",
		"per_page", fmt.Sprint(PerPage),
		"updated", ">="+z,
	), nil
}

var linkSplitRe = regexp.MustCompile(", *<")

// parseHeaderLinks is httpx._models._parse_header_links.
func parseHeaderLinks(value string) []map[string]string {
	const replace = " '\""
	var links []map[string]string
	value = strings.Trim(value, replace)
	if value == "" {
		return links
	}
	for _, val := range linkSplitRe.Split(value, -1) {
		u, params, ok := strings.Cut(val, ";")
		if !ok {
			u, params = val, ""
		}
		link := map[string]string{"url": strings.Trim(u, "<> '\"")}
		for _, param := range strings.Split(params, ";") {
			kv := strings.Split(param, "=")
			if len(kv) != 2 {
				break
			}
			link[strings.Trim(kv[0], replace)] = strings.Trim(kv[1], replace)
		}
		links = append(links, link)
	}
	return links
}

// headerGet is httpx Headers.get: all values of the field joined by ", ".
func headerGet(h http.Header, key string) (string, bool) {
	vs := h.Values(key)
	if len(vs) == 0 {
		return "", false
	}
	return strings.Join(vs, ", "), true
}

// urlSplit returns scheme, netloc and path as urllib.parse.urlsplit does.
func urlSplit(raw string) (scheme, netloc, path string, err error) {
	u := strings.TrimLeft(raw, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"+
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	for _, c := range []string{"\t", "\r", "\n"} {
		u = strings.ReplaceAll(u, c, "")
	}
	if i := strings.IndexByte(u, ':'); i > 0 && isASCIIAlpha(u[0]) {
		ok := true
		for j := 0; j < i; j++ {
			c := u[j]
			if !(isASCIIAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
				ok = false
				break
			}
		}
		if ok {
			scheme, u = strings.ToLower(u[:i]), u[i+1:]
		}
	}
	if strings.HasPrefix(u, "//") {
		rest := u[2:]
		end := len(rest)
		if k := strings.IndexAny(rest, "/?#"); k >= 0 {
			end = k
		}
		netloc, u = rest[:end], rest[end:]
		if strings.Contains(netloc, "[") != strings.Contains(netloc, "]") {
			return "", "", "", errors.New("Invalid IPv6 URL")
		}
	}
	if k := strings.IndexByte(u, '#'); k >= 0 {
		u = u[:k]
	}
	if k := strings.IndexByte(u, '?'); k >= 0 {
		u = u[:k]
	}
	return scheme, netloc, u, nil
}

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// nextURL is GhsaCollector._next_url: the Link rel="next" URL, verbatim, after
// checking it points at GET /advisories on the API host.
func nextURL(h http.Header) (string, error) {
	hv, ok := headerGet(h, "Link")
	if !ok {
		return "", nil
	}
	byKey := map[string]map[string]string{}
	for _, l := range parseHeaderLinks(hv) {
		key := l["rel"]
		if key == "" {
			key = l["url"]
		}
		byKey[key] = l
	}
	nxt := byKey["next"]["url"]
	if nxt == "" {
		return "", nil
	}
	scheme, netloc, path, err := urlSplit(nxt)
	if err != nil {
		return "", err
	}
	if scheme+"://"+netloc != APIBase || path != "/advisories" {
		return "", fmt.Errorf("unexpected Link next URL: %s", pyStrRepr(nxt))
	}
	return nxt, nil
}

// ------------------------------------------------------------------ HTTP

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// transportError is httpx.TransportError (retried, then a "stop").
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// TooLargeError: body over MaxBodyBytes (Go-only cap; fails the run).
type TooLargeError struct{ URL string }

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s: response body exceeds %d bytes", e.URL, MaxBodyBytes)
}

func (c *Collector) headers() http.Header {
	h := http.Header{}
	h.Set("User-Agent", httpc.UserAgent)
	h.Set("Accept", AcceptHeader)
	h.Set("X-GitHub-Api-Version", APIVersion)
	if c.token != "" {
		h.Set("Authorization", "Bearer "+c.token)
	}
	return h
}

// do is one attempt (Python: self.client.get(url, headers=self._headers())).
func (c *Collector) do(ctx context.Context, url string) (*response, error) {
	for i := 0; i < len(c.token); i++ {
		if c.token[i] >= 0x80 {
			// httpx encodes header values as ASCII: UnicodeEncodeError (fatal).
			// The token itself is never echoed.
			return nil, errors.New("UnicodeEncodeError: NDAY_GITHUB_TOKEN contains non-ASCII characters")
		}
	}
	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = c.headers()
	resp, err := c.client.Do(req)
	if err != nil {
		if parent.Err() != nil {
			return nil, err // caller's cancellation / deadline: fatal
		}
		return nil, &transportError{err}
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxBodyBytes {
		return nil, &TooLargeError{URL: url}
	}
	// httpx read timeout: no data for ReadTimeout.
	idle := time.AfterFunc(ReadTimeout, func() {
		cancel(fmt.Errorf("ReadTimeout: no data for %s", ReadTimeout))
	})
	defer idle.Stop()
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(chunk)
		if n > 0 {
			idle.Reset(ReadTimeout)
			if buf.Len()+n > MaxBodyBytes {
				return nil, &TooLargeError{URL: url}
			}
			buf.Write(chunk[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if parent.Err() != nil {
				return nil, rerr
			}
			if cause := context.Cause(ctx); cause != nil {
				return nil, &transportError{cause} // read timeout
			}
			return nil, &transportError{rerr}
		}
	}
	return &response{Status: resp.StatusCode, Header: resp.Header, Body: buf.Bytes()}, nil
}

// stop is ghsa.py's _Stop: stop paginating cleanly, keep progress.
type stop struct {
	reason string
	info   *pyjson.Object
}

func (c *Collector) rateInfo(status any) *pyjson.Object {
	info := pyjson.NewObject()
	info.Set("status", status)
	for _, k := range c.rate.Keys() {
		info.Set(k, c.rate.Get(k))
	}
	return info
}

// maxTimestamp is datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC).timestamp().
const maxTimestamp = 253402300799

// noteRate is _note_rate. Errors are Python's uncaught exceptions (fatal).
func (c *Collector) noteRate(r *response) error {
	for _, key := range []string{"limit", "remaining", "used", "reset"} {
		v, ok := headerGet(r.Header, "x-ratelimit-"+key)
		if !ok || !isDigitStr(pystr.Strip(v)) {
			continue
		}
		n, err := pyInt(v)
		if err != nil {
			return fmt.Errorf("ValueError: %v", err)
		}
		c.rate.Set(key, pyjson.Int(n.String()))
	}
	if v, ok := c.rate.Lookup("reset"); ok {
		n, _ := new(big.Int).SetString(string(v.(pyjson.Int)), 10)
		if n.Cmp(big.NewInt(maxTimestamp)) > 0 {
			return fmt.Errorf("ValueError: x-ratelimit-reset %s: year is out of range", n)
		}
		at, err := isoZ(time.Unix(n.Int64(), 0))
		if err != nil {
			return err
		}
		c.rate.Set("reset_at", at)
	}
	return nil
}

// asciiLower lowercases ASCII letters only. Python's resp.text.lower() can
// only produce the needle "rate limit" from ASCII input (the non-ASCII
// characters whose lowercase contains ASCII are U+0130 -> "i̇" and
// U+212A -> "k", neither of which can complete "rate limit"), and ASCII
// bytes never occur inside UTF-8 multi-byte sequences, so a byte search is
// equivalent for UTF-8 (the charset GitHub declares).
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// isRateLimited is _is_rate_limited.
func isRateLimited(r *response) bool {
	if r.Status == 429 {
		return true
	}
	if r.Status != 403 {
		return false
	}
	if v, _ := headerGet(r.Header, "x-ratelimit-remaining"); v == "0" {
		return true
	}
	if _, ok := headerGet(r.Header, "retry-after"); ok {
		return true
	}
	return bytes.Contains(asciiLower(r.Body), []byte("rate limit"))
}

func secs(f float64) time.Duration {
	if f >= float64(math.MaxInt64)/float64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(f * float64(time.Second))
}

// get is _get: one logical GET with Python's retry policy. Exactly one of
// the results is non-nil: the response, a stop, or a fatal error (an
// *httpc.StatusError is Python's httpx.HTTPStatusError).
func (c *Collector) get(ctx context.Context, url string) (*response, *stop, error) {
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		delay := BackoffBase * math.Pow(2, float64(attempt-1))
		c.RequestsMade++
		resp, err := c.do(ctx, url)
		if err != nil {
			var te *transportError
			if !errors.As(err, &te) {
				return nil, nil, err
			}
			if attempt == MaxAttempts {
				info := pyjson.NewObject()
				info.Set("error", te.Error())
				return nil, &stop{"transport_error", info}, nil
			}
			c.logger.Warn(fmt.Sprintf("GET %s failed (%s), retry %d in %.0fs", url, te.Error(), attempt, delay))
			if err := c.sleep(ctx, secs(delay)); err != nil {
				return nil, nil, err
			}
			continue
		}
		if err := c.noteRate(resp); err != nil {
			return nil, nil, err
		}
		if isRateLimited(resp) {
			info := c.rateInfo(resp.Status)
			if v, _ := headerGet(resp.Header, "x-ratelimit-remaining"); v == "0" {
				return nil, &stop{"rate_limited", info}, nil
			}
			ra, _ := headerGet(resp.Header, "retry-after")
			ra = pystr.Strip(ra)
			wait := 60.0 // docs: else wait >= 1 min
			if isDigitStr(ra) {
				if wait, err = pyFloatDigits(ra); err != nil {
					return nil, nil, fmt.Errorf("ValueError: %v", err)
				}
			}
			if wait > MaxRetryAfter || attempt == MaxAttempts {
				info.Set("retry_after", wait)
				return nil, &stop{"secondary_rate_limited", info}, nil
			}
			c.logger.Warn(fmt.Sprintf("GET %s -> %d (secondary rate limit), retry in %.0fs", url, resp.Status, wait))
			if err := c.sleep(ctx, secs(wait)); err != nil {
				return nil, nil, err
			}
			continue
		}
		if resp.Status >= 500 {
			if attempt == MaxAttempts {
				info := pyjson.NewObject()
				info.Set("status", resp.Status)
				return nil, &stop{"server_error", info}, nil
			}
			c.logger.Warn(fmt.Sprintf("GET %s -> %d, retry %d in %.0fs", url, resp.Status, attempt, delay))
			if err := c.sleep(ctx, secs(delay)); err != nil {
				return nil, nil, err
			}
			continue
		}
		if resp.Status < 200 || resp.Status >= 300 { // raise_for_status
			return nil, nil, &httpc.StatusError{Status: resp.Status, URL: url}
		}
		return resp, nil, nil
	}
	return nil, nil, errors.New("unreachable")
}

// ------------------------------------------------------------------ fetch

// pyList is list(value or []) for the cursor's gaps.
func pyList(v any) ([]any, error) {
	if !truthy(v) {
		return []any{}, nil
	}
	switch x := v.(type) {
	case []any:
		return append([]any(nil), x...), nil
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	case *pyjson.Object:
		out := []any{}
		for _, k := range x.Keys() {
			out = append(out, k)
		}
		return out, nil
	}
	return nil, fmt.Errorf("TypeError: %T object is not iterable", v)
}

// Fetch is GhsaCollector.fetch.
func (c *Collector) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	cursor := pyjson.NewObject()
	if truthy(state.Cursor) {
		o, ok := state.Cursor.(*pyjson.Object)
		if !ok {
			return nil, fmt.Errorf("ghsa: cursor is not an object: %s", truncRunes(pyRepr(state.Cursor), 200))
		}
		cursor = o.Clone()
	}
	now := c.clock().Round(0).UTC().Truncate(time.Microsecond) // Python datetime precision
	first := state.IsFirstRun() || !truthy(cursor.Get("since"))
	resuming := false
	var since, querySince time.Time
	var url string
	var err error
	if first {
		since = now.AddDate(0, 0, -c.BootstrapDays)
		querySince = since
		if url, err = ListURL(since); err != nil {
			return nil, err
		}
	} else {
		var ok bool
		if since, ok = parseTS(cursor.Get("since")); !ok {
			return nil, fmt.Errorf("cursor.since is not a timestamp: %s", pyRepr(cursor.Get("since")))
		}
		pending := cursor.Get("pending")
		var po *pyjson.Object
		if truthy(pending) {
			if po, ok = pending.(*pyjson.Object); !ok {
				return nil, fmt.Errorf("AttributeError: cursor.pending is not an object: %s", pyRepr(pending))
			}
		}
		if po != nil && truthy(po.Get("next_url")) {
			resuming = true
			if querySince, ok = parseTS(po.Get("query_since")); !ok {
				querySince = since
			}
			s, isStr := po.Get("next_url").(string)
			if !isStr {
				return nil, fmt.Errorf("TypeError: cursor.pending.next_url is not a string: %s", pyRepr(po.Get("next_url")))
			}
			url = s
			c.logger.Info(fmt.Sprintf("ghsa: resuming pending pagination (%s, query since %s)",
				pyStr(po.Get("reason")), pyStr(po.Get("query_since"))))
		} else {
			if querySince, err = c.minusOverlap(since); err != nil {
				return nil, err
			}
			if url, err = ListURL(querySince); err != nil {
				return nil, err
			}
		}
	}

	records := map[string]any{}
	high := since
	pages := 0
	var st *stop
	var pendingURL string
	for {
		if pages >= c.MaxRequests {
			info := pyjson.NewObject()
			info.Set("max_requests", c.MaxRequests)
			pendingURL, st = url, &stop{"request_cap", info}
			break
		}
		if pages > 0 && c.rate.Get("remaining") == pyjson.Int("0") { // don't spend a doomed request
			pendingURL, st = url, &stop{"rate_limited", c.rateInfo(nil)}
			break
		}
		resp, s, err := c.get(ctx, url)
		if s != nil {
			pendingURL, st = url, s
			break
		}
		if err != nil {
			var se *httpc.StatusError
			if resuming && pages == 0 && errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
				// stale pending cursor rejected: restart from the high-water mark
				c.logger.Warn(fmt.Sprintf("ghsa: pending next URL rejected (%d); restarting from since", se.Status))
				resuming = false
				if querySince, err = c.minusOverlap(since); err != nil {
					return nil, err
				}
				if url, err = ListURL(querySince); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		pages++
		data, err := pyjson.Decode(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("JSONDecodeError: GET %s: %w", url, err)
		}
		items, ok := data.([]any)
		if !ok {
			return nil, errors.New("GET /advisories: expected a JSON array")
		}
		for _, adv := range items {
			var gid *string
			o, isObj := adv.(*pyjson.Object)
			if isObj {
				gid = collector.Text(o.Get("ghsa_id"))
			}
			if gid == nil {
				return nil, fmt.Errorf("advisory without ghsa_id: %s", truncRunes(pyStr(adv), 200))
			}
			records[*gid] = adv // later pages hold newer versions
			if upd, ok := parseTS(o.Get("updated_at")); ok && upd.After(high) {
				high = upd
			}
		}
		nxt, err := nextURL(resp.Header)
		if err != nil {
			return nil, err
		}
		if nxt == "" {
			break
		}
		url = nxt
	}

	if st != nil && (first || (len(records) == 0 && (st.reason == "transport_error" || st.reason == "server_error"))) {
		// Bootstrap must be complete; an incremental run whose very first
		// request failed is a plain failure (cursor kept).
		where := "before any data"
		if first {
			where = "during the first-run window"
		}
		return nil, fmt.Errorf("ghsa: stopped (%s) after %d page(s) %s: %s. "+
			"Nothing stored; retry later, lower NDAY_GHSA_BOOTSTRAP_DAYS, raise "+
			"NDAY_GHSA_MAX_REQUESTS or set NDAY_GITHUB_TOKEN.", st.reason, pages, where, pyRepr(st.info))
	}

	out := pyjson.NewObject()
	for _, k := range cursor.Keys() {
		if k != "pending" && k != "last_run" {
			out.Set(k, cursor.Get(k))
		}
	}
	gaps, err := pyList(cursor.Get("gaps"))
	if err != nil {
		return nil, err
	}
	highZ, err := isoZ(high)
	if err != nil {
		return nil, err
	}
	nowZ, err := isoZ(now)
	if err != nil {
		return nil, err
	}
	qsZ, err := isoZ(querySince)
	if err != nil {
		return nil, err
	}
	out.Set("since", highZ)
	out.Set("pending", nil)
	if first {
		sinceZ, err := isoZ(since)
		if err != nil {
			return nil, err
		}
		b := pyjson.NewObject()
		b.Set("days", c.BootstrapDays)
		b.Set("window_from", sinceZ)
		b.Set("at", nowZ)
		out.Set("bootstrap", b)
	}
	if st != nil {
		p := pyjson.NewObject()
		p.Set("next_url", pendingURL)
		p.Set("query_since", qsZ)
		p.Set("reason", st.reason)
		out.Set("pending", p)
		c.logger.Warn(fmt.Sprintf("ghsa: stopped early (%s) after %d page(s), %d advisories; "+
			"remaining pages resume next run. %s", st.reason, pages, len(records), pyRepr(st.info)))
		if now.Sub(high) > LagWarn {
			c.logger.Warn(fmt.Sprintf("ghsa fell behind: advisories updated since %s are not all "+
				"fetched yet (%s). Recorded in collector_state.cursor.gaps.", highZ, st.reason))
			g := pyjson.NewObject()
			g.Set("behind_since", highZ)
			g.Set("reason", st.reason)
			g.Set("detected_at", nowZ)
			gaps = append(gaps, g)
		}
	}
	if len(gaps) > MaxGapsKept {
		gaps = gaps[len(gaps)-MaxGapsKept:]
	}
	out.Set("gaps", gaps)
	lr := pyjson.NewObject()
	lr.Set("query_since", qsZ)
	lr.Set("pages", pages)
	lr.Set("http_requests", c.RequestsMade)
	lr.Set("advisories", len(records))
	if st != nil {
		lr.Set("stopped", st.reason)
	} else {
		lr.Set("stopped", nil)
	}
	rl := pyjson.NewObject()
	for _, k := range []string{"limit", "remaining", "reset_at"} {
		if v, ok := c.rate.Lookup(k); ok {
			rl.Set(k, v)
		}
	}
	lr.Set("rate_limit", rl)
	out.Set("last_run", lr)

	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	raw := make([]model.RawRecord, 0, len(keys))
	for _, k := range keys {
		raw = append(raw, model.RawRecord{Source: Name, SourceKey: k, Payload: records[k]})
	}
	return &model.FetchResult{Records: raw, Cursor: out}, nil
}

// minusOverlap is since - self.overlap (OverflowError below year 1).
func (c *Collector) minusOverlap(since time.Time) (time.Time, error) {
	m := c.OverlapMinutes
	t := since.AddDate(0, 0, -int(m/1440)).Add(-time.Duration(m%1440) * time.Minute)
	if t.Year() < 1 {
		return time.Time{}, errors.New("OverflowError: date value out of range")
	}
	return t, nil
}
