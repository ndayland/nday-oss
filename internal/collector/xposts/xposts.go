// Package xposts collects posts on X (Twitter) that mention CVE or GHSA ids, from a
// hand-maintained allowlist of accounts, through the official X API v2
// recent search endpoint with an app-only Bearer token. Nothing else: no
// scraping, no other endpoints, no browser automation. Go only (there is no
// Python counterpart). See docs/xposts.md.
//
// Configuration:
//   - NDAY_X_BEARER_TOKEN (secret; never logged, never in the cursor): a
//     database setting sealed in app_settings (internal/settings, read at
//     the start of every run) or else the environment, see docs/settings.md;
//   - the allowlist (table x_accounts) and the runtime knobs (table
//     x_settings: enabled, max posts / requests per run, bootstrap days,
//     max query length) live in the database and are read in Prepare at the
//     start of every run through internal/xconfig.
//
// Missing configuration (no token, no enabled account, or x_settings.enabled
// = false) is not an error: the run is skipped with a log line, makes no
// request, stores nothing and keeps the cursor (collector_state ends "ok"
// and cursor.last_run.skipped says why), so `nday collect xposts` can be
// scheduled before it is configured.
//
// Fetch: the enabled accounts, ordered by numeric id, are packed into as few
// queries as fit in max_query_length characters:
//
//	(from:handle1 OR from:handle2 ...) (CVE OR GHSA) -is:retweet
//
// The docs only show from:<username> (see docs/xposts.md), so the query uses
// the handle; the numeric id stays the key: posts whose author_id is not an
// enabled allowlisted id are dropped. Each query is paginated with
// pagination_token (100 posts per page). The first run (or a cursor whose
// since_id is older than the 7-day search window) uses start_time =
// now - bootstrap_days; later runs use since_id = the highest post id seen
// (the API takes at most one of the two). The cursor advances only when every
// batch completed; a run stopped by the request cap, the post cap, HTTP 429
// or repeated 5xx/transport errors keeps the posts it got (they are billed)
// but not the new since_id, so the next run re-fetches instead of skipping,
// and cursor.last_run.stopped records the reason (like ghsa's truncated
// runs). Posts of authors not on the enabled allowlist are dropped before
// storage; every other returned post is stored as a raw record, whether or
// not it names a CVE id (the search already returned and billed it).
//
// Normalize: one social_post event per (post, CVE id in the text) and per
// (post, GHSA id in the text; the event is keyed by the GHSA id, which the
// pipeline redirects to the CVE it is an alias of, docs/ghsa.md):
// occurred_at = post created_at, url = https://x.com/<handle>/status/<id>,
// dedupe_key = post id, detail = post id, author id and handle, text, lang,
// all CVE ids of the post (and "ghsas": its GHSA ids, only when it has
// any). social_post is not a lifecycle stage; vuln_state
// ignores it (migrations/0008_xposts.sql), so a post can never move a
// vulnerability's stage. A post without a CVE id gives one model.PostNoCVE
// (table x_post_no_cve, migrations/0015_xposts_no_cve.sql), kept for linking
// to a CVE later; nothing displays it yet. That includes a post that has
// only a GHSA id: Normalize cannot tell whether the id resolves (the
// pipeline skips rows of a GHSA id with no vuln row), so such a post gives
// both its GHSA-keyed event and the no-CVE row. CVE and GHSA ids are read
// from note_tweet.text of a long post, else text (never from referenced
// posts). Every stored post also gives its links (model.PostLink, table
// x_post_link, classified by internal/xlinks) and the users it quotes,
// replies to or mentions (model.CandidateRef, allowlist candidates;
// migrations/0019_xposts_links_candidates.sql).
//
// Raw payload: {"post": <post>, "author": <includes.users object or null>,
// "referenced": [{"type": "quoted"|"replied_to", "post": <includes.tweets
// object or null>, "author": <its includes.users object or null>}, ...]}
// ("referenced" only when the post references any). Records stored before
// the request asked for entities / referenced posts have only post and
// author and still normalize (their t.co links are stored as pending).
//
// TODO: posts deleted upstream are not re-checked or removed.
package xposts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlinks"
)

// Name is the source name (raw_record.source, event.source, collector_state.source).
const Name = "xposts"

// Constants.
const (
	SearchURL = "https://api.x.com/2/tweets/search/recent"
	TokenEnv  = "NDAY_X_BEARER_TOKEN"

	PageSize    = 100 // max_results maximum
	MinPageSize = 10  // max_results minimum
	// SearchWindow is how far back recent search reaches.
	SearchWindow = 7 * 24 * time.Hour
	// WindowMargin keeps start_time / since_id safely inside the window.
	WindowMargin = time.Hour
	// MaxAttempts per request for 5xx / transport errors (each counts
	// against max_requests). 429 is never retried.
	MaxAttempts = 3
	BackoffBase = 2 * time.Second
	MaxBodyByte = 16 << 20

	// TweetFields / Expansions of every search request: the links
	// (entities), long posts (note_tweet), and the posts this one quotes or
	// replies to with their authors (referenced_tweets; includes.tweets /
	// includes.users). user.fields is always "username".
	TweetFields = "author_id,created_at,lang,entities,note_tweet,referenced_tweets"
	Expansions  = "author_id,referenced_tweets.id,referenced_tweets.id.author_id,entities.mentions.username"

	// snowflakeEpochMS is the X id epoch (ms); id>>22 is ms since it.
	snowflakeEpochMS = 1288834974657
)

// cveRe finds CVE ids in free text: ASCII, case-insensitive, word-bounded.
var cveRe = regexp.MustCompile(`(?i)\bCVE-([0-9]{4})-([0-9]{4,19})\b`)

var postIDRe = regexp.MustCompile(`^[0-9]{1,19}$`)

// ghsaRe finds GHSA ids in free text (also inside github.com/advisories/...
// URLs): ASCII, case-insensitive, word-bounded; ExtractGHSAs validates.
var ghsaRe = regexp.MustCompile(`(?i)\bGHSA-([a-z0-9]{4})-([a-z0-9]{4})-([a-z0-9]{4})\b`)

// ExtractGHSAs returns the GHSA ids in text in canonical form ("GHSA-" in
// upper case, the groups in lower case; model.IsGHSAID), deduplicated, in
// order of first appearance. Ids with letters outside GitHub's alphabet are
// not ids and are left out.
func ExtractGHSAs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range ghsaRe.FindAllStringSubmatch(text, -1) {
		id := "GHSA-" + strings.ToLower(m[1]+"-"+m[2]+"-"+m[3])
		if !seen[id] && model.IsGHSAID(id) {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// ExtractCVEs returns the CVE ids in text, upper-cased, deduplicated, in
// order of first appearance.
func ExtractCVEs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveRe.FindAllStringSubmatch(text, -1) {
		id := "CVE-" + m[1] + "-" + m[2]
		if !seen[id] && model.IsValidCVEID(id) {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Query suffix and per-account term.
const (
	queryHead = "("
	queryTail = ") (CVE OR GHSA) -is:retweet"
	orSep     = " OR "
)

// BuildQueries packs the accounts (in the given order) into as few queries
// as fit in maxLen characters each.
func BuildQueries(accounts []xconfig.Account, maxLen int) ([]string, error) {
	var out []string
	var cur []string
	size := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, queryHead+strings.Join(cur, orSep)+queryTail)
			cur, size = nil, 0
		}
	}
	fixed := len(queryHead) + len(queryTail)
	for _, a := range accounts {
		term := "from:" + a.Handle
		if fixed+len(term) > maxLen {
			return nil, fmt.Errorf("xposts: query for one account (%s) is longer than max_query_length %d", a.UserID, maxLen)
		}
		add := len(term)
		if len(cur) > 0 {
			add += len(orSep)
		}
		if fixed+size+add > maxLen {
			flush()
			add = len(term)
		}
		cur = append(cur, term)
		size += add
	}
	flush()
	return out, nil
}

// Options configures New.
type Options struct {
	Transport http.RoundTripper
	Env       collector.Env
	Clock     func() time.Time
	Sleep     func(ctx context.Context, d time.Duration) error
	Logger    *slog.Logger
	// Accounts / Settings: used when Prepare is not called (tests, tools).
	Accounts []xconfig.Account
	Settings *xconfig.Settings
}

// Collector implements collector.Collector and collector.Preparer.
type Collector struct {
	token    string // never logged, never in errors or the cursor
	clock    func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
	logger   *slog.Logger
	client   *httpc.Client
	accounts []xconfig.Account
	settings xconfig.Settings

	RequestsMade int
	PostsSeen    int
	rate         *pyjson.Object
}

// New builds the collector.
func New(o Options) (*Collector, error) {
	var tok string
	if o.Env != nil {
		tok, _ = o.Env(TokenEnv)
	}
	tok = strings.TrimSpace(tok)
	for i := 0; i < len(tok); i++ {
		if tok[i] < 0x21 || tok[i] > 0x7e {
			return nil, fmt.Errorf("%s contains characters not allowed in an HTTP header", TokenEnv)
		}
	}
	c := &Collector{token: tok, clock: o.Clock, sleep: o.Sleep, logger: o.Logger,
		accounts: o.Accounts, settings: xconfig.Defaults, rate: pyjson.NewObject()}
	if o.Settings != nil {
		c.settings = *o.Settings
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.logger == nil {
		c.logger = slog.Default()
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
	// One attempt per Get: this package does its own retry accounting so
	// every HTTP request counts against max_requests and 429 is never retried.
	c.client = httpc.New(httpc.Options{Transport: o.Transport, MaxAttempts: 1, MaxBytes: MaxBodyByte,
		ReadTimeout: 60 * time.Second, Logger: c.logger})
	return c, nil
}

// Factory is the registry entry.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport, Env: d.Env})
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// HasToken reports whether a token is configured.
func (c *Collector) HasToken() bool { return c.token != "" }

// Settings returns the settings the next Fetch uses.
func (c *Collector) Settings() xconfig.Settings { return c.settings }

// Prepare implements collector.Preparer: loads the enabled allowlist and the
// settings (clamped into the hard bounds) from the database.
func (c *Collector) Prepare(ctx context.Context, conn *pgx.Conn) error {
	s, warns, err := xconfig.GetSettings(ctx, conn)
	if err != nil {
		return fmt.Errorf("xposts: read x_settings: %w", err)
	}
	for _, w := range warns {
		c.logger.Warn("xposts: " + w)
	}
	accts, err := xconfig.ListEnabledAccounts(ctx, conn)
	if err != nil {
		return fmt.Errorf("xposts: read x_accounts: %w", err)
	}
	c.settings, c.accounts = s, accts
	return nil
}

// ------------------------------------------------------------------ HTTP

type stopReason struct {
	reason string
	info   *pyjson.Object
}

func (c *Collector) noteRate(h http.Header) {
	for _, k := range []string{"limit", "remaining", "reset"} {
		if v := strings.TrimSpace(h.Get("x-rate-limit-" + k)); postIDRe.MatchString(v) {
			n, _ := new(big.Int).SetString(v, 10)
			c.rate.Set(k, pyjson.Int(n.String()))
		}
	}
}

func (c *Collector) rateInfo(status int) *pyjson.Object {
	o := pyjson.NewObject()
	o.Set("status", status)
	for _, k := range c.rate.Keys() {
		o.Set(k, c.rate.Get(k))
	}
	return o
}

// problemText extracts title/detail of an X API error body (no secrets in it).
func problemText(body []byte) string {
	v, err := pyjson.Decode(body)
	if err != nil {
		return ""
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		return ""
	}
	var parts []string
	for _, k := range []string{"title", "detail"} {
		if s, ok := o.Get(k).(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	s := strings.Join(parts, ": ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "..."
	}
	return s
}

// get performs one logical GET: a 2xx response, a stop, or a fatal error.
func (c *Collector) get(ctx context.Context, u string) (*httpc.Response, *stopReason, error) {
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.token)
	hdr.Set("Accept", "application/json")
	for attempt := 1; ; attempt++ {
		if c.RequestsMade >= c.settings.MaxRequests {
			info := pyjson.NewObject()
			info.Set("max_requests", c.settings.MaxRequests)
			return nil, &stopReason{"request_cap", info}, nil
		}
		c.RequestsMade++
		resp, err := c.client.Get(ctx, u, httpc.GetOptions{Header: hdr, Accept: func(int) bool { return true }})
		retry := ""
		switch {
		case err != nil:
			var tl *httpc.TooLargeError
			if ctx.Err() != nil || errors.As(err, &tl) {
				return nil, nil, err
			}
			retry = "transport_error"
		case resp.Status >= 200 && resp.Status < 300:
			c.noteRate(resp.Header)
			return resp, nil, nil
		case resp.Status == http.StatusTooManyRequests:
			c.noteRate(resp.Header)
			return nil, &stopReason{"rate_limited", c.rateInfo(resp.Status)}, nil
		case resp.Status >= 500:
			c.noteRate(resp.Header)
			retry = "server_error"
		default:
			msg := fmt.Sprintf("xposts: GET %s: HTTP %d", u, resp.Status)
			if p := problemText(resp.Body); p != "" {
				msg += " (" + p + ")"
			}
			return nil, nil, errors.New(msg)
		}
		if attempt >= MaxAttempts {
			info := pyjson.NewObject()
			if err != nil {
				info.Set("error", err.Error())
			} else {
				info.Set("status", resp.Status)
			}
			return nil, &stopReason{retry, info}, nil
		}
		delay := BackoffBase << (attempt - 1)
		c.logger.Warn(fmt.Sprintf("xposts: %s on search request, retry %d in %s", retry, attempt, delay))
		if err := c.sleep(ctx, delay); err != nil {
			return nil, nil, err
		}
	}
}

// ------------------------------------------------------------------ fetch

func searchURL(query string, maxResults int, sinceID string, start time.Time, next string) string {
	v := url.Values{}
	v.Set("query", query)
	v.Set("max_results", fmt.Sprint(maxResults))
	v.Set("tweet.fields", TweetFields)
	v.Set("expansions", Expansions)
	v.Set("user.fields", "username")
	if sinceID != "" {
		v.Set("since_id", sinceID)
	} else {
		v.Set("start_time", start.UTC().Format(time.RFC3339))
	}
	if next != "" {
		v.Set("pagination_token", next)
	}
	return SearchURL + "?" + v.Encode()
}

// idLess compares decimal ids without leading zeros numerically.
func idLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// idTime is the creation time encoded in an X (snowflake) id.
func idTime(id string) (time.Time, bool) {
	n, ok := new(big.Int).SetString(id, 10)
	if !ok || !n.IsUint64() {
		return time.Time{}, false
	}
	ms := int64(n.Uint64()>>22) + snowflakeEpochMS
	return time.UnixMilli(ms).UTC(), true
}

func cursorSinceID(cur any) string {
	o, ok := cur.(*pyjson.Object)
	if !ok {
		return ""
	}
	s, _ := o.Get("since_id").(string)
	if !postIDRe.MatchString(s) {
		return ""
	}
	return s
}

func newCursor(sinceID string, lastRun *pyjson.Object) *pyjson.Object {
	o := pyjson.NewObject()
	if sinceID == "" {
		o.Set("since_id", nil)
	} else {
		o.Set("since_id", sinceID)
	}
	o.Set("last_run", lastRun)
	return o
}

// Fetch implements collector.Collector.
func (c *Collector) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	now := c.clock().UTC().Truncate(time.Second)
	nowZ := now.Format(time.RFC3339)
	oldSince := cursorSinceID(state.Cursor)
	lr := pyjson.NewObject()
	lr.Set("at", nowZ)

	skip := ""
	switch {
	case !c.settings.Enabled:
		skip = "disabled"
	case c.token == "":
		skip = "no_token"
	case len(c.accounts) == 0:
		skip = "no_accounts"
	}
	if skip != "" {
		c.logger.Warn(fmt.Sprintf("xposts: skipped (%s): set %s, add enabled accounts (nday x-accounts-import) "+
			"and keep x_settings.enabled on to collect; nothing fetched", skip, TokenEnv))
		lr.Set("skipped", skip)
		return &model.FetchResult{Cursor: newCursor(oldSince, lr)}, nil
	}

	accounts := append([]xconfig.Account(nil), c.accounts...)
	sort.SliceStable(accounts, func(i, j int) bool { return idLess(accounts[i].UserID, accounts[j].UserID) })
	allowed := map[string]bool{}
	for _, a := range accounts {
		allowed[a.UserID] = true
	}
	queries, err := BuildQueries(accounts, c.settings.MaxQueryLength)
	if err != nil {
		return nil, err
	}

	// since_id when it is still inside the search window, else start_time.
	sinceID := oldSince
	if sinceID != "" {
		if t, ok := idTime(sinceID); !ok || t.Before(now.Add(-SearchWindow+WindowMargin)) {
			sinceID = ""
		}
	}
	start := now.AddDate(0, 0, -c.settings.BootstrapDays)
	if floor := now.Add(-SearchWindow + WindowMargin); start.Before(floor) {
		start = floor
	}
	if sinceID != "" {
		lr.Set("mode", "since_id")
	} else {
		lr.Set("mode", "start_time")
		lr.Set("start_time", start.Format(time.RFC3339))
	}

	records := map[string]*pyjson.Object{}
	maxID := sinceID
	posts, droppedAuthor, batchesDone := 0, 0, 0
	var stop *stopReason
batches:
	for _, q := range queries {
		next := ""
		for {
			remaining := c.settings.MaxPosts - posts
			if remaining < MinPageSize {
				info := pyjson.NewObject()
				info.Set("max_posts", c.settings.MaxPosts)
				stop = &stopReason{"post_cap", info}
				break batches
			}
			u := searchURL(q, min(PageSize, remaining), sinceID, start, next)
			resp, st, err := c.get(ctx, u)
			if err != nil {
				return nil, err
			}
			if st != nil {
				stop = st
				break batches
			}
			body, err := pyjson.Decode(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("xposts: search response is not JSON: %w", err)
			}
			obj, ok := body.(*pyjson.Object)
			if !ok {
				return nil, errors.New("xposts: search response is not a JSON object")
			}
			users, tweets := map[string]any{}, map[string]*pyjson.Object{}
			if inc, ok := obj.Get("includes").(*pyjson.Object); ok {
				ul, _ := inc.Get("users").([]any)
				for _, u := range ul {
					if uo, ok := u.(*pyjson.Object); ok {
						if id, ok := uo.Get("id").(string); ok {
							users[id] = uo
						}
					}
				}
				tl, _ := inc.Get("tweets").([]any)
				for _, tw := range tl {
					if to, ok := tw.(*pyjson.Object); ok {
						if id, ok := to.Get("id").(string); ok {
							tweets[id] = to
						}
					}
				}
			}
			data, _ := obj.Get("data").([]any)
			posts += len(data)
			c.PostsSeen += len(data)
			for _, d := range data {
				p, ok := d.(*pyjson.Object)
				if !ok {
					return nil, errors.New("xposts: search data item is not an object")
				}
				id, _ := p.Get("id").(string)
				if !postIDRe.MatchString(id) {
					return nil, fmt.Errorf("xposts: post without a valid id: %s", truncRunes(pyjson.Repr(p.Get("id")), 60))
				}
				if maxID == "" || idLess(maxID, id) {
					maxID = id
				}
				aid, _ := p.Get("author_id").(string)
				if !allowed[aid] {
					droppedAuthor++
					continue
				}
				// Posts without a CVE id are stored too (already fetched and
				// billed); Normalize sends them to x_post_no_cve, not event.
				payload := pyjson.NewObject()
				payload.Set("post", p)
				payload.Set("author", users[aid])
				if refs := referenced(p, tweets, users); len(refs) > 0 {
					payload.Set("referenced", refs)
				}
				records[id] = payload
			}
			meta, _ := obj.Get("meta").(*pyjson.Object)
			next = ""
			if meta != nil {
				next, _ = meta.Get("next_token").(string)
			}
			if next == "" {
				break
			}
		}
		batchesDone++
	}

	newSince := oldSince
	if stop == nil {
		newSince = maxID
		if newSince == "" {
			newSince = oldSince
		}
	} else {
		c.logger.Warn(fmt.Sprintf("xposts: stopped early (%s) after %d of %d batch(es), %d request(s), %d post(s); "+
			"cursor not advanced, the next run re-fetches. %s", stop.reason, batchesDone, len(queries),
			c.RequestsMade, posts, pyjson.Repr(stop.info)))
	}
	lr.Set("accounts", len(accounts))
	lr.Set("batches", len(queries))
	lr.Set("batches_done", batchesDone)
	lr.Set("http_requests", c.RequestsMade)
	lr.Set("posts", posts)
	// kept = stored posts that name a CVE id (event rows; same meaning as
	// before 0015), kept_no_cve = stored posts that name none (x_post_no_cve;
	// these were "dropped_no_cve" before). kept + kept_no_cve = records.
	// kept_ghsa_only (a subset of kept_no_cve) = those that name a GHSA id:
	// they also give a GHSA-keyed event.
	keptNoCVE, keptGHSAOnly := 0, 0
	for _, r := range records {
		t := cveText(r.Get("post").(*pyjson.Object))
		if len(ExtractCVEs(t)) == 0 {
			keptNoCVE++
			if len(ExtractGHSAs(t)) > 0 {
				keptGHSAOnly++
			}
		}
	}
	lr.Set("kept", len(records)-keptNoCVE)
	lr.Set("kept_no_cve", keptNoCVE)
	lr.Set("kept_ghsa_only", keptGHSAOnly)
	lr.Set("dropped_author", droppedAuthor)
	if stop != nil {
		lr.Set("stopped", stop.reason)
		lr.Set("stop_info", stop.info)
	} else {
		lr.Set("stopped", nil)
	}
	rl := pyjson.NewObject()
	for _, k := range c.rate.Keys() {
		rl.Set(k, c.rate.Get(k))
	}
	lr.Set("rate_limit", rl)

	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return idLess(keys[i], keys[j]) })
	raw := make([]model.RawRecord, 0, len(keys))
	for _, k := range keys {
		raw = append(raw, model.RawRecord{Source: Name, SourceKey: k, Payload: records[k]})
	}
	return &model.FetchResult{Records: raw, Cursor: newCursor(newSince, lr)}, nil
}

// referenced is the payload's "referenced" list: for each referenced_tweets
// entry of the post, {"type", "post": the includes.tweets object or null,
// "author": its includes.users object or null}, in the API's order.
func referenced(p *pyjson.Object, tweets map[string]*pyjson.Object, users map[string]any) []any {
	rl, _ := p.Get("referenced_tweets").([]any)
	var out []any
	for _, r := range rl {
		ro, ok := r.(*pyjson.Object)
		if !ok {
			continue
		}
		id, _ := ro.Get("id").(string)
		e := pyjson.NewObject()
		e.Set("type", ro.Get("type"))
		var author any
		if t, ok := tweets[id]; ok {
			e.Set("post", t)
			if aid, ok := t.Get("author_id").(string); ok {
				author = users[aid]
			}
		} else {
			e.Set("post", nil)
		}
		e.Set("author", author)
		out = append(out, e)
	}
	return out
}

func truncRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// ------------------------------------------------------------------ normalize

var handleRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`)

// PostURL is the public link of a post.
func PostURL(handle, id string) string {
	if handleRe.MatchString(handle) {
		return "https://x.com/" + handle + "/status/" + id
	}
	return "https://x.com/i/web/status/" + id
}

// Normalize implements collector.Collector (pure).
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, ok := rec.Payload.(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload is not a JSON object")
	}
	post, ok := p.Get("post").(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload.post is not an object")
	}
	id, _ := post.Get("id").(string)
	if !postIDRe.MatchString(id) || id != rec.SourceKey {
		return nil, collector.NormalizeErrorf("bad post id %s for source_key %s", pyjson.Repr(post.Get("id")), rec.SourceKey)
	}
	aid, _ := post.Get("author_id").(string)
	if !postIDRe.MatchString(aid) {
		return nil, collector.NormalizeErrorf("bad author_id: %s", pyjson.Repr(post.Get("author_id")))
	}
	ca, _ := post.Get("created_at").(string)
	created, err := time.Parse(time.RFC3339Nano, ca)
	if err != nil {
		return nil, collector.NormalizeErrorf("bad created_at: %s", pyjson.Repr(post.Get("created_at")))
	}
	created = created.UTC()
	text, ok := post.Get("text").(string)
	if !ok {
		return nil, collector.NormalizeErrorf("post text is not a string")
	}
	var handle any
	h := ""
	if a, ok := p.Get("author").(*pyjson.Object); ok {
		if u, ok := a.Get("username").(string); ok {
			handle, h = u, u
		}
	}
	ptext := cveText(post)
	cves, ghsas := ExtractCVEs(ptext), ExtractGHSAs(ptext)
	n := &model.Normalized{PostLinks: postLinks(id, post), CandidateRefs: candidateRefs(p, post, id, aid, created)}
	link := PostURL(h, id)
	if len(cves) == 0 {
		// no CVE id: one x_post_no_cve row (and, below, one event per GHSA id
		// the post names, if any: the pipeline writes it only when the GHSA id
		// resolves to a vuln, so the row keeps the post either way)
		pn := model.PostNoCVE{PostID: id, AuthorID: aid, Text: text, PostedAt: created, URL: link}
		if handle != nil {
			pn.AuthorHandle = model.Ptr(h)
		}
		if l, ok := post.Get("lang").(string); ok {
			pn.Lang = model.Ptr(l)
		}
		n.PostsNoCVE = []model.PostNoCVE{pn}
	}
	all := make([]any, len(cves))
	for i, cve := range cves {
		all[i] = cve
	}
	// Every event of the post has the same detail, so a CVE and a GHSA id of
	// one vulnerability (both rows end on the same CVE after the pipeline's
	// redirect, with the same dedupe key) are one event: the second insert is
	// a no-op conflict.
	var allGHSA []any
	for _, g := range ghsas {
		allGHSA = append(allGHSA, g)
	}
	for _, cve := range append(append([]string(nil), cves...), ghsas...) {
		detail := map[string]any{
			"post_id":       id,
			"author_id":     aid,
			"author_handle": handle,
			"text":          text,
			"lang":          post.Get("lang"),
			"cves":          all,
		}
		if len(allGHSA) > 0 {
			detail["ghsas"] = allGHSA
		}
		n.Events = append(n.Events, model.Event{
			CVEID:      cve,
			Type:       model.EventSocialPost,
			Source:     Name,
			OccurredAt: model.Ptr(created),
			URL:        model.Ptr(link),
			DedupeKey:  id,
			Detail:     detail,
		})
	}
	return n, nil
}

// cveText is the text CVE and GHSA ids are read from: note_tweet.text of a long post
// (the full text; "text" is cut short), else text. Referenced posts are never
// read.
func cveText(post *pyjson.Object) string {
	if nt, ok := post.Get("note_tweet").(*pyjson.Object); ok {
		if t, ok := nt.Get("text").(string); ok {
			return t
		}
	}
	t, _ := post.Get("text").(string)
	return t
}

// entityLists returns the post's entities.<key> arrays: note_tweet's first
// (the full text of a long post), then the post's own.
func entityLists(post *pyjson.Object, key string) [][]any {
	var out [][]any
	add := func(o *pyjson.Object) {
		if ents, ok := o.Get("entities").(*pyjson.Object); ok {
			if l, ok := ents.Get(key).([]any); ok {
				out = append(out, l)
			}
		}
	}
	if nt, ok := post.Get("note_tweet").(*pyjson.Object); ok {
		add(nt)
	}
	add(post)
	return out
}

// tcoRe finds t.co short links in the text of raw records without entities.
var tcoRe = regexp.MustCompile(`https://t\.co/[A-Za-z0-9]+`)

func nonEmpty(o *pyjson.Object, k string) *string {
	if s, ok := o.Get(k).(string); ok && s != "" {
		return model.Ptr(s)
	}
	return nil
}

// postLinks: one model.PostLink per distinct short link of the post, in
// order (note_tweet's entities first, then the post's; de-duplicated by
// short link). From the entities: status "ok" with final_url = unwound_url
// if present else expanded_url (status "pending" if neither). Raw records
// without entities (stored before the collector asked for them): every
// https://t.co/<alnum> in the text, status "pending" (nday x-links-resolve).
func postLinks(id string, post *pyjson.Object) []model.PostLink {
	var out []model.PostLink
	seen := map[string]bool{}
	add := func(l model.PostLink) {
		if seen[l.ShortURL] {
			return
		}
		seen[l.ShortURL] = true
		l.PostID, l.Pos, l.Origin = id, len(out), "api"
		out = append(out, l)
	}
	_, hasEnt := post.Get("entities").(*pyjson.Object)
	_, hasNote := post.Get("note_tweet").(*pyjson.Object)
	if !hasEnt && !hasNote {
		text, _ := post.Get("text").(string)
		for _, u := range tcoRe.FindAllString(text, -1) {
			add(model.PostLink{ShortURL: u, Kind: xlinks.KindOther, Status: "pending"})
		}
		return out
	}
	for _, list := range entityLists(post, "urls") {
		for _, e := range list {
			eo, ok := e.(*pyjson.Object)
			if !ok {
				continue
			}
			short := nonEmpty(eo, "url")
			if short == nil {
				continue
			}
			l := model.PostLink{ShortURL: *short, ExpandedURL: nonEmpty(eo, "expanded_url"), Title: nonEmpty(eo, "title"),
				Kind: xlinks.KindOther, Status: "pending"}
			l.FinalURL = nonEmpty(eo, "unwound_url")
			if l.FinalURL == nil {
				l.FinalURL = l.ExpandedURL
			}
			if l.FinalURL != nil {
				host, kind := xlinks.Classify(*l.FinalURL, id)
				if host != "" {
					l.Host = model.Ptr(host)
				}
				l.Kind, l.Status = kind, "ok"
			}
			add(l)
		}
	}
	return out
}

// candidateRefs: the users the post quotes or replies to (the "referenced"
// list of the payload: the referenced post's author_id, else its author
// object's id) and mentions (entities.mentions of the post and of
// note_tweet), one per (user, kind), skipping the post's own author and
// entries without a valid numeric user id. The handle is kept only when it
// is a valid handle; display code must still check it with
// xconfig.ValidHandle (it is upstream text).
func candidateRefs(p, post *pyjson.Object, id, aid string, posted time.Time) []model.CandidateRef {
	var out []model.CandidateRef
	seen := map[string]bool{}
	add := func(uid, handle, kind string) {
		if !xconfig.ValidUserID(uid) || uid == aid || seen[uid+" "+kind] {
			return
		}
		seen[uid+" "+kind] = true
		r := model.CandidateRef{UserID: uid, PostID: id, ReferrerID: aid, Kind: kind, PostedAt: posted}
		if xconfig.ValidHandle(handle) {
			r.Handle = model.Ptr(handle)
		}
		out = append(out, r)
	}
	refs, _ := p.Get("referenced").([]any)
	for _, r := range refs {
		ro, ok := r.(*pyjson.Object)
		if !ok {
			continue
		}
		kind, _ := ro.Get("type").(string)
		if kind != "quoted" && kind != "replied_to" {
			continue
		}
		uid, handle := "", ""
		if rp, ok := ro.Get("post").(*pyjson.Object); ok {
			uid, _ = rp.Get("author_id").(string)
		}
		if a, ok := ro.Get("author").(*pyjson.Object); ok {
			aid2, _ := a.Get("id").(string)
			if uid == "" {
				uid = aid2
			}
			if aid2 == uid {
				handle, _ = a.Get("username").(string)
			}
		}
		add(uid, handle, kind)
	}
	for _, list := range entityLists(post, "mentions") {
		for _, m := range list {
			if mo, ok := m.(*pyjson.Object); ok {
				uid, _ := mo.Get("id").(string)
				handle, _ := mo.Get("username").(string)
				add(uid, handle, "mentioned")
			}
		}
	}
	return out
}

// compile-time interface checks
var (
	_ collector.Collector = (*Collector)(nil)
	_ collector.Preparer  = (*Collector)(nil)
)
