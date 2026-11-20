package ghrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/researchsql"
)

// Discovery through the GitHub search API (GET /search/repositories;
// docs/github.md "Discovery"): a scan for new repositories whose name
// carries a CVE id of the current or previous year, and a targeted search
// for the CVEs that are hot right now. Results are stored straight from the
// search response (no request per repository) through observe: the
// identity with the result's GitHub id is updated, or a new one starts
// 'unverified' with first_source 'search'. A search result never grants
// trust and never changes another identity's id or status. A fork under
// MinForkStars stars that we have no row for isn't stored at all.

// Search limits. GitHub allows 10 search requests a minute without a token
// and 30 with one (docs.github.com/en/rest/search/search, "Rate limit").
const (
	// SearchPerPage is per_page (GitHub's maximum).
	SearchPerPage = 100
	// SearchResultCap: GitHub returns at most this many results of one
	// search, whatever total_count says.
	SearchResultCap = 1000
	// SearchSpacingAnon and SearchSpacingAuth are the waits between two
	// requests. Any 60 seconds then hold at most floor(60/7)+1 = 9 requests
	// without a token (limit 10) and floor(60/2.5)+1 = 25 with one (limit 30).
	SearchSpacingAnon = 7 * time.Second
	SearchSpacingAuth = 2500 * time.Millisecond
	// SearchRequestTimeout bounds one search request (no redirects are
	// followed: Client.Search).
	SearchRequestTimeout = 15 * time.Second
	// MaxRunTime bounds a whole Discover run (requests and waits; it then
	// stops cleanly, TimedOut). The systemd unit allows 20 minutes; the
	// worst case without this bound would be 100 × (15 s + 7 s) ≈ 37 min.
	MaxRunTime = 15 * time.Minute
	// DefaultMaxRequests is the request cap of one Discover run (scan pages
	// and CVE searches together); MaxMaxRequests is the most a caller may ask
	// for. 40 requests at SearchSpacingAnon take about 4.6 minutes.
	DefaultMaxRequests = 40
	MaxMaxRequests     = 100
	// DefaultScanPages caps the scan's share of a run (both years; at least
	// a third of it is kept for the previous year).
	DefaultScanPages = 10
	// DefaultHotCVEs caps the ids (CVE and GHSA) searched in one run.
	DefaultHotCVEs = 30
	// GHSAScanPages is the fixed share of the scan budget that the scan for
	// names containing "GHSA" gets in a run (taken out of ScanPages when
	// that is 3 or more; with less, every third hour). GitHub has a few
	// hundred such repositories in all, so one page a run keeps up.
	GHSAScanPages = 1
	// ghsaScanKey is the scan key of that scan (github_search_scan).
	ghsaScanKey = "name:GHSA"
	// ScanIncompleteRetries: a one-minute window that ends with
	// incomplete_results on this many consecutive runs is passed (logged,
	// counted in ScanDropped), so one window cannot stop a scan for good.
	ScanIncompleteRetries = 3
	// ResearchAfter: a CVE whose search succeeded is not searched again for
	// this long. A failed search is retried after 1, 2, 4, 8, 16, then
	// every 24 hours (failures counted in github_search_cve).
	ResearchAfter = 24 * time.Hour
	// ScanLag keeps the scan this far behind now (time for GitHub to index a
	// new repository); ScanBootstrap is how far back a new scan key starts.
	ScanLag       = time.Hour
	ScanBootstrap = 3 * 24 * time.Hour
	// hotPool is how many CVEs each source of "hot" contributes (the first
	// page of /discussed and of /hot: site.DefaultHotLimit).
	hotPool = 50
	// hotWindow is the window of the hot list's default since=7d (the
	// discussed source uses the researcher window, researchsql.Window).
	hotWindow = 7 * 24 * time.Hour
	// scanMinWindow: a scan window is not halved below this.
	scanMinWindow = time.Minute
	// SearchSource is first_source of rows created by Discover.
	SearchSource = "search"
	// DiscoverLockID is the first key of the session advisory lock that
	// Discover and FetchPending share, so two GitHub passes never run at
	// once ("ndGH"); the second key is hashtext(current_schema()), so
	// isolated schemas (tests) do not share it.
	DiscoverLockID int32 = 0x6E644748
)

// tryLock takes the GitHub pass lock (DiscoverLockID) without waiting.
func tryLock(ctx context.Context, db DB) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext(current_schema()))`, DiscoverLockID).Scan(&ok)
	return ok, err
}

// unlock releases it (also when ctx is done).
func unlock(ctx context.Context, db DB) {
	_, _ = db.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1, hashtext(current_schema()))`, DiscoverLockID)
}

// searchTime is the time format of created: qualifiers (UTC).
const searchTime = "2006-01-02T15:04:05Z"

var cveIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// ScanQuery is the q of the new-repository scan for year: repositories
// whose name has the token "CVE-<year>", forks included, created in
// [lo, hi] (UTC, second precision, both ends inclusive). Only year, lo and
// hi vary; year must be 1999..9999.
func ScanQuery(year int, lo, hi time.Time) (string, error) {
	if year < 1999 || year > 9999 {
		return "", fmt.Errorf("ghrepo: scan year %d", year)
	}
	return fmt.Sprintf("CVE-%04d in:name fork:true created:%s..%s", year, lo.UTC().Format(searchTime), hi.UTC().Format(searchTime)), nil
}

// GHSAScanQuery is the q of the new-repository scan for names with the
// token "GHSA" (names like GHSA-xxxx-xxxx-xxxx-poc; forks included),
// created in [lo, hi]. Only lo and hi vary.
func GHSAScanQuery(lo, hi time.Time) string {
	return fmt.Sprintf("GHSA in:name fork:true created:%s..%s", lo.UTC().Format(searchTime), hi.UTC().Format(searchTime))
}

// GHSAQuery is the q of the targeted search for one GHSA id: the id in the
// name or description, forks included. The id is the only variable part
// and must be a canonical GHSA id (model.IsGHSAID: "GHSA-" and three
// groups of four characters from GitHub's alphabet), so no other qualifier
// can get in.
func GHSAQuery(id string) (string, error) {
	if !model.IsGHSAID(id) {
		return "", fmt.Errorf("ghrepo: not a GHSA id")
	}
	return id + " in:name,description fork:true", nil
}

// IDQuery is CVEQuery or GHSAQuery, by the form of id.
func IDQuery(id string) (string, error) {
	if strings.HasPrefix(id, "GHSA-") {
		return GHSAQuery(id)
	}
	return CVEQuery(id)
}

// CVEQuery is the q of the targeted search for one CVE: the id in the name
// or description, forks included. The id is the only variable part and must
// match ^CVE-[0-9]{4}-[0-9]{4,19}$, so no other qualifier can get in.
func CVEQuery(cve string) (string, error) {
	if !cveIDRe.MatchString(cve) {
		return "", fmt.Errorf("ghrepo: not a CVE id")
	}
	return cve + " in:name,description fork:true", nil
}

// SearchPath is the request path of one search page: q, sort (descending;
// "" = best match), per_page SearchPerPage and page, URL-encoded.
func SearchPath(q, sort string, page int) string {
	v := url.Values{}
	v.Set("q", q)
	if sort != "" {
		v.Set("sort", sort)
		v.Set("order", "desc")
	}
	v.Set("per_page", strconv.Itoa(SearchPerPage))
	v.Set("page", strconv.Itoa(page))
	return "/search/repositories?" + v.Encode()
}

// SearchPage is a decoded search response.
type SearchPage struct {
	Total      int // total_count, clamped to 0..2^31-1
	Incomplete bool
	Repos      []*Repo // the items that decoded (DecodeRepo)
	Bad        int     // items that did not
}

// DecodeSearch parses a search page. total_count, incomplete_results and
// items are required, items at most SearchPerPage; anything else is
// errMalformed. Each item goes through DecodeRepo (an item that fails is
// counted in Bad and dropped).
func DecodeSearch(body []byte) (*SearchPage, error) {
	var a struct {
		Total      *int64             `json:"total_count"`
		Incomplete *bool              `json:"incomplete_results"`
		Items      *[]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, errors.Join(errMalformed, err)
	}
	if a.Total == nil || a.Incomplete == nil || a.Items == nil || len(*a.Items) > SearchPerPage {
		return nil, errMalformed
	}
	p := &SearchPage{Total: clampCount(a.Total), Incomplete: *a.Incomplete}
	for _, it := range *a.Items {
		r, err := DecodeRepo(it)
		if err != nil {
			p.Bad++
			continue
		}
		p.Repos = append(p.Repos, r)
	}
	return p, nil
}

// DiscoverOptions configures Discover.
type DiscoverOptions struct {
	// MaxRequests caps the requests of the run (<= 0: DefaultMaxRequests;
	// more than MaxMaxRequests: MaxMaxRequests).
	MaxRequests int
	// ScanPages caps the scan's requests (0: DefaultScanPages; < 0: no scan).
	ScanPages int
	// ScanGHSA: 0 = the GHSA name scan takes GHSAScanPages of the scan's
	// requests; < 0 = no GHSA scan.
	ScanGHSA int
	// HotCVEs caps the ids searched (0: DefaultHotCVEs; < 0: none).
	HotCVEs int
	// Client makes the requests; nil means NewClient with Token.
	Client *Client
	Token  string // used only when Client is nil; "" = unauthenticated
	// Spacing between requests; 0 = SearchSpacingAuth with a token, else
	// SearchSpacingAnon.
	Spacing time.Duration
	// RunTime bounds the run (0 = MaxRunTime), the review refresh included.
	RunTime time.Duration
	// RefreshLimit caps the review refresh (refreshUnverified): 0 =
	// RefreshUnverifiedLimit with a token, RefreshUnverifiedAnonLimit
	// without; < 0 = no review refresh.
	RefreshLimit int
	// RefreshSpacing between two refresh requests; 0 = RefreshSpacingAuth
	// with a token, else RefreshSpacingAnon.
	RefreshSpacing time.Duration
	// RefreshReserve: the refresh stops once the core limit reports fewer
	// requests left than this; 0 = RefreshReserveAuth with a token, else
	// RefreshReserveAnon.
	RefreshReserve int
	Now            func() time.Time
	Sleep          func(ctx context.Context, d time.Duration) error
	Logger         *slog.Logger

	decode func([]byte) (*SearchPage, error) // tests only; nil = DecodeSearch
}

// DiscoverResult counts one Discover run.
type DiscoverResult struct {
	Requests    int  `json:"requests"`
	ScanPages   int  `json:"scan_pages"`   // scan responses used
	ScanWindows int  `json:"scan_windows"` // scan windows read to the end (cursor moved)
	ScanDropped int  `json:"scan_dropped"` // results of minimal windows beyond the 1,000 cap (or incomplete) passed over
	CVEs        int  `json:"cves"`         // CVEs searched (a page parsed)
	CVEFailed   int  `json:"cve_failed"`   // CVE searches that failed (retried later, with backoff)
	Items       int  `json:"items"`        // repositories decoded from responses
	Added       int  `json:"added"`        // new rows
	Updated     int  `json:"updated"`      // known rows refreshed
	Skipped     int  `json:"skipped"`      // no CVE id in name, description or topics, or not public
	Hidden      int  `json:"hidden"`       // known repositories search reported as not public (now 'gone')
	Malformed   int  `json:"malformed"`    // items and pages that did not decode
	Failed      int  `json:"failed"`       // requests that failed (other than the rate limit)
	Incomplete  int  `json:"incomplete"`   // pages with incomplete_results
	RateLimited bool `json:"rate_limited"` // stopped on the rate limit or a 403
	TimedOut    bool `json:"timed_out"`    // stopped at RunTime
	Remaining   int  `json:"remaining"`    // the last x-ratelimit-remaining (-1 = none)
	Locked      bool `json:"locked"`       // another GitHub pass holds the lock: nothing done

	// SkippedForks: new forks under MinForkStars stars, not stored at all
	// (a fork we already have a row for is refreshed and counted in Updated)
	SkippedForks int `json:"skipped_forks"`

	// Refresh is the review refresh after the search part (refresh.go).
	Refresh RefreshResult `json:"refresh"`
}

// Discover runs the new-repository scan (current year, then the previous
// one; at most ScanPages requests, a third of them kept for the previous
// year) and then the targeted search for HotCVEs (at most HotCVEs CVEs,
// one request each), in all at most MaxRequests requests, Spacing apart,
// within RunTime minus the refresh's share (refreshShare). The search
// part stops cleanly, without an error, on any 403 or 429, after a
// response reporting 0 requests left, and at its time. Then the review
// refresh (refreshUnverified) brings the repositories waiting for review
// up to date through the core API, until RunTime. Only one
// GitHub pass at a time (DiscoverLockID, shared with FetchPending; a run
// that cannot take it returns Locked). Errors are database and context
// errors; db must be a single connection (the lock is per session).
func Discover(ctx context.Context, db DB, o DiscoverOptions) (DiscoverResult, error) {
	res := DiscoverResult{Remaining: -1, Refresh: RefreshResult{Remaining: -1}}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	o.MaxRequests = min(o.MaxRequests, MaxMaxRequests)
	if o.ScanPages == 0 {
		o.ScanPages = DefaultScanPages
	}
	if o.HotCVEs == 0 {
		o.HotCVEs = DefaultHotCVEs
	}
	if o.Client == nil {
		o.Client = NewClient(ClientOptions{Token: o.Token})
	}
	if o.Spacing <= 0 {
		o.Spacing = SearchSpacingAnon
		if o.Client.Authenticated() {
			o.Spacing = SearchSpacingAuth
		}
	}
	if o.RunTime <= 0 {
		o.RunTime = MaxRunTime
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.decode == nil {
		o.decode = DecodeSearch
	}
	locked, err := tryLock(ctx, db)
	if err != nil {
		return res, err
	}
	if !locked {
		res.Locked = true
		return res, nil
	}
	defer unlock(ctx, db)
	// the whole run has RunTime; the search part may use all of it but
	// the review refresh's share, so that one always gets its turn
	run, cancel := context.WithTimeout(ctx, o.RunTime)
	defer cancel()
	srun, scancel := context.WithTimeout(run, o.RunTime-refreshShare(o.RunTime))
	defer scancel()
	d := &discoverer{db: db, o: o, res: &res, now: o.Now().UTC(), run: srun}
	if err := d.search(ctx); err != nil {
		return res, err
	}
	// the core API has its own limit: a search part stopped by the search
	// limit or its time share doesn't stop the refresh
	if err := d.refreshUnverified(ctx, run); err != nil {
		return res, err
	}
	return res, nil
}

// search is the search part of a run: the scan, then the targeted search.
func (d *discoverer) search(ctx context.Context) error {
	o, res := d.o, d.res
	budget := o.MaxRequests
	if o.ScanPages > 0 {
		scan := min(o.ScanPages, budget)
		// the GHSA name scan: a fixed share, set aside first so the year
		// scans cannot starve it and it cannot take more from them; with a
		// scan budget under 3 it runs every third hour instead
		ghsa := 0
		if o.ScanGHSA >= 0 && (scan >= 3 || d.now.Hour()%3 == 2) {
			ghsa = min(GHSAScanPages, scan)
		}
		scan -= ghsa
		y := d.now.Year()
		years := []int{y, y - 1}
		if scan < 2 && d.now.Hour()%2 == 1 {
			years = []int{y - 1, y} // one page: alternate the years
		}
		// the first year may use all but a third of the share; the second
		// gets what is left (at least that third)
		first := scan - scan/3
		for i, year := range years {
			share := first
			if i == 1 {
				share = scan
			}
			if share <= 0 {
				continue
			}
			before := res.Requests
			if err := d.scanYear(ctx, year, &share); err != nil {
				return err
			}
			used := res.Requests - before
			scan -= used
			budget -= used
			if d.stop {
				return nil
			}
		}
		if ghsa > 0 {
			before := res.Requests
			if err := d.scan(ctx, ghsaScanKey, func(lo, hi time.Time) (string, error) { return GHSAScanQuery(lo, hi), nil }, &ghsa); err != nil {
				return err
			}
			budget -= res.Requests - before
			if d.stop {
				return nil
			}
		}
	}
	if o.HotCVEs > 0 && budget > 0 {
		cves, err := HotCVEs(ctx, d.db, d.now, min(o.HotCVEs, budget))
		if err != nil {
			return err
		}
		for _, cve := range cves {
			if d.stop || budget <= 0 {
				break
			}
			if err := d.searchCVE(ctx, cve); err != nil {
				return err
			}
			budget--
		}
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type discoverer struct {
	db   DB
	o    DiscoverOptions
	res  *DiscoverResult
	now  time.Time
	run  context.Context // RunTime deadline: requests and waits only
	stop bool            // no more requests in this run
}

// What a request gave (fetch).
type fetchStatus int

const (
	fetchOK      fetchStatus = iota // a page was parsed
	fetchFailed                     // the request failed (counts against the CVE)
	fetchLimited                    // the rate limit or RunTime: nothing to count
)

// fetch makes one search request (Spacing after the previous one, at most
// SearchRequestTimeout). Any 403 or 429 stops the run (secondary limits
// may come without headers): with rate-limit headers it is fetchLimited,
// a bare 403 fetchFailed. A response reporting 0 requests left is used and
// stops the run. err is a context error of ctx only.
func (d *discoverer) fetch(ctx context.Context, path string) (*SearchPage, fetchStatus, error) {
	timedOut := func() (*SearchPage, fetchStatus, error) {
		if ctx.Err() != nil {
			return nil, fetchLimited, ctx.Err()
		}
		d.stop, d.res.TimedOut = true, true
		return nil, fetchLimited, nil
	}
	if d.res.Requests > 0 {
		if err := d.o.Sleep(d.run, d.o.Spacing); err != nil {
			return timedOut()
		}
	}
	if d.run.Err() != nil {
		return timedOut()
	}
	d.res.Requests++
	rctx, cancel := context.WithTimeout(d.run, SearchRequestTimeout)
	defer cancel()
	resp, gerr := d.o.Client.Search(rctx, path)
	if d.run.Err() != nil {
		return timedOut()
	}
	if resp != nil && resp.Remaining >= 0 {
		d.res.Remaining = resp.Remaining
	}
	if resp != nil && (resp.Status == http.StatusForbidden || resp.Status == http.StatusTooManyRequests) {
		d.res.RateLimited, d.stop = true, true
		if resp.RateLimited() {
			return nil, fetchLimited, nil
		}
		d.res.Failed++
		return nil, fetchFailed, nil
	}
	if resp != nil && resp.Remaining == 0 {
		d.res.RateLimited, d.stop = true, true
	}
	switch {
	case gerr != nil:
		d.res.Failed++
		d.o.Logger.Debug("github search request failed", "refused", errors.Is(gerr, ErrRefused))
		return nil, fetchFailed, nil
	case resp.Status != http.StatusOK:
		d.res.Failed++
		d.o.Logger.Debug("github search not successful", "status", resp.Status)
		return nil, fetchFailed, nil
	case resp.TooBig:
		d.res.Failed++
		d.o.Logger.Debug("github search response too large")
		return nil, fetchFailed, nil
	}
	p, err := d.o.decode(resp.Body)
	if err != nil {
		d.res.Failed++
		d.res.Malformed++
		d.o.Logger.Debug("github search response unusable")
		return nil, fetchFailed, nil
	}
	d.res.Malformed += p.Bad
	if p.Incomplete {
		d.res.Incomplete++
	}
	return p, fetchOK, nil
}

// store writes the repositories of p: public ones with at least one CVE id
// in their name, description or topics (storeSearched); a known repository
// that search reports as not public becomes 'gone' (no longer listed); the
// rest are skipped. A fork under MinForkStars stars that we have no row for
// isn't stored at all (SkippedForks): no row, no association, no name, so
// nothing gets queued for it either. One we already have (a post link, a
// staff decision) is refreshed as before.
func (d *discoverer) store(ctx context.Context, p *SearchPage) error {
	now := d.o.Now().UTC()
	for _, r := range p.Repos {
		d.res.Items++
		if !r.Public {
			d.res.Skipped++
			hidden := 0
			err := pgx.BeginFunc(ctx, d.db, func(tx pgx.Tx) error {
				if err := lockStore(ctx, tx); err != nil {
					return err
				}
				var err error
				hidden, err = markGone(ctx, tx, r.ID, true, now)
				return err
			})
			if err != nil {
				return err
			}
			d.res.Hidden += hidden
			continue
		}
		if len(r.Associations()) == 0 {
			d.res.Skipped++
			continue
		}
		added, skipped, err := storeSearched(ctx, d.db, r, now)
		if err != nil {
			return err
		}
		if skipped {
			d.res.SkippedForks++
			continue
		}
		if added {
			d.res.Added++
		} else {
			d.res.Updated++
		}
	}
	return nil
}

// scanYear reads the new-repository scan of year from its state
// (github_search_scan, key "name:CVE-<year>": created_after, window_end,
// next_page, window_total, window_incomplete; a new key starts
// ScanBootstrap before now-ScanLag), using at most *budget requests.
// GitHub cannot sort repositories by creation, so the scan reads
// creation-time windows [created_after, window_end]:
//
//   - paging a search sorted by "updated" is not stable (a push moves a
//     repository between pages), so a window is narrowed until it fits ONE
//     page: a window wider than scanMinWindow whose first page reports more
//     than SearchPerPage results, or comes back incomplete, is halved
//     (window_end persists, so a backlog keeps converging across runs).
//     Only a window of the minimum width is read page by page;
//   - a window is "read cleanly" when every page up to the last one its
//     largest reported total asks for was parsed and none came back with
//     incomplete_results; the total and the incomplete flag are kept
//     across all its pages and across runs (window_total,
//     window_incomplete). Only then created_after moves to its end; the
//     next window is at most twice as wide, up to now-ScanLag;
//   - a run that stops inside a window (budget, rate limit, failure, run
//     time) saves the page to read next and resumes there;
//   - a minimal window that was not read cleanly because a page was
//     incomplete is read again from page 1 by the next run (logged); the
//     cursor does not move;
//   - the one exception: a minimal window with more than SearchResultCap
//     results moves on after its 10 retrievable pages (if none was
//     incomplete), and the count passed over is logged and counted
//     (ScanDropped).
func (d *discoverer) scanYear(ctx context.Context, year int, budget *int) error {
	return d.scan(ctx, fmt.Sprintf("name:CVE-%04d", year), func(lo, hi time.Time) (string, error) { return ScanQuery(year, lo, hi) }, budget)
}

// scan is the window scan of one scan key with its query (scanYear's rules).
func (d *discoverer) scan(ctx context.Context, key string, query func(lo, hi time.Time) (string, error), budget *int) error {
	end := d.now.Add(-ScanLag).Truncate(time.Second)
	var lo time.Time
	var wend *time.Time
	var wtotal *int
	page, total, incomplete, retries := 1, 0, false, 0
	err := d.db.QueryRow(ctx, `SELECT created_after, window_end, next_page, window_total, window_incomplete, window_retries
        FROM github_search_scan WHERE scan_key = $1`, key).Scan(&lo, &wend, &page, &wtotal, &incomplete, &retries)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		lo, page = end.Add(-ScanBootstrap), 1
	case err != nil:
		return err
	}
	if wtotal != nil {
		total = *wtotal
	}
	lo = lo.UTC().Truncate(time.Second)
	hi := end
	if wend != nil && wend.After(lo) && !wend.After(end) {
		hi = wend.UTC().Truncate(time.Second)
	} else {
		page, retries = 1, 0 // no saved window, or it reaches past now-ScanLag: a new one
	}
	if page == 1 {
		total, incomplete = 0, false
	}
	save := func() error {
		var wt any
		if page > 1 {
			wt = total
		}
		_, err := d.db.Exec(ctx, `INSERT INTO github_search_scan (scan_key, created_after, window_end, next_page, window_total,
            window_incomplete, window_retries, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (scan_key) DO UPDATE SET created_after = EXCLUDED.created_after, window_end = EXCLUDED.window_end,
            next_page = EXCLUDED.next_page, window_total = EXCLUDED.window_total, window_incomplete = EXCLUDED.window_incomplete,
            window_retries = EXCLUDED.window_retries, updated_at = EXCLUDED.updated_at`, key, lo, hi, page, wt, incomplete && page > 1,
			retries, d.now)
		return err
	}
	for lo.Before(end) && *budget > 0 && !d.stop {
		q, err := query(lo, hi)
		if err != nil {
			return err
		}
		minimal := hi.Sub(lo) <= scanMinWindow
		if !minimal {
			page, total, incomplete, retries = 1, 0, false, 0 // a wide window is one page, never resumed
		}
		*budget--
		p, st, err := d.fetch(ctx, SearchPath(q, "updated", page))
		if err != nil {
			return err
		}
		if st != fetchOK {
			return save() // resume at this page
		}
		d.res.ScanPages++
		if err := d.store(ctx, p); err != nil {
			return err
		}
		// what the window's pages reported so far, all of them
		total = max(total, p.Total)
		incomplete = incomplete || p.Incomplete
		if !minimal && (total > SearchPerPage || incomplete) {
			hi = lo.Add(hi.Sub(lo) / 2).Truncate(time.Second)
			page, total, incomplete = 1, 0, false
			if err := save(); err != nil {
				return err
			}
			continue
		}
		pages := (min(total, SearchResultCap) + SearchPerPage - 1) / SearchPerPage
		if page < pages {
			page++
			if err := save(); err != nil { // the next page, this run or the next
				return err
			}
			continue
		}
		// the last page of the window was read
		if incomplete && retries+1 < ScanIncompleteRetries {
			retries++
			d.o.Logger.Warn("github scan: a minimal window came back incomplete; it will be read again", "scan", key,
				"from", lo, "to", hi, "total", total, "run", retries)
			page, total, incomplete = 1, 0, false
			return save()
		}
		if incomplete {
			// incomplete on ScanIncompleteRetries consecutive runs: pass it,
			// so the scan cannot be stopped for good by one window
			passed := max(total-SearchResultCap, 1)
			d.res.ScanDropped += passed
			d.o.Logger.Warn("github scan: a minimal window stayed incomplete and is passed", "scan", key, "from", lo, "to", hi,
				"total", total, "runs", ScanIncompleteRetries, "passed_over", passed)
		} else if total > SearchResultCap {
			d.res.ScanDropped += total - SearchResultCap
			d.o.Logger.Warn("github scan: results of a minimal window passed over", "scan", key, "from", lo, "to", hi,
				"total", total, "passed_over", total-SearchResultCap)
		}
		w := hi.Sub(lo)
		lo, page, total, incomplete, retries = hi, 1, 0, false, 0
		hi = lo.Add(2 * w)
		if w <= 0 || hi.After(end) {
			hi = end
		}
		d.res.ScanWindows++
		if err := save(); err != nil {
			return err
		}
	}
	return nil
}

// searchCVE makes the targeted search of one CVE (first page, by stars).
// A parsed page records the CVE as searched (github_search_cve, failures
// reset); a failed request counts a failure (retried with backoff, not
// marked searched); a rate-limit refusal or the run time records nothing.
func (d *discoverer) searchCVE(ctx context.Context, cve string) error {
	q, err := IDQuery(cve)
	if err != nil {
		return nil // HotCVEs only returns valid ids
	}
	p, st, err := d.fetch(ctx, SearchPath(q, "stars", 1))
	switch {
	case err != nil:
		return err
	case st == fetchLimited:
		return nil
	case st == fetchFailed:
		d.res.CVEFailed++
		_, err := d.db.Exec(ctx, `INSERT INTO github_search_cve (cve_id, failures, failed_at) VALUES ($1, 1, $2)
            ON CONFLICT (cve_id) DO UPDATE SET failures = github_search_cve.failures + 1, failed_at = EXCLUDED.failed_at`, cve, d.now)
		return err
	}
	if err := d.store(ctx, p); err != nil {
		return err
	}
	d.res.CVEs++
	_, err = d.db.Exec(ctx, `INSERT INTO github_search_cve (cve_id, searched_at, total_count, failures, failed_at) VALUES ($1, $2, $3, 0, NULL)
        ON CONFLICT (cve_id) DO UPDATE SET searched_at = EXCLUDED.searched_at, total_count = EXCLUDED.total_count, failures = 0, failed_at = NULL`,
		cve, d.now, p.Total)
	return err
}

// hotStages are the transition types of the hot list's default view
// (site.HotParams: MinStage patch_released and later).
var hotStages = []string{model.EventPatchReleased, model.EventAnalysisPublished, model.EventPocPublished,
	model.EventExploitedInWild, model.EventKevAdded}

// hotSQL selects the ids to search: the union of the first page of
// /discussed (site.Discussed: distinct enabled allowlisted researchers who
// posted about the CVE in the researcher window [$7, $2], the same bounds
// as site.Discussed through researchsql.Window: today and the 6 UTC days
// before; then the latest post, then the id; the hot list's pinned rows
// come from the same ranking) and the first page of /hot in its default
// view (site.Hot: a transition to patch_released or a later stage in
// [$1, $2], the last 7 days, not rejected, newest transition first), each
// at most $3 vulnerabilities (CVE-keyed or GHSA-keyed, as both lists hold
// them); for each its own id and, when it is CVE-keyed, its GHSA alias
// ids; without the ids searched after $5, and without those whose last
// failure is within their backoff (2^(failures-1) hours, at most 24); CVE
// ids before GHSA ids, then never tried first, then least recently tried,
// then discussed before hot, then rank; at most $6.
const hotSQL = `
WITH discussed AS (
  SELECT p.cve_id, count(DISTINCT p.detail->>'author_id') AS researchers, max(p.occurred_at) AS last_at
  FROM event p JOIN x_accounts xa ON xa.user_id = p.detail->>'author_id' AND xa.enabled
  WHERE p.type = 'social_post' AND p.source = 'xposts' AND p.occurred_at >= $7 AND p.occurred_at <= $2
  GROUP BY p.cve_id
  ORDER BY researchers DESC, last_at DESC, p.cve_id
  LIMIT $3
), hot AS (
  SELECT m.cve_id, m.last_transition_at, m.stage_rank FROM vuln_state_mat m
  WHERE m.last_transition_at >= $1 AND m.last_transition_at <= $2 AND m.last_transition_type = ANY($4) AND NOT m.is_rejected
  ORDER BY m.last_transition_at DESC, m.stage_rank DESC, m.cve_id DESC
  LIMIT $3
), pool AS (
  SELECT cve_id, 0 AS tier, row_number() OVER (ORDER BY researchers DESC, last_at DESC, cve_id) AS rk FROM discussed
  UNION ALL
  SELECT cve_id, 1, row_number() OVER (ORDER BY last_transition_at DESC, stage_rank DESC, cve_id DESC) FROM hot
), best AS (
  SELECT DISTINCT ON (cve_id) cve_id, tier, rk FROM pool ORDER BY cve_id, tier, rk
), ids AS (
  SELECT b.cve_id AS id, b.tier, b.rk FROM best b
  UNION ALL
  SELECT a.alias, b.tier, b.rk FROM best b JOIN vuln_alias a ON a.cve_id = b.cve_id AND a.alias_type = 'ghsa' AND a.alias <> b.cve_id
), one AS (
  SELECT DISTINCT ON (id) id, tier, rk FROM ids ORDER BY id, tier, rk
)
SELECT o.id FROM one o LEFT JOIN github_search_cve s ON s.cve_id = o.id
WHERE (o.id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$' OR o.id ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$')
  AND (s.searched_at IS NULL OR s.searched_at <= $5)
  AND (s.failures IS NULL OR s.failures = 0 OR s.failed_at IS NULL
       OR s.failed_at <= $2 - make_interval(hours => least(power(2, least(s.failures, 10) - 1)::int, 24)))
ORDER BY (o.id LIKE 'GHSA-%'), greatest(s.searched_at, s.failed_at) ASC NULLS FIRST, o.tier, o.rk, o.id
LIMIT $6`

// HotCVEs returns at most limit ids to search at now (hotSQL): for every
// hot vulnerability its own id — a CVE id, or the GHSA id of an advisory
// without a CVE — and, for a CVE-keyed one, each GHSA id that is its alias
// (normally one). Each id is searched and recorded on its own
// (github_search_cve): not searched within ResearchAfter nor failed within
// its backoff. All due CVE ids come first (least recently tried first, as
// before), then the GHSA ids in the same order: the second id never takes
// a request from a main id.
func HotCVEs(ctx context.Context, db DB, now time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	wstart, _ := researchsql.Window(now)
	rows, err := db.Query(ctx, hotSQL, now.Add(-hotWindow), now, hotPool, hotStages, now.Add(-ResearchAfter), limit, wstart)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// storeSearched stores one public repository from a search response, in
// one transaction (observe): the identity with its GitHub id is updated —
// a changed full_name is its rename — or a new one is created: the
// placeholder queued under its name becomes it, else a new row
// (first_source 'search'), 'unverified'. The name key of its full name now
// points at it. added reports a new row. A skipped fork (Repo.SkippedFork)
// with no row of its GitHub id yet writes nothing (skipped).
func storeSearched(ctx context.Context, db DB, r *Repo, now time.Time) (added, skipped bool, err error) {
	err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		added, skipped = false, false
		if err := lockStore(ctx, tx); err != nil {
			return err
		}
		if r.SkippedFork() {
			var known bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM github_repo WHERE github_id = $1)`, r.ID).Scan(&known); err != nil {
				return err
			}
			if !known {
				skipped = true
				return nil
			}
		}
		o, err := observe(ctx, tx, r, answer{source: SearchSource}, now)
		added = o.added
		return err
	})
	return added, skipped, err
}
