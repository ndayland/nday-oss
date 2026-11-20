package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup"
)

// The X posts collector module (/admin/x; docs/xposts.md, docs/admin.md).
// The configuration tables are read and written only through
// internal/xconfig; the review list reads event (source xposts, type
// social_post) directly. Reads use ReadDB; writes use AuthDB (writable),
// each in one transaction with its audit row. The bearer token is used for
// one thing only: Options.XLookup resolves a handle to its numeric user id
// when an administrator adds or imports an account (internal/xlookup); it is
// never shown, logged, stored, returned or accepted. The status comes from
// what the collector's last run wrote into its cursor.

// XSource is the collector's registry name.
const XSource = "xposts"

// XPricePerPostUSD is what X bills per post read ($0.005; see docs/xposts.md
// and the official pricing page, https://docs.x.com/x-api/getting-started/pricing,
// read 2026-11-13). Every cost on the page derives from this constant.
const XPricePerPostUSD = 0.005

// XRunsPerDay is the assumed schedule: collectors run from the shared
// systemd template deploy/systemd/nday-collect@.timer (OnCalendar=hourly),
// enabled per source with `systemctl enable --now nday-collect@xposts.timer`
// (deploy/README.md). Whether that timer is enabled on the server cannot be
// seen from here; the page says so next to the per-day figures.
const XRunsPerDay = 24

// XPostsPerPage is the API's largest page (max_results 100), so a run
// returns at most max_requests × 100 posts whatever max_posts says.
const XPostsPerPage = 100

// XWorstPostsPerRun is the most posts one run can be billed for with
// these settings: max_posts, and never more than max_requests full pages.
func XWorstPostsPerRun(s xconfig.Settings) int {
	return min(s.MaxPosts, s.MaxRequests*XPostsPerPage)
}

// XRun is the collector_state row of xposts and its cursor's last_run.
type XRun struct {
	Exists        bool
	Status        string
	LastRunAt     *time.Time
	LastSuccessAt *time.Time
	LastError     string
	At            string // last_run.at
	Skipped       string // no_token | no_accounts | disabled | ""
	Mode          string // since_id | start_time
	StartTime     string
	Accounts      *int64
	Batches       *int64
	BatchesDone   *int64
	Requests      *int64
	Posts         *int64 // returned by the API = billed
	Kept          *int64 // stored, names a CVE id (event rows)
	KeptNoCVE     *int64 // stored, names no CVE id (x_post_no_cve; not shown elsewhere)
	DroppedAuthor *int64
	Stopped       string
	StopInfo      string // compact JSON
	SinceID       string
	HasLastRun    bool
}

// XStatus reads the collector's state (admin-only: public pages never show
// xposts).
func (s *Service) XStatus(ctx context.Context) (*XRun, error) {
	r := &XRun{}
	var cur []byte
	var status, lastErr *string
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT last_status, last_run_at, last_success_at, last_error, cursor
			FROM collector_state WHERE source = $1`, XSource).Scan(&status, &r.LastRunAt, &r.LastSuccessAt, &lastErr, &cur)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	r.Exists = true
	if status != nil {
		r.Status = *status
	}
	if lastErr != nil {
		r.LastError = *lastErr
	}
	var c struct {
		SinceID *string                    `json:"since_id"`
		LastRun map[string]json.RawMessage `json:"last_run"`
	}
	if len(cur) > 0 && json.Unmarshal(cur, &c) == nil {
		if c.SinceID != nil {
			r.SinceID = *c.SinceID
		}
		lr := c.LastRun
		r.HasLastRun = lr != nil
		str := func(k string) string {
			var v string
			_ = json.Unmarshal(lr[k], &v)
			return v
		}
		num := func(k string) *int64 {
			var v int64
			if raw, ok := lr[k]; ok && json.Unmarshal(raw, &v) == nil {
				return &v
			}
			return nil
		}
		r.At, r.Skipped, r.Mode, r.StartTime, r.Stopped = str("at"), str("skipped"), str("mode"), str("start_time"), str("stopped")
		r.Accounts, r.Batches, r.BatchesDone, r.Requests = num("accounts"), num("batches"), num("batches_done"), num("http_requests")
		r.Posts, r.Kept, r.KeptNoCVE, r.DroppedAuthor = num("posts"), num("kept"), num("kept_no_cve"), num("dropped_author")
		if raw, ok := lr["stop_info"]; ok && string(raw) != "null" {
			r.StopInfo = string(raw)
		}
	}
	return r, nil
}

// XConfig is the stored settings, their effective values and the allowlist.
type XConfig struct {
	Stored    xconfig.Stored
	Effective xconfig.Settings
	Warnings  []string
	Accounts  []xconfig.Account
}

// XConfig reads the configuration (xconfig on ReadDB).
func (s *Service) XConfig(ctx context.Context) (*XConfig, error) {
	x := &XConfig{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		if x.Stored, err = xconfig.LoadSettings(ctx, c); err != nil {
			return err
		}
		x.Accounts, err = xconfig.ListAccounts(ctx, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	x.Effective, x.Warnings = x.Stored.Effective()
	return x, nil
}

// XAccountsPage is the allowlist's page size on /admin/x.
const XAccountsPage = 10

// XAccountPage is one page of the allowlist.
type XAccountPage struct {
	Accounts []xconfig.Account
	Matched  int // accounts whose handle contains the term (all of them when it is empty)
	Page     int // 1-based, after clamping
	Pages    int // at least 1
}

// XAccounts returns page page (1-based) of the accounts whose handle
// contains q (case-insensitive, literal; "" lists all), XAccountsPage per
// page in ListAccounts' order. A page below 1 is page 1 and a page past the
// last is the last page, so a non-empty match never yields an empty page.
// Count and fetch share one connection.
func (s *Service) XAccounts(ctx context.Context, q string, page int) (*XAccountPage, error) {
	p := &XAccountPage{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		if p.Matched, err = xconfig.CountAccounts(ctx, c, q); err != nil {
			return err
		}
		p.Pages = max(1, (p.Matched+XAccountsPage-1)/XAccountsPage)
		p.Page = min(max(page, 1), p.Pages)
		p.Accounts, err = xconfig.SearchAccounts(ctx, c, q, XAccountsPage, (p.Page-1)*XAccountsPage)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// XPost is one collected post (its social_post events grouped).
type XPost struct {
	PostID     string
	At         *time.Time // created_at of the post
	ObservedAt time.Time
	URL        string
	AuthorID   string
	Handle     string
	Text       string
	Lang       string
	CVEs       []string
}

// XPostsPage is the review list's page size.
const XPostsPage = ListPage

var postIDRe = regexp.MustCompile(`^[0-9]{1,20}$`)

// XPosts lists one page of the collected posts newest first (by first
// observation; keyset both ways; XPostsCount is its length), with
// optional filters: author handle (case-insensitive) and CVE id. A
// position is the observed time and post id of a row.
func (s *Service) XPosts(ctx context.Context, handle, cve string, pos Keyset[Cursor]) ([]XPost, *Cursor, *Cursor, error) {
	return keysetPage(pos, XPostsPage, func(cur *Cursor, back bool, n int) ([]XPost, error) {
		return s.xPosts(ctx, handle, cve, cur, back, n)
	}, func(p XPost) Cursor { return Cursor{At: p.ObservedAt, ID: p.PostID} })
}

// XPostsCount is the length of the post list for the same filters: the
// posts the list groups (each page of it reads them all), counted once.
func (s *Service) XPostsCount(ctx context.Context, handle, cve string) (n int, err error) {
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT count(DISTINCT e.dedupe_key)::int
			FROM event e
			WHERE `+xPostMatch, XSource, handle, cve).Scan(&n)
	})
	return n, err
}

// xPostMatch is the post list's filter on events e: $1 the source, $2 the
// author handle, $3 the CVE id ("" = any).
const xPostMatch = `e.source = $1 AND e.type = 'social_post'
				  AND ($2 = '' OR lower(e.detail->>'author_handle') = lower($2))
				  AND ($3 = '' OR e.dedupe_key IN (SELECT dedupe_key FROM event WHERE source = $1 AND type = 'social_post' AND cve_id = $3))`

func (s *Service) xPosts(ctx context.Context, handle, cve string, cur *Cursor, back bool, n int) ([]XPost, error) {
	at := Cursor{At: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), ID: "99999999999999999999"}
	switch {
	case cur != nil:
		at = *cur
	case back:
		at = Cursor{ID: "0"} // from the oldest
	}
	cmp, ord := "<", "DESC"
	if back {
		cmp, ord = ">", "ASC"
	}
	var out []XPost
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `WITH p AS (
				SELECT e.dedupe_key AS post_id, min(e.observed_at) AS seen, min(e.occurred_at) AS at, min(e.url) AS url,
				       min(e.detail->>'author_id') AS author_id, min(e.detail->>'author_handle') AS handle,
				       min(e.detail->>'text') AS text, min(e.detail->>'lang') AS lang,
				       (array_agg(e.detail->'cves'))[1] AS cves
				FROM event e
				WHERE `+xPostMatch+`
				GROUP BY e.dedupe_key)
			SELECT post_id, seen, at, coalesce(url, ''), coalesce(author_id, ''), coalesce(handle, ''), coalesce(text, ''),
			       coalesce(lang, ''), coalesce(cves, '[]'::jsonb)
			FROM p WHERE (seen, lpad(post_id, 20, '0')) `+cmp+` ($4, lpad($5, 20, '0'))
			ORDER BY seen `+ord+`, lpad(post_id, 20, '0') `+ord+` LIMIT $6`, XSource, handle, cve, at.At, at.ID, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p XPost
			var cves []byte
			if err := rows.Scan(&p.PostID, &p.ObservedAt, &p.At, &p.URL, &p.AuthorID, &p.Handle, &p.Text, &p.Lang, &cves); err != nil {
				return err
			}
			p.ObservedAt = p.ObservedAt.UTC()
			_ = json.Unmarshal(cves, &p.CVEs)
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// EncodeXCursor / DecodeXCursor: the review list's cursor (post ids are
// decimal, not UUIDs).
func EncodeXCursor(c *Cursor) string { return EncodeCursor(c) }

// DecodeXCursor parses EncodeXCursor's output (nil when invalid).
func DecodeXCursor(s string) *Cursor {
	if s == "" || len(s) > 200 {
		return nil
	}
	c := decodeAny(s)
	if c == nil || !postIDRe.MatchString(c.ID) || c.At.IsZero() {
		return nil
	}
	return c
}

// XAccountCount is posts stored per author.
type XAccountCount struct {
	AuthorID, Handle string
	Posts            int64
}

// XStats is posts stored per local day over the last 30 days and per
// account (all time).
func (s *Service) XStats(ctx context.Context) ([]DayValue, []XAccountCount, error) {
	to := localDate(s.now(), s.loc)
	from := to.AddDate(0, 0, -29)
	var starts []time.Time
	for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
		starts = append(starts, time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.loc))
	}
	end := time.Date(to.Year(), to.Month(), to.Day()+1, 0, 0, 0, 0, s.loc)
	counts := make([]int64, len(starts))
	var per []XAccountCount
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT width_bucket(seen, $2::timestamptz[]), count(*) FROM (
				SELECT dedupe_key, min(observed_at) AS seen FROM event WHERE source = $1 AND type = 'social_post' GROUP BY dedupe_key) p
			WHERE seen >= $3 AND seen < $4 GROUP BY 1`, XSource, starts, starts[0], end)
		if err != nil {
			return err
		}
		var b int
		var n int64
		if _, err := pgx.ForEachRow(rows, []any{&b, &n}, func() error {
			if b >= 1 && b <= len(counts) {
				counts[b-1] += n
			}
			return nil
		}); err != nil {
			return err
		}
		rows, err = c.Query(ctx, `SELECT coalesce(detail->>'author_id', ''), coalesce(max(detail->>'author_handle'), ''), count(DISTINCT dedupe_key)
			FROM event WHERE source = $1 AND type = 'social_post' GROUP BY 1 ORDER BY 3 DESC, 1 LIMIT 200`, XSource)
		if err != nil {
			return err
		}
		per, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (XAccountCount, error) {
			var x XAccountCount
			return x, r.Scan(&x.AuthorID, &x.Handle, &x.Posts)
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	out := make([]DayValue, len(starts))
	for i, st := range starts {
		out[i] = DayValue{Day: time.Date(st.Year(), st.Month(), st.Day(), 0, 0, 0, 0, time.UTC), V: counts[i]}
	}
	return out, per, nil
}

// ---- writes (each one transaction on AuthDB with its audit row) ----

// ErrBadSetting / ErrNoXChange are refusals of the X actions.
var (
	ErrNoXChange = errors.New("nothing to change")
)

// writeTx runs fn in one transaction on AuthDB after re-checking, under a
// share lock of the actor's row, that the actor is still an active admin
// (the HTTP layer checked it already; this closes the gap to a concurrent
// demotion or suspension by the CLI).
func (s *Service) writeTx(ctx context.Context, actor string, fn func(tx pgx.Tx) error) error {
	return s.o.AuthDB.WithConn(ctx, func(c *pgx.Conn) error {
		return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			var ok bool
			err := tx.QueryRow(ctx, `SELECT role = 'admin' AND (status = 'active' OR (suspended_until IS NOT NULL AND suspended_until <= now()))
				FROM users WHERE id = $1::uuid FOR SHARE`, actor).Scan(&ok)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && !ok {
				return auth.ErrNotAdmin
			}
			if err != nil {
				return err
			}
			return fn(tx)
		})
	})
}

func optB(v *bool) any {
	if v == nil {
		return nil
	}
	return *v
}

func optI(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

// SettingsDiff is the details object of x.settings.update: for each
// changed field {"from": old, "to": new} (null = default).
func SettingsDiff(old, cur xconfig.Stored) map[string]any {
	d := map[string]any{}
	add := func(name string, a, b any) {
		if a != b {
			d[name] = map[string]any{"from": a, "to": b}
		}
	}
	add("enabled", optB(old.Enabled), optB(cur.Enabled))
	add("max_posts", optI(old.MaxPosts), optI(cur.MaxPosts))
	add("max_requests", optI(old.MaxRequests), optI(cur.MaxRequests))
	add("bootstrap_days", optI(old.BootstrapDays), optI(cur.BootstrapDays))
	add("max_query_length", optI(old.MaxQueryLength), optI(cur.MaxQueryLength))
	return d
}

// XSaveSettings replaces the stored settings (validated by xconfig);
// ErrNoXChange when nothing differs.
func (s *Service) XSaveSettings(ctx context.Context, actor string, st xconfig.Stored) (xconfig.Stored, error) {
	if err := st.Validate(); err != nil {
		return xconfig.Stored{}, err
	}
	var saved xconfig.Stored
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		if err := xconfig.LockSettings(ctx, tx); err != nil {
			return err
		}
		old, err := xconfig.LoadSettings(ctx, tx)
		if err != nil {
			return err
		}
		if old.Equal(st) {
			return ErrNoXChange
		}
		if err := xconfig.SaveSettings(ctx, tx, st); err != nil {
			return err
		}
		if saved, err = xconfig.LoadSettings(ctx, tx); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: audit.XSettingsUpdate, TargetType: audit.TargetXSettings,
			TargetID: "1", Details: SettingsDiff(old, st)})
	})
	return saved, err
}

func accountEntry(actor *string, action string, a xconfig.Account, details map[string]any) audit.Entry {
	return audit.Entry{ActorID: actor, Action: action, TargetType: audit.TargetXAccount, TargetID: a.UserID,
		TargetLabel: "@" + a.Handle, Details: details}
}

// XAddAccount lists a new account (enabled) under an id the administrator
// typed (no lookup); xconfig.ErrExists when the user id is already listed.
func (s *Service) XAddAccount(ctx context.Context, actor, userID, handle, note string) error {
	return s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		if err := xconfig.InsertAccount(ctx, tx, userID, handle, note); err != nil {
			return err
		}
		return audit.Write(ctx, tx, accountEntry(&actor, audit.XAccountAdd, xconfig.Account{UserID: userID, Handle: handle},
			map[string]any{"user_id": userID, "handle": handle, "note": note, "lookup": false}))
	})
}

// Refusals of an add by handle (the lookup's request-level errors are the
// xlookup sentinels: ErrNotConfigured, ErrRateLimited, ErrAuth,
// ErrUpstream).
var (
	ErrXHandleNotFound = errors.New("no X account has this handle")
	ErrXUnavailable    = errors.New("the X account is suspended or unavailable")
	ErrXLookupOff      = xlookup.ErrNotConfigured
)

// XLookupAvailable reports whether this process can look up handles (a
// token is configured). Nothing else about the token is exposed.
func (s *Service) XLookupAvailable() bool { return s.xLookup().Configured() }

// XAdded is what XAddByHandle did.
type XAdded struct {
	UserID, Handle string // the id X returned and its canonical handle
	Renamed        bool   // the id was listed under another handle, now updated
	Previous       string // that handle
}

// XAddByHandle resolves handle through the X API (outside any
// transaction), then lists the id it returned: a new id is inserted
// (enabled) with the canonical handle; an id already listed under the same
// handle is xconfig.ErrExists; an id listed under another handle (the
// account was renamed, or only its spelling differs) gets the new handle,
// keeps its note and enabled state, and is reported as Renamed. The id is
// the key: there is never a second row for it. With ErrExists the result
// still names the listed account.
func (s *Service) XAddByHandle(ctx context.Context, actor, handle, note string) (*XAdded, error) {
	if !xconfig.ValidHandle(handle) {
		return nil, xlookup.ErrBadHandle
	}
	if xconfig.IsOwnHandle(handle) { // no X request for it; the returned handle is checked by the writes below
		return nil, xconfig.ErrOwnAccount
	}
	r, err := s.xLookup().LookupOne(ctx, handle)
	if err != nil {
		return nil, err
	}
	switch r.Outcome {
	case xlookup.Found:
	case xlookup.Unavailable:
		return nil, ErrXUnavailable
	default:
		return nil, ErrXHandleNotFound
	}
	res := &XAdded{UserID: r.ID, Handle: r.Handle}
	err = s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		old, err := xconfig.GetAccountForUpdate(ctx, tx, r.ID)
		if errors.Is(err, xconfig.ErrNotFound) {
			if err := xconfig.InsertAccount(ctx, tx, r.ID, r.Handle, note); err != nil {
				return err
			}
			if err := xconfig.SetProfile(ctx, tx, r.ID, profileOf(r)); err != nil {
				return err
			}
			return audit.Write(ctx, tx, accountEntry(&actor, audit.XAccountAdd, xconfig.Account{UserID: r.ID, Handle: r.Handle},
				map[string]any{"user_id": r.ID, "handle": r.Handle, "note": note, "lookup": true, "entered": handle}))
		}
		if err != nil {
			return err
		}
		if old.Handle == r.Handle {
			return xconfig.ErrExists
		}
		if _, err := xconfig.UpdateAccount(ctx, tx, r.ID, r.Handle, old.Note); err != nil {
			return err
		}
		if err := xconfig.SetProfile(ctx, tx, r.ID, profileOf(r)); err != nil {
			return err
		}
		res.Renamed, res.Previous = true, old.Handle
		return audit.Write(ctx, tx, accountEntry(&actor, audit.XAccountUpdate, xconfig.Account{UserID: r.ID, Handle: r.Handle},
			map[string]any{"user_id": r.ID, "handle": map[string]any{"from": old.Handle, "to": r.Handle}, "lookup": true, "entered": handle}))
	})
	if errors.Is(err, xconfig.ErrExists) {
		return res, err // res names the listed account
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// XUpdateAccount sets the handle and note of a listed account.
func (s *Service) XUpdateAccount(ctx context.Context, actor, userID, handle, note string) error {
	return s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		old, err := xconfig.GetAccountForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		changed, err := xconfig.UpdateAccount(ctx, tx, userID, handle, note)
		if err != nil {
			return err
		}
		if !changed {
			return ErrNoXChange
		}
		d := map[string]any{"user_id": userID, "account": "@" + handle}
		if old.Handle != handle {
			d["handle"] = map[string]any{"from": old.Handle, "to": handle}
		}
		if old.Note != note {
			d["note"] = map[string]any{"from": old.Note, "to": note}
		}
		return audit.Write(ctx, tx, accountEntry(&actor, audit.XAccountUpdate, xconfig.Account{UserID: userID, Handle: handle}, d))
	})
}

// XSetAccountEnabled enables or disables an account (there is no delete).
func (s *Service) XSetAccountEnabled(ctx context.Context, actor, userID string, on bool) error {
	return s.writeTx(ctx, actor, func(tx pgx.Tx) error { return SetXAccountEnabled(ctx, tx, &actor, userID, on) })
}

// SetXAccountEnabled is the transaction body shared with the CLI (actor nil
// = the CLI): lock, refuse a no-op (ErrNoXChange), switch, audit.
func SetXAccountEnabled(ctx context.Context, tx pgx.Tx, actor *string, userID string, on bool) error {
	a, err := xconfig.GetAccountForUpdate(ctx, tx, userID)
	if err != nil {
		return err
	}
	if a.Enabled == on {
		return ErrNoXChange
	}
	if err := xconfig.SetAccountEnabled(ctx, tx, userID, on); err != nil {
		return err
	}
	action := audit.XAccountDisable
	if on {
		action = audit.XAccountEnable
	}
	return audit.Write(ctx, tx, accountEntry(actor, action, a, nil))
}

// ImportLine is one line of an import as applied (or previewed). LookedUp:
// the line gave only a handle and UserID is what the X API returned for it
// (Handle is then the canonical spelling).
type ImportLine struct {
	Line     int                  `json:"line"`
	UserID   string               `json:"user_id"`
	Handle   string               `json:"handle"`
	Result   xconfig.UpsertResult `json:"result"`
	LookedUp bool                 `json:"looked_up"`
}

// ImportResult counts an import.
type ImportResult struct {
	Inserted, Updated, Unchanged int
	Lines                        []ImportLine
}

// errDryRun rolls a preview back.
var errDryRun = errors.New("dry run")

// ImportXAccounts upserts parsed accounts in tx (same semantics as `nday
// x-accounts-import`: never deletes, never changes enabled) and, when
// anything changed, writes one x.accounts.import audit row (actor nil = the
// CLI). Shared by the web and the CLI.
func ImportXAccounts(ctx context.Context, tx pgx.Tx, actor *string, accounts []xconfig.FileAccount) (*ImportResult, error) {
	return importXAccounts(ctx, tx, actor, accounts, nil)
}

// ImportResolvedXAccounts is ImportXAccounts for accounts that went through
// ResolveXImport (looked marks the lines whose id was looked up).
func ImportResolvedXAccounts(ctx context.Context, tx pgx.Tx, actor *string, accounts []xconfig.FileAccount, looked map[int]bool) (*ImportResult, error) {
	return importXAccounts(ctx, tx, actor, accounts, looked)
}

func importXAccounts(ctx context.Context, tx pgx.Tx, actor *string, accounts []xconfig.FileAccount, looked map[int]bool) (*ImportResult, error) {
	res := &ImportResult{}
	for _, a := range accounts {
		r, err := xconfig.UpsertAccount(ctx, tx, a.UserID, a.Handle, a.Note)
		if err != nil {
			return nil, &xconfig.LineError{Line: a.Line, Err: err}
		}
		if a.Profile != nil { // looked up on X just now
			if err := xconfig.SetProfile(ctx, tx, a.UserID, a.Profile); err != nil {
				return nil, &xconfig.LineError{Line: a.Line, Err: err}
			}
		}
		switch r {
		case xconfig.Inserted:
			res.Inserted++
		case xconfig.Updated:
			res.Updated++
		default:
			res.Unchanged++
		}
		res.Lines = append(res.Lines, ImportLine{Line: a.Line, UserID: a.UserID, Handle: a.Handle, Result: r, LookedUp: looked[a.Line]})
	}
	if res.Inserted+res.Updated == 0 {
		return res, nil
	}
	return res, audit.Write(ctx, tx, audit.Entry{ActorID: actor, Action: audit.XAccountsImport, TargetType: audit.TargetXAccount,
		TargetID: "import", Details: importDetails(res)})
}

// importDetails: the counts, how many ids were looked up, and the changed
// accounts as "<result> <id> @<handle>" (" lookup" when the id was looked
// up), as many as fit the audit row (audit.MaxDetails); "changed_omitted"
// counts the rest.
func importDetails(res *ImportResult) map[string]any {
	d := map[string]any{"inserted": res.Inserted, "updated": res.Updated, "unchanged": res.Unchanged}
	n := 0
	for _, l := range res.Lines {
		if l.LookedUp {
			n++
		}
	}
	d["looked_up"] = n
	changed := []string{}
	omitted := 0
	size := 200 // the counts and the keys, generously
	for _, l := range res.Lines {
		if l.Result == xconfig.Unchanged {
			continue
		}
		e := string(l.Result) + " " + l.UserID + " @" + l.Handle
		if l.LookedUp {
			e += " lookup"
		}
		if size+len(e)+3 > audit.MaxDetails {
			omitted++
			continue
		}
		size += len(e) + 3
		changed = append(changed, e)
	}
	d["changed"] = changed
	if omitted > 0 {
		d["changed_omitted"] = omitted
	}
	return d
}

// ResolveXImport looks up the ids of the handle-only lines of accounts
// (batched by internal/xlookup) and returns the accounts with every UserID
// set and the handles in X's spelling, plus which lines were looked up.
// Lines that cannot be resolved (no such account, suspended, or an id that
// is already on another line) come back as line errors, all of them; a
// request-level failure (no token: xlookup.ErrNotConfigured, 429, 401/403,
// timeout) is returned as err. Accounts without handle-only lines are
// returned unchanged without any request.
func ResolveXImport(ctx context.Context, lk *xlookup.Client, accounts []xconfig.FileAccount) ([]xconfig.FileAccount, map[int]bool, []*xconfig.LineError, error) {
	var handles []string
	for _, a := range accounts {
		if a.UserID == "" {
			handles = append(handles, a.Handle)
		}
	}
	looked := map[int]bool{}
	if len(handles) == 0 {
		return accounts, looked, nil, nil
	}
	found, err := lk.Lookup(ctx, handles)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]xconfig.FileAccount, 0, len(accounts))
	var errs []*xconfig.LineError
	for _, a := range accounts {
		if a.UserID != "" {
			out = append(out, a)
			continue
		}
		switch r := found[xlookup.Key(a.Handle)]; r.Outcome {
		case xlookup.Found:
			a.UserID, a.Handle, a.Profile = r.ID, r.Handle, profileOf(r)
			looked[a.Line] = true
			out = append(out, a)
		case xlookup.Unavailable:
			errs = append(errs, &xconfig.LineError{Line: a.Line, Err: fmt.Errorf("@%s: the X account is suspended or unavailable", a.Handle)})
		default:
			errs = append(errs, &xconfig.LineError{Line: a.Line, Err: fmt.Errorf("@%s: no X account has this handle", a.Handle)})
		}
	}
	// one id, one line: a looked-up id may already be on another line
	seen := map[string]int{}
	for _, a := range out {
		if prev, dup := seen[a.UserID]; dup {
			first, second := prev, a.Line
			errs = append(errs, &xconfig.LineError{Line: second, Err: fmt.Errorf("@%s is user id %s, already on line %d", a.Handle, a.UserID, first)})
			continue
		}
		seen[a.UserID] = a.Line
	}
	if len(errs) > 0 {
		sort.Slice(errs, func(i, j int) bool { return errs[i].Line < errs[j].Line })
		return nil, nil, errs, nil
	}
	return out, looked, nil, nil
}

// XImport parses text (deploy/x-accounts.example.txt format) and applies
// it, or with dryRun computes the same counts and rolls back. Invalid lines
// are returned and nothing is applied.
func (s *Service) XImport(ctx context.Context, actor, text string, dryRun bool) (*ImportResult, []*xconfig.LineError, error) {
	accounts, errs := xconfig.ParseAccounts(strings.NewReader(text))
	if len(errs) > 0 {
		return nil, errs, nil
	}
	// handle-only lines: look the ids up before the transaction (only when
	// every line parses, so a broken file costs no request)
	accounts, looked, errs, err := ResolveXImport(ctx, s.xLookup(), accounts)
	if err != nil {
		return nil, nil, err
	}
	if len(errs) > 0 {
		return nil, errs, nil
	}
	var res *ImportResult
	err = s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		var err error
		if res, err = ImportResolvedXAccounts(ctx, tx, &actor, accounts, looked); err != nil {
			return err
		}
		if dryRun {
			return errDryRun
		}
		return nil
	})
	if errors.Is(err, errDryRun) {
		err = nil
	}
	var le *xconfig.LineError
	if errors.As(err, &le) {
		return nil, []*xconfig.LineError{le}, nil
	}
	return res, nil, err
}
