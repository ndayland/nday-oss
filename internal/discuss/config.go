package discuss

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Fixed limits (not configurable: the page and the schema rely on them).
const (
	MaxBodyChars    = 10000    // characters (runes) of a normalised body
	MaxRequestBytes = 64 << 10 // JSON request body
	MaxNoteChars    = 500      // report note
	MaxReasonChars  = 200      // hide reason
	MaxReplies      = 200      // replies per top-level comment (all statuses)
	PageDefault     = 50       // top-level comments per page by default
	PageMax         = 200      // top-level comments per page at most
	PageMaxComments = 500      // a page stops adding threads once it holds this many comments
	ModPageMax      = 100      // rows per page of the moderator lists
	// PageMaxHTMLBytes is the byte budget of one page (GET and StreamPage):
	// rendered body HTML plus source bodies when included. Whole threads are
	// added while they fit (at least one); a single thread over the budget is
	// cut at a reply boundary (Comment.RepliesTruncated).
	PageMaxHTMLBytes = 512 << 10
)

// Limits are the configurable rate limits (see docs/discuss.md §5). In-process
// token buckets reset on restart; the daily caps are counted in the database
// (rolling 24 hours) and survive restarts.
type Limits struct {
	PostBurst int           // NDAY_DISCUSS_POST_BURST (5)
	PostEvery time.Duration // NDAY_DISCUSS_POST_EVERY (30s)
	PostDaily int           // NDAY_DISCUSS_POST_DAILY (60)

	NewPostBurst int           // NDAY_DISCUSS_NEW_POST_BURST (2)
	NewPostEvery time.Duration // NDAY_DISCUSS_NEW_POST_EVERY (2m)
	NewPostDaily int           // NDAY_DISCUSS_NEW_POST_DAILY (10)

	// An account is "new" while younger than NewAccountAge OR with fewer
	// than NewAccountComments visible comments.
	NewAccountAge      time.Duration // NDAY_DISCUSS_NEW_ACCOUNT_AGE (24h)
	NewAccountComments int           // NDAY_DISCUSS_NEW_ACCOUNT_COMMENTS (3)

	AddrBurst int           // NDAY_DISCUSS_ADDR_BURST (10): creates per client address, all users
	AddrEvery time.Duration // NDAY_DISCUSS_ADDR_EVERY (10s)

	EditBurst int           // NDAY_DISCUSS_EDIT_BURST (20): edits per user
	EditEvery time.Duration // NDAY_DISCUSS_EDIT_EVERY (3m) -> about 20 per hour

	ReportDaily int // NDAY_DISCUSS_REPORT_DAILY (20): reports per user per 24 h

	ReportBurst int           // NDAY_DISCUSS_REPORT_BURST (5): report requests per user (any outcome)
	ReportEvery time.Duration // NDAY_DISCUSS_REPORT_EVERY (1m)

	DeleteBurst int           // NDAY_DISCUSS_DELETE_BURST (10): delete requests per user (suspended too)
	DeleteEvery time.Duration // NDAY_DISCUSS_DELETE_EVERY (30s)

	ReadBurst int           // NDAY_DISCUSS_READ_BURST (120): GET per client address
	ReadEvery time.Duration // NDAY_DISCUSS_READ_EVERY (500ms)

	ModBurst int           // NDAY_DISCUSS_MOD_BURST (600): moderator requests per user
	ModEvery time.Duration // NDAY_DISCUSS_MOD_EVERY (100ms)

	DuplicateWindow time.Duration // NDAY_DISCUSS_DUPLICATE_WINDOW (10m)

	// GuestRead (NDAY_DISCUSS_GUEST_READ, on): signed-out visitors may read
	// the comments (GET /api/discuss/{cve} returns what any member sees of
	// them, docs/discuss.md §4.1); off: they get only the outline. Not a
	// rate limit, but kept here so SetLimits applies it to a running site.
	GuestRead bool

	// GuestReadBurst / GuestReadEvery: signed-out reads of the comments per
	// client address, on top of ReadBurst/ReadEvery (GuestRead on only).
	GuestReadBurst int           // NDAY_DISCUSS_GUEST_READ_BURST (60)
	GuestReadEvery time.Duration // NDAY_DISCUSS_GUEST_READ_EVERY (2s)
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		PostBurst: 5, PostEvery: 30 * time.Second, PostDaily: 60,
		NewPostBurst: 2, NewPostEvery: 2 * time.Minute, NewPostDaily: 10,
		NewAccountAge: 24 * time.Hour, NewAccountComments: 3,
		AddrBurst: 10, AddrEvery: 10 * time.Second,
		EditBurst: 20, EditEvery: 3 * time.Minute,
		ReportDaily: 20, ReportBurst: 5, ReportEvery: time.Minute,
		DeleteBurst: 10, DeleteEvery: 30 * time.Second,
		ReadBurst: 120, ReadEvery: 500 * time.Millisecond,
		ModBurst: 600, ModEvery: 100 * time.Millisecond,
		DuplicateWindow: 10 * time.Minute,
		GuestRead:       true, GuestReadBurst: 60, GuestReadEvery: 2 * time.Second,
	}
}

// EnvGuestRead turns signed-out reading of the comments off with "off"
// (default on; Limits.GuestRead).
const EnvGuestRead = "NDAY_DISCUSS_GUEST_READ"

// onOff reads an on/off switch ("" = def).
func onOff(getenv func(string) string, name string, def bool) (bool, error) {
	switch v := strings.ToLower(strings.TrimSpace(getenv(name))); v {
	case "":
		return def, nil
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be on or off", name)
	}
}

// EnvEnabled turns the feature off with "off" (default on whenever accounts
// are enabled).
const EnvEnabled = "NDAY_DISCUSS"

// EnvPoolSize is the size of the discussion store's writable pool (default 4).
const EnvPoolSize = "NDAY_DISCUSS_DB_POOL_SIZE"

// Enabled reads NDAY_DISCUSS: "" or "on" -> true, "off" -> false.
func Enabled(getenv func(string) string) (bool, error) {
	return onOff(getenv, EnvEnabled, true)
}

// PoolSize reads NDAY_DISCUSS_DB_POOL_SIZE (1..32, default 4).
func PoolSize(getenv func(string) string) (int, error) {
	v := strings.TrimSpace(getenv(EnvPoolSize))
	if v == "" {
		return 4, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 32 {
		return 0, fmt.Errorf("%s must be 1..32", EnvPoolSize)
	}
	return n, nil
}

// LimitsFromEnv returns DefaultLimits overridden by the NDAY_DISCUSS_*
// variables. Counts are integers 1..100000; durations are Go durations or a
// number of days ("1d"), between 1ms and 30d. Errors name the variable and
// never echo its value.
func LimitsFromEnv(getenv func(string) string) (Limits, error) {
	l := DefaultLimits()
	ints := []struct {
		name string
		p    *int
	}{
		{"NDAY_DISCUSS_POST_BURST", &l.PostBurst}, {"NDAY_DISCUSS_POST_DAILY", &l.PostDaily},
		{"NDAY_DISCUSS_NEW_POST_BURST", &l.NewPostBurst}, {"NDAY_DISCUSS_NEW_POST_DAILY", &l.NewPostDaily},
		{"NDAY_DISCUSS_NEW_ACCOUNT_COMMENTS", &l.NewAccountComments},
		{"NDAY_DISCUSS_ADDR_BURST", &l.AddrBurst}, {"NDAY_DISCUSS_EDIT_BURST", &l.EditBurst},
		{"NDAY_DISCUSS_REPORT_DAILY", &l.ReportDaily}, {"NDAY_DISCUSS_READ_BURST", &l.ReadBurst},
		{"NDAY_DISCUSS_MOD_BURST", &l.ModBurst},
		{"NDAY_DISCUSS_REPORT_BURST", &l.ReportBurst}, {"NDAY_DISCUSS_DELETE_BURST", &l.DeleteBurst},
		{"NDAY_DISCUSS_GUEST_READ_BURST", &l.GuestReadBurst},
	}
	for _, e := range ints {
		v := strings.TrimSpace(getenv(e.name))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100000 {
			return Limits{}, fmt.Errorf("%s must be an integer 1..100000", e.name)
		}
		*e.p = n
	}
	durs := []struct {
		name string
		p    *time.Duration
	}{
		{"NDAY_DISCUSS_POST_EVERY", &l.PostEvery}, {"NDAY_DISCUSS_NEW_POST_EVERY", &l.NewPostEvery},
		{"NDAY_DISCUSS_NEW_ACCOUNT_AGE", &l.NewAccountAge}, {"NDAY_DISCUSS_ADDR_EVERY", &l.AddrEvery},
		{"NDAY_DISCUSS_EDIT_EVERY", &l.EditEvery}, {"NDAY_DISCUSS_READ_EVERY", &l.ReadEvery},
		{"NDAY_DISCUSS_MOD_EVERY", &l.ModEvery}, {"NDAY_DISCUSS_DUPLICATE_WINDOW", &l.DuplicateWindow},
		{"NDAY_DISCUSS_REPORT_EVERY", &l.ReportEvery}, {"NDAY_DISCUSS_DELETE_EVERY", &l.DeleteEvery},
		{"NDAY_DISCUSS_GUEST_READ_EVERY", &l.GuestReadEvery},
	}
	for _, e := range durs {
		v := strings.TrimSpace(getenv(e.name))
		if v == "" {
			continue
		}
		d, err := parseDuration(v)
		if err != nil || d < time.Millisecond || d > 30*24*time.Hour {
			return Limits{}, fmt.Errorf("%s must be a duration between 1ms and 30d (e.g. 30s, 2m, 24h, 1d)", e.name)
		}
		*e.p = d
	}
	on, err := onOff(getenv, EnvGuestRead, l.GuestRead)
	if err != nil {
		return Limits{}, err
	}
	l.GuestRead = on
	return l, nil
}

func parseDuration(v string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 || n > 3650 {
			return 0, fmt.Errorf("bad days")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(v)
}
