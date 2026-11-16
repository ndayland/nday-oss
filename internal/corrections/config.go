package corrections

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Fixed limits (the schema and the page rely on them).
const (
	MaxBodyChars     = 4000     // characters (runes) of a normalised submission
	MaxURLBytes      = 2048     // evidence link
	MaxPublicNote    = 1000     // characters of the editor's public note
	MaxInternalNote  = 500      // characters of the internal note of a rejection
	MaxRequestBytes  = 32 << 10 // JSON request body
	MineMax          = 100      // rows of GET /api/corrections/mine
	modBurst         = 600      // staff decisions per moderator: burst ...
	modEvery         = 100 * time.Millisecond
	readBurst        = 120 // GET /api/corrections/mine per user
	readEvery        = 500 * time.Millisecond
	PublicLogMax     = 100 // accepted corrections listed on a vulnerability page
	StatusPending    = "pending"
	StatusAccepted   = "accepted"
	StatusRejected   = "rejected"
	CategoryOther    = "other"
	categoryTitle    = "title"
	categorySummary  = "summary"
	categoryAffected = "affected"
	categoryFix      = "fix"
	categoryTimeline = "timeline"
	categorySources  = "sources"
)

// Categories are what a correction may be about, in display order (the
// CHECK of vuln_corrections.category).
var Categories = []string{categoryTitle, categorySummary, categoryAffected, categoryFix, categoryTimeline, categorySources, CategoryOther}

// Statuses of a correction.
var Statuses = []string{StatusPending, StatusAccepted, StatusRejected}

// Limits are the configurable limits of submissions (docs/corrections.md;
// database settings in the discussion group, internal/settings).
type Limits struct {
	// Daily: corrections a user may submit in 24 hours (rolling, counted in
	// the database).
	Daily int // NDAY_CORRECTIONS_DAILY (10)
	// OpenPerVuln: pending corrections one vulnerability may have, all
	// submitters together.
	OpenPerVuln int // NDAY_CORRECTIONS_OPEN_PER_VULN (20)
	// OpenPerUser: pending corrections one user may have on one
	// vulnerability.
	OpenPerUser int // NDAY_CORRECTIONS_OPEN_PER_USER (3)
	// Burst / Every: submit requests per user (any outcome), in-process
	// token bucket.
	Burst int           // NDAY_CORRECTIONS_BURST (3)
	Every time.Duration // NDAY_CORRECTIONS_EVERY (1m)
}

// Environment / database setting names.
const (
	EnvDaily       = "NDAY_CORRECTIONS_DAILY"
	EnvOpenPerVuln = "NDAY_CORRECTIONS_OPEN_PER_VULN"
	EnvOpenPerUser = "NDAY_CORRECTIONS_OPEN_PER_USER"
	EnvBurst       = "NDAY_CORRECTIONS_BURST"
	EnvEvery       = "NDAY_CORRECTIONS_EVERY"
)

// Keys lists the setting names in display order.
var Keys = []string{EnvDaily, EnvOpenPerVuln, EnvOpenPerUser, EnvBurst, EnvEvery}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{Daily: 10, OpenPerVuln: 20, OpenPerUser: 3, Burst: 3, Every: time.Minute}
}

// LimitsFromEnv returns DefaultLimits overridden by the NDAY_CORRECTIONS_*
// values getenv gives: counts are integers 1..100000, the interval a Go
// duration or a number of days ("1d") between 1ms and 30d. Errors name the
// variable and never echo its value.
func LimitsFromEnv(getenv func(string) string) (Limits, error) {
	l := DefaultLimits()
	for _, e := range []struct {
		name string
		p    *int
	}{{EnvDaily, &l.Daily}, {EnvOpenPerVuln, &l.OpenPerVuln}, {EnvOpenPerUser, &l.OpenPerUser}, {EnvBurst, &l.Burst}} {
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
	if v := strings.TrimSpace(getenv(EnvEvery)); v != "" {
		d, err := parseDuration(v)
		if err != nil || d < time.Millisecond || d > 30*24*time.Hour {
			return Limits{}, fmt.Errorf("%s must be a duration between 1ms and 30d (e.g. 30s, 2m, 24h, 1d)", EnvEvery)
		}
		l.Every = d
	}
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
