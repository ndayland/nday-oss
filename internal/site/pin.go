package site

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Pinned rows of the hot list: CVEs that researchers on the allowlist are
// discussing right now go to the top of the first page. Up to Max CVEs are
// pinned, chosen in two steps (all of it, here and in pinSQL).
//
// The rule (PinRule). A CVE is pinned when
//
//  1. its public researcher count (researchers_7d: distinct ENABLED
//     allow-listed authors, last ResearcherWindow; public.go) is at least
//     MinResearchers;
//  2. its most recent researcher post is at most Recent old;
//  3. its current wave started at most Wave ago. The wave is the most
//     recent run of its researcher posts in which no two consecutive posts
//     are more than Wave apart; it starts at the run's earliest post. So a
//     CVE discussed again after a silence longer than Wave can be pinned
//     again, and one discussed without such a break stops being pinned Wave
//     after its run began;
//  4. it is in the list the request asks for anyway (same window, minimum
//     stage, rejected switch and tags).
//
// These are ordered by researchers_7d desc, then the most recent post desc,
// then CVE id, and cut at Max.
//
// The fill (PinDiscussed). When the rule yields fewer than Max, the rest
// is filled from the top of the "discussed" ranking (discussed.go: the
// public aggregate researcherAggSQL, ordered by researchers_7d desc, most
// recent post desc, CVE id), skipping CVEs the rule pinned, until Max is
// reached or the ranking runs out. A fill CVE must have a lifecycle row
// (vuln_state_mat; a CVE known only from posts cannot be shown as a hot
// row) and match the request's rejected switch and tags; it need NOT be in
// the request's window or reach its minimum stage.
//
// The post times only order and select rows; they are never returned
// (public.go). Only the first page (no cursor, offset 0) shows the pinned
// rows (rule first, then fill), before its Limit ordinary rows; every page
// leaves all of them out of the ordinary rows, so no CVE appears twice and
// the cursor and offset of the ordinary rows work as before. The pinned
// ids come from one query (pinSQL) run on every page of a request, so a
// page excludes exactly the ids the first page pins.
//
// The four numbers are database settings (NDAY_HOT_PIN_*, docs/settings.md;
// PinConfigFromEnv); Max 0 switches pinning off, fill included.

// Why a hot row is pinned (HotRow.PinReason; "" = an ordinary row).
const (
	PinRule      = "rule"      // the rule above
	PinDiscussed = "discussed" // filled from the discussed ranking
)

// Settings of pinned rows (environment variable and app_settings key).
const (
	EnvPinMax         = "NDAY_HOT_PIN_MAX"
	EnvPinResearchers = "NDAY_HOT_PIN_RESEARCHERS"
	EnvPinRecentHours = "NDAY_HOT_PIN_RECENT_HOURS"
	EnvPinWaveDays    = "NDAY_HOT_PIN_WAVE_DAYS"
)

// PinConfig is the pinning rule's numbers.
type PinConfig struct {
	// Max pinned rows (0 = pinning off). 0..20.
	Max int
	// MinResearchers: researchers_7d at least this. 1..100.
	MinResearchers int
	// Recent: the most recent researcher post at most this old. 1h..168h.
	Recent time.Duration
	// Wave: the longest gap inside a wave and the oldest a wave's start may
	// be. 1d..30d.
	Wave time.Duration
}

// DefaultPinConfig is the rule without settings: 10 rows, 2 researchers,
// last post within 72 hours, wave of at most 7 days.
var DefaultPinConfig = PinConfig{Max: 10, MinResearchers: 2, Recent: 72 * time.Hour, Wave: 7 * 24 * time.Hour}

// PinConfigFromEnv reads the NDAY_HOT_PIN_* settings (empty = default).
// Errors name the key, never the value.
func PinConfigFromEnv(getenv func(string) string) (PinConfig, error) {
	c := DefaultPinConfig
	recent, wave := int(c.Recent/time.Hour), int(c.Wave/(24*time.Hour))
	for _, e := range []struct {
		name     string
		p        *int
		min, max int
	}{
		{EnvPinMax, &c.Max, 0, 20},
		{EnvPinResearchers, &c.MinResearchers, 1, 100},
		{EnvPinRecentHours, &recent, 1, 168},
		{EnvPinWaveDays, &wave, 1, 30},
	} {
		v := strings.TrimSpace(getenv(e.name))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < e.min || n > e.max {
			return PinConfig{}, fmt.Errorf("%s must be an integer %d..%d", e.name, e.min, e.max)
		}
		*e.p = n
	}
	c.Recent, c.Wave = time.Duration(recent)*time.Hour, time.Duration(wave)*24*time.Hour
	return c, nil
}

// key is a canonical string of c (part of the hot list's cache key).
func (c PinConfig) key() string {
	return fmt.Sprintf("pin%d/%d/%d/%d", c.Max, c.MinResearchers, int64(c.Recent/time.Second), int64(c.Wave/time.Second))
}

// SetPinConfig replaces the pinning rule's numbers (validated values, e.g.
// PinConfigFromEnv); later requests use them. Safe for concurrent use; a
// copy made by WithClock shares it.
func (s *Store) SetPinConfig(c PinConfig) { s.pins.Store(&c) }

// PinConfig returns the numbers in force (DefaultPinConfig until set).
func (s *Store) PinConfig() PinConfig {
	if c := s.pins.Load(); c != nil {
		return *c
	}
	return DefaultPinConfig
}

// HotCacheKey is the cache key of Hot(p) for normalized p: p.CacheKey and
// the pinning numbers in force.
func (s *Store) HotCacheKey(p HotParams) string {
	return p.CacheKey() + "|" + s.PinConfig().key()
}

// pinBox holds the shared configuration pointer of a Store and its
// WithClock copies.
type pinBox = atomic.Pointer[PinConfig]

// pinSQL selects the pinned CVE ids in pin order, each with whether it is
// a fill row. $1 researcher window start, $2 now (the bounds of
// researcherAggSQL), $3 posts lookback start, $4 wave length (seconds), $5
// minimum researchers, $6 oldest last post, $7 oldest wave start, $8
// transition window start, $9 stage types, $10 include rejected, $11 max
// rows; %[3]s: the tag filter on m.cve_id (parameters from $12; used in
// both steps).
//
// The lookback is max(2*Wave, ResearcherWindow): a run start found within
// it but after now-Wave is genuine (the Wave before it lies inside the
// lookback); one before now-Wave fails rule 3 whatever came earlier.
//
// Cost: pin_rule reads the researcher posts of the lookback (14 days by
// default) once, with a window function per CVE; pin_fill reads the
// researcher posts of the last 7 days again through researcherAggSQL (the
// same aggregate as /discussed), joins each discussed CVE to
// vuln_state_mat by primary key, applies the tag EXISTS filters, sorts the
// (small: one row per discussed CVE) result and keeps at most Max minus
// the rule's count. Both are small: posts of allow-listed researchers over
// two weeks.
const pinSQL = `
WITH rp AS (
  SELECT p.cve_id, p.occurred_at AS at, p.detail->>'author_id' AS author,
         lag(p.occurred_at) OVER (PARTITION BY p.cve_id ORDER BY p.occurred_at, p.id) AS prev
  FROM ` + "%[1]s" + `
  WHERE ` + "%[2]s" + ` AND p.occurred_at >= $3 AND p.occurred_at <= $2
), c AS (
  SELECT rp.cve_id,
         count(DISTINCT rp.author) FILTER (WHERE rp.at >= $1)::int AS researchers,
         max(rp.at) AS last_at,
         max(rp.at) FILTER (WHERE rp.prev IS NULL OR rp.at > rp.prev + make_interval(secs => $4)) AS wave_start
  FROM rp GROUP BY rp.cve_id
), pin_rule AS (
  SELECT c.cve_id, c.researchers, c.last_at
  FROM c JOIN vuln_state_mat m USING (cve_id)
  WHERE c.researchers >= $5 AND c.last_at >= $6 AND c.wave_start >= $7
    AND m.last_transition_at >= $8
    AND m.last_transition_type = ANY($9)
    AND ($10 OR NOT m.is_rejected)
    ` + "%[3]s" + `
  ORDER BY c.researchers DESC, c.last_at DESC, c.cve_id
  LIMIT $11
), pin_fill AS (
  SELECT d.cve_id, d.researchers, d.last_at
  FROM (` + "%[4]s" + `) d JOIN vuln_state_mat m USING (cve_id)
  WHERE d.cve_id NOT IN (SELECT cve_id FROM pin_rule)
    AND ($10 OR NOT m.is_rejected)
    ` + "%[3]s" + `
  ORDER BY d.researchers DESC, d.last_at DESC, d.cve_id
  LIMIT $11 - (SELECT count(*) FROM pin_rule)
)
SELECT u.cve_id, u.fill
FROM (SELECT cve_id, researchers, last_at, false AS fill FROM pin_rule
      UNION ALL
      SELECT cve_id, researchers, last_at, true FROM pin_fill) u
ORDER BY u.fill, u.researchers DESC, u.last_at DESC, u.cve_id`

// pinnedID is one pinned CVE and why (PinRule or PinDiscussed).
type pinnedID struct {
	ID, Reason string
}

// pinnedIDs returns the CVEs pinned for a hot list request (in pin order:
// the rule's, then the fill; none when pinning is off).
func pinnedIDs(ctx context.Context, conn *pgx.Conn, cfg PinConfig, now, start time.Time, types []string,
	includeRejected bool, tags []string) ([]pinnedID, error) {
	if cfg.Max <= 0 {
		return nil, nil
	}
	look := 2 * cfg.Wave
	if look < ResearcherWindow {
		look = ResearcherWindow
	}
	rstart, rend := researcherWindow(now)
	args := []any{rstart, rend, now.Add(-look), cfg.Wave.Seconds(), cfg.MinResearchers, now.Add(-cfg.Recent),
		now.Add(-cfg.Wave), start, types, includeRejected, cfg.Max}
	tf, targs := tagFilterSQL("m.cve_id", tags, len(args)+1)
	sql := fmt.Sprintf(pinSQL, researcherPostFrom, researcherPostWhere, tf, researcherAggSQL(""))
	rows, err := conn.Query(ctx, sql, append(args, targs...)...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (pinnedID, error) {
		var p pinnedID
		var fill bool
		err := r.Scan(&p.ID, &fill)
		p.Reason = PinRule
		if fill {
			p.Reason = PinDiscussed
		}
		return p, err
	})
}
