// Package state queries the derived lifecycle state and keeps its
// materialized copy fresh.
//
// The definition of the derived state is the vuln_state view
// (migrations/0002_vuln_state.sql). Reads go to vuln_state_mat
// (migrations/0003_vuln_state_mat.sql), a materialized view of vuln_state
// plus a few extra columns, refreshed by Refresh. Refresh is called by the
// pipeline after every successful collector run and by `nday refresh-state`.
package state

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
)

// hotSQL is Python's HOT_SQL, reading the materialized state. The window is
// passed as days + seconds and rebuilt with make_interval, which is exactly
// the interval psycopg sends for a Python timedelta (days and seconds are
// kept apart, so "24h" is "1 day" — this matters for timestamptz arithmetic
// in a session TimeZone with DST).
const hotSQL = `
SELECT s.cve_id, v.title, s.stage, s.stage_rank, s.last_transition_at,
       s.last_transition_type, s.has_patch, s.has_analysis, s.has_poc,
       s.exploited, s.in_kev, s.is_rejected
FROM vuln_state_mat s
JOIN vuln v USING (cve_id)
WHERE s.last_transition_at IS NOT NULL
  AND s.last_transition_at >= now() - make_interval(days => $1, secs => $2)
  AND ($3 OR NOT s.is_rejected)
  AND s.last_transition_type = ANY($4)
ORDER BY s.last_transition_at DESC, s.stage_rank DESC, s.cve_id
LIMIT $5`

// HotRow is one row of Hot.
type HotRow struct {
	CVEID              string
	Title              *string
	Stage              string
	StageRank          int
	LastTransitionAt   time.Time
	LastTransitionType string
	HasPatch           bool
	HasAnalysis        bool
	HasPoc             bool
	Exploited          bool
	InKev              bool
	IsRejected         bool
}

// Hot returns vulns whose most recent transition (reaching a NEW event type)
// falls in the window, newest first. minStage keeps only transitions to that
// stage or a later one. It reads vuln_state_mat (as fresh as the last Refresh).
func Hot(ctx context.Context, conn *pgx.Conn, since time.Duration, limit int, includeRejected bool, minStage string) ([]HotRow, error) {
	idx := -1
	for i, s := range model.Stages {
		if s == minStage {
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("unknown stage %q", minStage)
	}
	types := model.Stages[idx:]
	// Python timedelta normalisation: days, then seconds (+ microseconds) in [0, 86400).
	days := int64(since / (24 * time.Hour))
	rest := since - time.Duration(days)*24*time.Hour
	if rest < 0 {
		days--
		rest += 24 * time.Hour
	}
	rows, err := conn.Query(ctx, hotSQL, days, rest.Seconds(), includeRejected, types, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (HotRow, error) {
		var h HotRow
		err := r.Scan(&h.CVEID, &h.Title, &h.Stage, &h.StageRank, &h.LastTransitionAt,
			&h.LastTransitionType, &h.HasPatch, &h.HasAnalysis, &h.HasPoc,
			&h.Exploited, &h.InKev, &h.IsRejected)
		return h, err
	})
}

// StageCount is one row of StageCounts.
type StageCount struct {
	Stage string
	N     int64
}

// StageCounts returns [(stage, n)] ordered by stage rank (from vuln_state_mat).
func StageCounts(ctx context.Context, conn *pgx.Conn) ([]StageCount, error) {
	rows, err := conn.Query(ctx,
		"SELECT stage, count(*) FROM vuln_state_mat GROUP BY stage, stage_rank ORDER BY stage_rank")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (StageCount, error) {
		var s StageCount
		return s, r.Scan(&s.Stage, &s.N)
	})
}
