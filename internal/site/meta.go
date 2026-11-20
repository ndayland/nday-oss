package site

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// SourceNames are the public collectors, in display order (SourceNames plus
// NonPublicSources must match internal/registry; checked by a test).
var SourceNames = []string{"cvelist", "kev", "ghsa", "exploitdb", "metasploit", "nuclei", "osssec", "zerowire", "nvd"}

// CollectorStatus is one collector's health.
type CollectorStatus struct {
	Name          string     `json:"name"`
	Status        *string    `json:"status"` // ok | partial | error; nil = never ran
	OK            bool       `json:"ok"`     // status == "ok"
	LastRunAt     *time.Time `json:"last_run_at"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	// LastError: last run's error (status error/partial), at most 300 characters.
	LastError *string `json:"last_error"`
}

// SourcesReport is the data-source health shown in the status line and on
// the sources page.
type SourcesReport struct {
	Collectors      []CollectorStatus `json:"collectors"`
	CollectorsOK    int               `json:"collectors_ok"`
	CollectorsTotal int               `json:"collectors_total"`
	Vulns           int64             `json:"vulns"`
	Events          int64             `json:"events"`
	// CvelistBackfillBacklog: vulns referenced by other sources for which no
	// CVE record has been fetched yet (no title, no disclosure time).
	CvelistBackfillBacklog int64 `json:"cvelist_backfill_backlog"`
	// DataUpdatedAt: latest successful collector run.
	DataUpdatedAt *time.Time `json:"data_updated_at"`
	// StateRefreshedAt: last refresh of the materialized lists.
	StateRefreshedAt *time.Time `json:"state_refreshed_at"`
	StateError       *string    `json:"state_error"` // last refresh error, nil if the last refresh succeeded
	GeneratedAt      time.Time  `json:"generated_at"`
}

const maxErrorRunes = 300

// Public sources and events only (public.go).
var sourcesSQL = `
SELECT source, last_status, last_run_at, last_success_at, last_error
FROM collector_state WHERE ` + publicSourceSQL("source") + ` ORDER BY source`

var totalsSQL = `
SELECT (SELECT count(*) FROM vuln),
       (SELECT count(*) FROM event e WHERE ` + publicEventSQL("e") + `),
       (SELECT count(*) FROM vuln v
         WHERE NOT EXISTS (SELECT 1 FROM raw_record r
                           WHERE r.source = 'cvelist' AND r.source_key = v.cve_id)),
       (SELECT refreshed_at FROM vuln_state_refresh WHERE id = 1),
       (SELECT last_error FROM vuln_state_refresh WHERE id = 1)`

// Sources reports collector health and totals.
func (s *Store) Sources(ctx context.Context) (*SourcesReport, error) {
	r := &SourcesReport{GeneratedAt: s.clock(), Collectors: []CollectorStatus{}}
	byName := map[string]CollectorStatus{}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		b := &pgx.Batch{}
		b.Queue(sourcesSQL)
		b.Queue(totalsSQL)
		br := conn.SendBatch(ctx, b)
		defer br.Close()
		rows, _ := br.Query()
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (CollectorStatus, error) {
			var c CollectorStatus
			err := row.Scan(&c.Name, &c.Status, &c.LastRunAt, &c.LastSuccessAt, &c.LastError)
			return c, err
		})
		if err != nil {
			return err
		}
		for _, c := range list {
			byName[c.Name] = c
		}
		return br.QueryRow().Scan(&r.Vulns, &r.Events, &r.CvelistBackfillBacklog, &r.StateRefreshedAt, &r.StateError)
	})
	if err != nil {
		return nil, err
	}
	names := append([]string(nil), SourceNames...)
	for n := range byName { // collectors not (yet) known here still show up
		if !contains(names, n) {
			names = append(names, n)
		}
	}
	for _, n := range names {
		c, ok := byName[n]
		if !ok {
			c = CollectorStatus{Name: n}
		}
		c.LastRunAt, c.LastSuccessAt = utcPtr(c.LastRunAt), utcPtr(c.LastSuccessAt)
		c.OK = c.Status != nil && *c.Status == "ok"
		if c.LastError != nil {
			if *c.LastError == "" {
				c.LastError = nil
			} else if utf8.RuneCountInString(*c.LastError) > maxErrorRunes {
				t := string([]rune(*c.LastError)[:maxErrorRunes]) + "…"
				c.LastError = &t
			}
		}
		if c.OK {
			r.CollectorsOK++
		}
		if c.LastSuccessAt != nil && (r.DataUpdatedAt == nil || c.LastSuccessAt.After(*r.DataUpdatedAt)) {
			r.DataUpdatedAt = c.LastSuccessAt
		}
		r.Collectors = append(r.Collectors, c)
	}
	r.CollectorsTotal = len(r.Collectors)
	r.StateRefreshedAt = utcPtr(r.StateRefreshedAt)
	return r, nil
}

// StageCount is the number of vulns whose current (highest) stage is Stage.
type StageCount struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

// Stats are whole-database counts (from vuln_state_mat).
type Stats struct {
	Vulns      int64 `json:"vulns"`       // all vuln rows
	WithEvents int64 `json:"with_events"` // vulns with at least one event
	// ByStage: all six stages in order, including zeros; counts include
	// rejected CVEs (see Rejected).
	ByStage      []StageCount `json:"by_stage"`
	Rejected     int64        `json:"rejected"`
	WithPatch    int64        `json:"with_patch"`
	WithAnalysis int64        `json:"with_analysis"`
	WithPoc      int64        `json:"with_poc"`
	Exploited    int64        `json:"exploited"` // exploited_in_wild or KEV
	InKEV        int64        `json:"in_kev"`
	// StateRefreshedAt: the counts are as of this instant.
	StateRefreshedAt *time.Time `json:"state_refreshed_at"`
	GeneratedAt      time.Time  `json:"generated_at"`
	// ByStageLive: the ByStage counts without rejected CVEs (DIS..KEV), for
	// the catalogue's position text (its default leaves rejected CVEs
	// out); counted in the same scan. Not in the JSON.
	ByStageLive [6]int64 `json:"-"`
}

const statsSQL = `
SELECT (SELECT count(*) FROM vuln),
       count(*),
       count(*) FILTER (WHERE is_rejected),
       count(*) FILTER (WHERE has_patch),
       count(*) FILTER (WHERE has_analysis),
       count(*) FILTER (WHERE has_poc),
       count(*) FILTER (WHERE exploited),
       count(*) FILTER (WHERE in_kev),
       count(*) FILTER (WHERE stage_rank = 1),
       count(*) FILTER (WHERE stage_rank = 2),
       count(*) FILTER (WHERE stage_rank = 3),
       count(*) FILTER (WHERE stage_rank = 4),
       count(*) FILTER (WHERE stage_rank = 5),
       count(*) FILTER (WHERE stage_rank = 6),
       (SELECT refreshed_at FROM vuln_state_refresh WHERE id = 1),
       count(*) FILTER (WHERE stage_rank = 1 AND NOT is_rejected),
       count(*) FILTER (WHERE stage_rank = 2 AND NOT is_rejected),
       count(*) FILTER (WHERE stage_rank = 3 AND NOT is_rejected),
       count(*) FILTER (WHERE stage_rank = 4 AND NOT is_rejected),
       count(*) FILTER (WHERE stage_rank = 5 AND NOT is_rejected),
       count(*) FILTER (WHERE stage_rank = 6 AND NOT is_rejected)
FROM vuln_state_mat`

// Stats returns stage counts and feature counts.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{GeneratedAt: s.clock()}
	var by [6]int64
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, statsSQL).Scan(&st.Vulns, &st.WithEvents, &st.Rejected, &st.WithPatch,
			&st.WithAnalysis, &st.WithPoc, &st.Exploited, &st.InKEV,
			&by[0], &by[1], &by[2], &by[3], &by[4], &by[5], &st.StateRefreshedAt,
			&st.ByStageLive[0], &st.ByStageLive[1], &st.ByStageLive[2], &st.ByStageLive[3], &st.ByStageLive[4], &st.ByStageLive[5])
	})
	if err != nil {
		return nil, err
	}
	for i, info := range StageInfos {
		st.ByStage = append(st.ByStage, StageCount{Stage: info.Type, Code: info.Code, Count: by[i]})
	}
	st.StateRefreshedAt = utcPtr(st.StateRefreshedAt)
	return st, nil
}

// Health is the cheap liveness/freshness probe.
type Health struct {
	DB             string     `json:"db"` // "ok" or "error"
	DataUpdatedAt  *time.Time `json:"data_updated_at"`
	DataAgeSeconds *int64     `json:"data_age_seconds"`
	// Stale: no successful collector run for more than StaleAfter.
	Stale            bool       `json:"stale"`
	StateRefreshedAt *time.Time `json:"state_refreshed_at"`
	CheckedAt        time.Time  `json:"checked_at"`
}

// StaleAfter: collectors run hourly; three missed hours is stale.
const StaleAfter = 3 * time.Hour

// Health runs two index-free one-row queries.
func (s *Store) Health(ctx context.Context) (Health, error) {
	h := Health{DB: "error", CheckedAt: s.clock()}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, `SELECT (SELECT max(last_success_at) FROM collector_state WHERE `+publicSourceSQL("source")+`),
                (SELECT refreshed_at FROM vuln_state_refresh WHERE id = 1)`).Scan(&h.DataUpdatedAt, &h.StateRefreshedAt)
	})
	if err != nil {
		return h, err
	}
	h.DB = "ok"
	h.DataUpdatedAt, h.StateRefreshedAt = utcPtr(h.DataUpdatedAt), utcPtr(h.StateRefreshedAt)
	if h.DataUpdatedAt != nil {
		age := int64(h.CheckedAt.Sub(*h.DataUpdatedAt) / time.Second)
		h.DataAgeSeconds = &age
		h.Stale = h.CheckedAt.Sub(*h.DataUpdatedAt) > StaleAfter
	} else {
		h.Stale = true
	}
	return h, nil
}
