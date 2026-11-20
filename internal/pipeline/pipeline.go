// Package pipeline runs a collector: fetch -> store raw -> normalize ->
// idempotent upserts -> collector_state, all data writes in one transaction
// (port of src/nday/pipeline.py; SQL kept textually identical where possible).
//
// Idempotency rules (re-running on unchanged upstream data writes zero rows):
//   - raw_record: a record whose content hash equals the latest stored version
//     for its (source, source_key) is skipped entirely (not even normalized),
//     unless Options.Renormalize. A reverted upstream version only bumps the
//     fetched_at of the row already stored.
//   - vuln: inserted if missing; otherwise updated only if the merged values
//     differ (stub vs authoritative, see MergeVuln).
//   - vuln_alias / affected: INSERT ... ON CONFLICT DO NOTHING.
//   - event: INSERT ... ON CONFLICT (cve_id, type, source, dedupe_key) DO
//     UPDATE only when detail/url changed or occurred_at was unknown;
//     observed_at and is_backfill of an existing event are never changed.
//   - x_post_no_cve (Go only, xposts posts without a CVE id): INSERT ... ON
//     CONFLICT (post_id) DO UPDATE only when a stored column changed; same
//     observed_at / is_backfill rule as event.
//   - x_post_link, x_account_candidate, x_account_candidate_ref (Go only,
//     xposts links and referred accounts): ON CONFLICT DO UPDATE only when
//     something changed; a link is never downgraded from 'ok' to 'pending',
//     a candidate's status is never touched (see ApplyNormalized).
//
// Backfill: events are stored with is_backfill=true when the run is the
// collector's first successful run (bulk import) OR the RawRecord has
// IsBackfill set. Collectors implementing collector.WantsMissingCVEs get
// state.Wanted filled before Fetch (MissingCVEs).
//
// Derived state: after the data transaction of a successful run commits
// (status ok or partial), RunCollector and Renormalize (unless DryRun) call
// state.Refresh without waiting (see RefreshState). A refresh failure is
// logged and never turns a successful run into a failed one.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/state"
)

// Stats is Python's RunStats; JSON field order and names are identical, so
// `nday collect` prints the same JSON.
type Stats struct {
	Source           string `json:"source"`
	IsBackfill       bool   `json:"is_backfill"`
	Fetched          int    `json:"fetched"`
	RawUnchanged     int    `json:"raw_unchanged"`
	RawNew           int    `json:"raw_new"`
	NormalizeErrors  int    `json:"normalize_errors"`
	VulnInserted     int    `json:"vuln_inserted"`
	VulnUpdated      int    `json:"vuln_updated"`
	AliasInserted    int    `json:"alias_inserted"`
	AffectedInserted int    `json:"affected_inserted"`
	EventInserted    int    `json:"event_inserted"`
	EventUpdated     int    `json:"event_updated"`
}

// Options for RunCollector.
type Options struct {
	// Renormalize also re-runs Normalize on records whose raw content is
	// unchanged (Python: --renormalize).
	Renormalize bool
	// Now is the run clock (Python: run_collector(now=...)); default time.Now.
	Now    func() time.Time
	Logger *slog.Logger
	// SkipStateRefresh disables the post-run refresh of vuln_state_mat
	// (tools that write to databases without migration 0003).
	SkipStateRefresh bool
}

func (o Options) now() time.Time {
	t := time.Now()
	if o.Now != nil {
		t = o.Now()
	}
	// Python datetimes and timestamptz have microsecond precision.
	return t.UTC().Truncate(time.Microsecond)
}

func (o Options) log() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// --------------------------------------------------------------------- state

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// LoadState reads collector_state for source (zero state if absent).
func LoadState(ctx context.Context, q querier, source string) (model.CollectorState, error) {
	st := model.CollectorState{Source: source}
	var cursor *string
	err := q.QueryRow(ctx, `SELECT cursor::text, last_run_at, last_status, last_error, last_success_at
           FROM collector_state WHERE source = $1`, source).
		Scan(&cursor, &st.LastRunAt, &st.LastStatus, &st.LastError, &st.LastSuccessAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if cursor != nil {
		if st.Cursor, err = pyjson.DecodeString(*cursor); err != nil {
			return st, fmt.Errorf("collector_state.cursor: %w", err)
		}
	}
	st.LastRunAt = utcPtr(st.LastRunAt)
	st.LastSuccessAt = utcPtr(st.LastSuccessAt)
	return st, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// execer is satisfied by *pgx.Conn and pgx.Tx.
type execer interface {
	querier
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// saveState is Python's _save_state: on failure keep the previous cursor and
// last_success_at.
func saveState(ctx context.Context, db execer, source string, runAt time.Time, status string,
	errText *string, cursor any, success bool) error {
	var cur *string
	if success && cursor != nil {
		s, err := pyjson.Encode(cursor, pyjson.Options{})
		if err != nil {
			return fmt.Errorf("cursor: %w", err)
		}
		cur = &s
	}
	_, err := db.Exec(ctx, `INSERT INTO collector_state
               (source, cursor, last_run_at, last_status, last_error, last_success_at)
           VALUES ($1, $2::jsonb, $3, $4, $5,
                   CASE WHEN $6::boolean THEN $3::timestamptz END)
           ON CONFLICT (source) DO UPDATE SET
               cursor          = CASE WHEN $6::boolean THEN EXCLUDED.cursor
                                      ELSE collector_state.cursor END,
               last_run_at     = EXCLUDED.last_run_at,
               last_status     = EXCLUDED.last_status,
               last_error      = EXCLUDED.last_error,
               last_success_at = CASE WHEN $6::boolean THEN EXCLUDED.last_run_at
                                      ELSE collector_state.last_success_at END`,
		source, cur, runAt, status, errText, success)
	return err
}

// missingCVEsSQL: numeric-aware "newest CVE first": year, then sequence number
// (CVE-2026-100000 sorts before CVE-2026-99999). Identical to Python.
// GHSA-keyed vulns (docs/ghsa.md) are not CVEs: they are left out, which
// also keeps the casts from seeing them.
const missingCVEsSQL = `
SELECT v.cve_id FROM vuln v
WHERE v.cve_id LIKE 'CVE-%'
  AND NOT EXISTS (SELECT 1 FROM raw_record r
                  WHERE r.source = $1 AND r.source_key = v.cve_id)
ORDER BY split_part(v.cve_id, '-', 2)::int DESC,
         split_part(v.cve_id, '-', 3)::numeric DESC
LIMIT $2`

// MissingCVEs: CVE ids in vuln for which source has never stored a raw record
// (any content), newest first, at most limit.
func MissingCVEs(ctx context.Context, q querier, source string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, missingCVEsSQL, source, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ----------------------------------------------------------------------- raw

func latestHashes(ctx context.Context, q querier, source string) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT ON (source_key) source_key, content_hash
           FROM raw_record WHERE source = $1
           ORDER BY source_key, fetched_at DESC, id DESC`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, h string
		if err := rows.Scan(&k, &h); err != nil {
			return nil, err
		}
		out[k] = h
	}
	return out, rows.Err()
}

// storeRaw inserts a new content version; if upstream reverted to a version
// already stored, it bumps that row's fetched_at instead. Returns true if a
// new row was inserted.
func storeRaw(ctx context.Context, q querier, rec model.RawRecord, hash string, runAt time.Time) (bool, error) {
	payload, err := pyjson.Encode(rec.Payload, pyjson.Options{SortKeys: true, Compact: true})
	if err != nil {
		return false, err
	}
	var inserted bool
	err = q.QueryRow(ctx, `INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES ($1, $2, $3, $4, $5::jsonb)
           ON CONFLICT (source, source_key, content_hash)
               DO UPDATE SET fetched_at = EXCLUDED.fetched_at
           RETURNING (xmax = 0) AS inserted`,
		rec.Source, rec.SourceKey, runAt, hash, payload).Scan(&inserted)
	return inserted, err
}

// ---------------------------------------------------------------------- vuln

// VulnRow is the mergeable part of a vuln row.
type VulnRow struct {
	Title       *string
	Description *string
	PublishedAt *time.Time
	ModifiedAt  *time.Time
}

// MergeVuln is Python's merge_vuln: a nil or "" new value never erases; a
// stub only fills NULL/"" columns; an authoritative upsert overwrites.
func MergeVuln(existing VulnRow, v model.VulnUpsert) VulnRow {
	m := existing
	str := func(cur, val *string) *string {
		if val == nil || *val == "" {
			return cur
		}
		if v.Authoritative || cur == nil || *cur == "" {
			return val
		}
		return cur
	}
	tm := func(cur, val *time.Time) *time.Time {
		if val == nil {
			return cur
		}
		if v.Authoritative || cur == nil {
			return val
		}
		return cur
	}
	m.Title = str(existing.Title, v.Title)
	m.Description = str(existing.Description, v.Description)
	m.PublishedAt = tm(existing.PublishedAt, v.PublishedAt)
	m.ModifiedAt = tm(existing.ModifiedAt, v.ModifiedAt)
	return m
}

// Equal compares like Python's dict equality (aware datetimes by instant).
func (a VulnRow) Equal(b VulnRow) bool {
	se := func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	te := func(x, y *time.Time) bool { return (x == nil) == (y == nil) && (x == nil || x.Equal(*y)) }
	return se(a.Title, b.Title) && se(a.Description, b.Description) &&
		te(a.PublishedAt, b.PublishedAt) && te(a.ModifiedAt, b.ModifiedAt)
}

func upsertVuln(ctx context.Context, db execer, v model.VulnUpsert, observedAt time.Time, st *Stats) error {
	var cur VulnRow
	err := db.QueryRow(ctx, `SELECT title, description, published_at, modified_at FROM vuln WHERE cve_id = $1 FOR UPDATE`,
		v.CVEID).Scan(&cur.Title, &cur.Description, &cur.PublishedAt, &cur.ModifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		tag, err := db.Exec(ctx, `INSERT INTO vuln (cve_id, title, description, published_at, modified_at,
                                 first_seen_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (cve_id) DO NOTHING`,
			v.CVEID, v.Title, v.Description, v.PublishedAt, v.ModifiedAt, observedAt)
		if err != nil {
			return err
		}
		st.VulnInserted += int(tag.RowsAffected())
		return nil
	}
	if err != nil {
		return err
	}
	merged := MergeVuln(cur, v)
	if merged.Equal(cur) {
		return nil
	}
	if _, err := db.Exec(ctx, `UPDATE vuln SET title = $1, description = $2,
                   published_at = $3, modified_at = $4,
                   updated_at = now()
               WHERE cve_id = $5`,
		merged.Title, merged.Description, merged.PublishedAt, merged.ModifiedAt, v.CVEID); err != nil {
		return err
	}
	st.VulnUpdated++
	return nil
}

func ensureStub(ctx context.Context, db execer, cveID string, observedAt time.Time, st *Stats) error {
	tag, err := db.Exec(ctx, `INSERT INTO vuln (cve_id, first_seen_at) VALUES ($1, $2) ON CONFLICT (cve_id) DO NOTHING`,
		cveID, observedAt)
	if err != nil {
		return err
	}
	st.VulnInserted += int(tag.RowsAffected())
	return nil
}

// --------------------------------------------------------------------- apply

// ApplyNormalized writes one Normalized result (Python apply_normalized).
//
// GHSA-keyed vulns (Go only, docs/ghsa.md): rows for a GHSA id that is
// already an alias of a CVE go to that CVE (redirectGHSA); a GHSA id never
// gets a stub vuln, so rows for one without a vuln row are skipped (a
// withdrawn advisory that was never stored stores nothing); writing the
// alias (ghsa, G) -> C while G has a vuln row moves G to C (mergeVuln); and
// a disclosed event of the CVE record replaces the advisory's.
func ApplyNormalized(ctx context.Context, db execer, norm *model.Normalized, observedAt time.Time,
	isBackfill bool, st *Stats) error {
	norm, err := redirectGHSA(ctx, db, norm)
	if err != nil {
		return err
	}
	for _, v := range norm.Vulns {
		if err := upsertVuln(ctx, db, v, observedAt, st); err != nil {
			return err
		}
	}
	// Any CVE referenced by other rows gets at least a stub vuln (FK target).
	known := map[string]bool{}
	for _, v := range norm.Vulns {
		known[v.CVEID] = true
	}
	need := map[string]bool{}
	for _, a := range norm.Aliases {
		need[a.CVEID] = true
	}
	for _, a := range norm.Affected {
		need[a.CVEID] = true
	}
	for _, e := range norm.Events {
		need[e.CVEID] = true
	}
	stubs := make([]string, 0, len(need))
	for id := range need {
		if !known[id] {
			stubs = append(stubs, id)
		}
	}
	sort.Strings(stubs)       // Python sorted(): code point order == UTF-8 byte order
	skip := map[string]bool{} // GHSA ids without a vuln row: their rows are not written
	for _, id := range stubs {
		if model.IsGHSAID(id) {
			var ok bool
			if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln WHERE cve_id = $1)`, id).Scan(&ok); err != nil {
				return err
			}
			skip[id] = !ok
			continue
		}
		if err := ensureStub(ctx, db, id, observedAt, st); err != nil {
			return err
		}
	}
	for _, a := range norm.Aliases {
		if skip[a.CVEID] {
			continue
		}
		tag, err := db.Exec(ctx, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, $3)
               ON CONFLICT (alias_type, alias) DO NOTHING`, a.CVEID, a.Alias, a.AliasType)
		if err != nil {
			return err
		}
		st.AliasInserted += int(tag.RowsAffected())
	}
	if err := mergeGHSAAliases(ctx, db, norm); err != nil {
		return err
	}
	for _, af := range norm.Affected {
		if skip[af.CVEID] {
			continue
		}
		tag, err := db.Exec(ctx, `INSERT INTO affected (cve_id, vendor, product) VALUES ($1, $2, $3)
               ON CONFLICT (cve_id, vendor, product) DO NOTHING`, af.CVEID, af.Vendor, af.Product)
		if err != nil {
			return err
		}
		st.AffectedInserted += int(tag.RowsAffected())
	}
	for _, e := range norm.Events {
		if skip[e.CVEID] {
			continue
		}
		detail, err := pyjson.Encode(e.Detail, pyjson.Options{SortKeys: true, Compact: true})
		if err != nil {
			return fmt.Errorf("event detail for %s: %w", e.CVEID, err)
		}
		if e.Detail == nil {
			detail = "{}"
		}
		var inserted bool
		err = db.QueryRow(ctx, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url,
                                  detail, is_backfill, dedupe_key)
               VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
               ON CONFLICT (cve_id, type, source, dedupe_key) DO UPDATE SET
                   detail      = EXCLUDED.detail,
                   url         = EXCLUDED.url,
                   occurred_at = COALESCE(event.occurred_at, EXCLUDED.occurred_at)
               WHERE event.detail IS DISTINCT FROM EXCLUDED.detail
                  OR event.url IS DISTINCT FROM EXCLUDED.url
                  OR (event.occurred_at IS NULL AND EXCLUDED.occurred_at IS NOT NULL)
               RETURNING (xmax = 0) AS inserted`,
			e.CVEID, e.Type, e.OccurredAt, observedAt, e.Source, e.URL, detail, isBackfill, e.DedupeKey).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // conflict and nothing changed
		}
		if err != nil {
			return err
		}
		if inserted {
			st.EventInserted++
			if e.Type == model.EventDisclosed && e.Source != ghsaSource {
				if err := dropGHSADisclosed(ctx, db, e.CVEID); err != nil {
					return err
				}
			}
		} else {
			st.EventUpdated++
		}
	}
	// Go only (xposts): posts without a CVE id; same rules as event rows
	// (observed_at and is_backfill of an existing row are never changed).
	// Not counted in Stats, whose fields mirror Python's RunStats.
	for _, p := range norm.PostsNoCVE {
		if _, err := db.Exec(ctx, `INSERT INTO x_post_no_cve (post_id, author_id, author_handle, text, lang,
                                  posted_at, url, observed_at, is_backfill)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (post_id) DO UPDATE SET
                   author_id     = EXCLUDED.author_id,
                   author_handle = EXCLUDED.author_handle,
                   text          = EXCLUDED.text,
                   lang          = EXCLUDED.lang,
                   posted_at     = EXCLUDED.posted_at,
                   url           = EXCLUDED.url
               WHERE (x_post_no_cve.author_id, x_post_no_cve.author_handle, x_post_no_cve.text,
                      x_post_no_cve.lang, x_post_no_cve.posted_at, x_post_no_cve.url)
                     IS DISTINCT FROM
                     (EXCLUDED.author_id, EXCLUDED.author_handle, EXCLUDED.text,
                      EXCLUDED.lang, EXCLUDED.posted_at, EXCLUDED.url)`,
			p.PostID, p.AuthorID, p.AuthorHandle, p.Text, p.Lang, p.PostedAt, p.URL, observedAt, isBackfill); err != nil {
			return fmt.Errorf("x_post_no_cve %s: %w", p.PostID, err)
		}
	}
	// Go only (xposts): links of stored posts. An 'ok' row (from the API or
	// the resolver) follows the latest API values; a 'pending' row (t.co link
	// from the text of an old raw record) is written only when the slot is
	// new or held another, unresolved short link: it never downgrades an
	// 'ok' row and never resets the resolver's attempts or a 'failed' row.
	for _, l := range norm.PostLinks {
		if _, err := db.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host,
                                  kind, title, origin, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (post_id, pos) DO UPDATE SET
                   short_url    = EXCLUDED.short_url,
                   expanded_url = EXCLUDED.expanded_url,
                   final_url    = EXCLUDED.final_url,
                   host         = EXCLUDED.host,
                   kind         = EXCLUDED.kind,
                   title        = EXCLUDED.title,
                   origin       = EXCLUDED.origin,
                   status       = EXCLUDED.status,
                   attempts     = CASE WHEN EXCLUDED.status = 'pending' THEN 0 ELSE x_post_link.attempts END,
                   resolved_at  = CASE WHEN EXCLUDED.status = 'pending' OR EXCLUDED.origin = 'api' THEN NULL
                                       ELSE x_post_link.resolved_at END
               WHERE CASE WHEN EXCLUDED.status = 'pending'
                          THEN x_post_link.status <> 'ok' AND x_post_link.short_url <> EXCLUDED.short_url
                          ELSE (x_post_link.short_url, x_post_link.expanded_url, x_post_link.final_url, x_post_link.host,
                                x_post_link.kind, x_post_link.title, x_post_link.origin, x_post_link.status)
                               IS DISTINCT FROM
                               (EXCLUDED.short_url, EXCLUDED.expanded_url, EXCLUDED.final_url, EXCLUDED.host,
                                EXCLUDED.kind, EXCLUDED.title, EXCLUDED.origin, EXCLUDED.status) END`,
			l.PostID, l.Pos, l.ShortURL, l.ExpandedURL, l.FinalURL, l.Host, l.Kind, l.Title, l.Origin, l.Status); err != nil {
			return fmt.Errorf("x_post_link %s/%d: %w", l.PostID, l.Pos, err)
		}
	}
	// Go only (xposts): accounts the stored posts quote, reply to or mention.
	// first/last_seen_at follow the posts' times (so re-normalizing old
	// records changes nothing); the handle follows the newest post; the
	// status ('dismissed' by an admin) is never touched here.
	for _, r := range norm.CandidateRefs {
		if _, err := db.Exec(ctx, `INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at)
               VALUES ($1, $2, $3, $3)
               ON CONFLICT (user_id) DO UPDATE SET
                   handle        = CASE WHEN EXCLUDED.handle IS NOT NULL AND EXCLUDED.last_seen_at >= x_account_candidate.last_seen_at
                                        THEN EXCLUDED.handle ELSE x_account_candidate.handle END,
                   first_seen_at = LEAST(x_account_candidate.first_seen_at, EXCLUDED.first_seen_at),
                   last_seen_at  = GREATEST(x_account_candidate.last_seen_at, EXCLUDED.last_seen_at)
               WHERE x_account_candidate.first_seen_at > EXCLUDED.first_seen_at
                  OR x_account_candidate.last_seen_at < EXCLUDED.last_seen_at
                  OR (EXCLUDED.handle IS NOT NULL AND EXCLUDED.last_seen_at >= x_account_candidate.last_seen_at
                      AND x_account_candidate.handle IS DISTINCT FROM EXCLUDED.handle)`,
			r.UserID, r.Handle, r.PostedAt); err != nil {
			return fmt.Errorf("x_account_candidate %s: %w", r.UserID, err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (user_id, post_id, kind) DO UPDATE SET
                   referrer_id = EXCLUDED.referrer_id,
                   posted_at   = EXCLUDED.posted_at
               WHERE (x_account_candidate_ref.referrer_id, x_account_candidate_ref.posted_at)
                     IS DISTINCT FROM (EXCLUDED.referrer_id, EXCLUDED.posted_at)`,
			r.UserID, r.PostID, r.ReferrerID, r.Kind, r.PostedAt); err != nil {
			return fmt.Errorf("x_account_candidate_ref %s/%s: %w", r.UserID, r.PostID, err)
		}
	}
	// Go only (xposts): the profile of each post's author. The newest fetch
	// wins (seen_at, set by stampProfiles to when the raw record was
	// fetched), so re-normalizing an old raw record never rolls a name or
	// avatar back, and a profile change shows on the next fetch even when
	// the author has posted nothing newer. A changed avatar_url leaves the stored image in
	// place (internal/xavatar refetches it at once); a NULL one drops it.
	for _, u := range norm.XUsers {
		if err := UpsertXUser(ctx, db, u); err != nil {
			return err
		}
	}
	return nil
}

// UpsertXUser writes one author profile (table x_user): the newer fetch
// wins (seen_at), an equal or older one changes nothing it should not. A
// NULL avatar_url drops a stored image; a changed one keeps it until
// internal/xavatar fetches the new one. Used by ApplyNormalized and by
// `nday x-profiles` (internal/xprofiles), so both follow the same rule.
func UpsertXUser(ctx context.Context, db Execer, u model.XUser) error {
	if _, err := db.Exec(ctx, `INSERT INTO x_user (user_id, name, avatar_url, seen_at, updated_at)
               VALUES ($1, $2, $3, $4, now())
               ON CONFLICT (user_id) DO UPDATE SET
                   name          = EXCLUDED.name,
                   avatar_url    = EXCLUDED.avatar_url,
                   seen_at       = EXCLUDED.seen_at,
                   updated_at    = now(),
                   avatar_status = CASE WHEN EXCLUDED.avatar_url IS NULL THEN NULL ELSE x_user.avatar_status END,
                   avatar_type   = CASE WHEN EXCLUDED.avatar_url IS NULL THEN NULL ELSE x_user.avatar_type END,
                   avatar_image  = CASE WHEN EXCLUDED.avatar_url IS NULL THEN NULL ELSE x_user.avatar_image END,
                   avatar_hash   = CASE WHEN EXCLUDED.avatar_url IS NULL THEN NULL ELSE x_user.avatar_hash END,
                   avatar_src    = CASE WHEN EXCLUDED.avatar_url IS NULL THEN NULL ELSE x_user.avatar_src END
               WHERE x_user.seen_at <= EXCLUDED.seen_at
                 AND (x_user.name, x_user.avatar_url, x_user.seen_at)
                     IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.avatar_url, EXCLUDED.seen_at)`,
		u.UserID, u.Name, u.AvatarURL, u.SeenAt); err != nil {
		return fmt.Errorf("x_user %s: %w", u.UserID, err)
	}
	return nil
}

// stampProfiles dates the author profiles of norm at fetchedAt, the time
// the raw record was fetched from X: a profile is what X said then, not
// when the post was written.
func stampProfiles(norm *model.Normalized, fetchedAt time.Time) {
	for i := range norm.XUsers {
		norm.XUsers[i].SeenAt = fetchedAt
	}
}

// normalizeOne runs Normalize and the constructor-time validation Python does.
// Returns (nil, nerr, nil) for a NormalizeError, (nil, nil, err) for a fatal one.
func normalizeOne(c collector.Collector, rec model.RawRecord) (*model.Normalized, *collector.NormalizeError, error) {
	norm, err := c.Normalize(rec)
	if err != nil {
		var ne *collector.NormalizeError
		if errors.As(err, &ne) {
			return nil, ne, nil
		}
		return nil, nil, fmt.Errorf("normalize %s/%s: %w", rec.Source, rec.SourceKey, err)
	}
	if norm == nil {
		norm = &model.Normalized{}
	}
	if err := norm.Validate(); err != nil {
		return nil, nil, fmt.Errorf("normalize %s/%s: %w", rec.Source, rec.SourceKey, err)
	}
	return norm, nil, nil
}

// ----------------------------------------------------------------------- run

// RunCollector runs one collector end to end (Python run_collector). conn
// must not be inside a transaction. On failure the error is recorded in
// collector_state (status "error", cursor and last_success_at kept) and
// returned.
func RunCollector(ctx context.Context, conn *pgx.Conn, c collector.Collector, opt Options) (*Stats, error) {
	runAt := opt.now()
	log := opt.log()
	state, err := LoadState(ctx, conn, c.Name())
	if err != nil {
		return nil, err
	}
	// First successful run = bulk import: observed_at is not meaningful.
	st := &Stats{Source: c.Name(), IsBackfill: state.IsFirstRun()}
	runErr := func() error {
		if w, ok := c.(collector.WantsMissingCVEs); ok {
			wanted, err := MissingCVEs(ctx, conn, c.Name(), w.WantedLimit())
			if err != nil {
				return err
			}
			state.Wanted = wanted
		}
		if p, ok := c.(collector.Preparer); ok {
			if err := p.Prepare(ctx, conn); err != nil {
				return err
			}
		}
		res, err := c.Fetch(ctx, state)
		if err != nil {
			return err
		}
		if res == nil {
			res = &model.FetchResult{}
		}
		st.Fetched = len(res.Records)
		var errs []string
		return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			db := tx
			latest, err := latestHashes(ctx, tx, c.Name())
			if err != nil {
				return err
			}
			// Raw records first, then the GHSA-id locks of every record to
			// apply, before the first vuln row lock (merge.go,
			// "Concurrency"), then the records. Normalizing is pure: the
			// second loop normalizes again rather than keep every result in
			// memory.
			var apply []model.RawRecord
			var locks []*model.Normalized
			for _, rec := range res.Records {
				h, err := rec.ContentHash()
				if err != nil {
					return fmt.Errorf("content hash %s/%s: %w", rec.Source, rec.SourceKey, err)
				}
				if prev, ok := latest[rec.SourceKey]; ok && prev == h {
					st.RawUnchanged++
					if !opt.Renormalize {
						continue
					}
				} else {
					ins, err := storeRaw(ctx, tx, rec, h, runAt)
					if err != nil {
						return fmt.Errorf("store raw %s/%s: %w", rec.Source, rec.SourceKey, err)
					}
					if ins {
						st.RawNew++
					}
				}
				apply = append(apply, rec)
				if norm, _, err := normalizeOne(c, rec); err == nil && norm != nil {
					locks = append(locks, ghsaOnly(norm))
				}
			}
			if err := LockGHSAIDs(ctx, tx, locks); err != nil {
				return err
			}
			for _, rec := range apply {
				norm, nerr, err := normalizeOne(c, rec)
				if err != nil {
					return err
				}
				if nerr != nil {
					st.NormalizeErrors++
					errs = append(errs, rec.SourceKey+": "+nerr.Msg)
					log.Warn(fmt.Sprintf("normalize failed for %s/%s: %s", rec.Source, rec.SourceKey, nerr.Msg))
					continue
				}
				stampProfiles(norm, runAt) // every record here came from X in this run
				if err := ApplyNormalized(ctx, db, norm, runAt, st.IsBackfill || rec.IsBackfill, st); err != nil {
					return err
				}
			}
			status, errText := "ok", (*string)(nil)
			if len(errs) > 0 {
				status = "partial"
				s := strings.Join(errs[:min(len(errs), 20)], "; ")
				errText = &s
			}
			return saveState(ctx, db, c.Name(), runAt, status, errText, res.Cursor, true)
		})
	}()
	if runErr != nil {
		msg := truncateRunes(pyTypeName(runErr)+": "+runErr.Error(), 2000)
		if err := saveState(context.WithoutCancel(ctx), conn, c.Name(), runAt, "error", &msg, nil, false); err != nil {
			log.Error("could not record failure in collector_state", "err", err)
		}
		return nil, runErr
	}
	if !opt.SkipStateRefresh {
		RefreshState(ctx, conn, log)
	}
	return st, nil
}

// RefreshState refreshes vuln_state_mat after a committed run (non-blocking
// mode of state.Refresh: if another process is refreshing, it takes over this
// request). Errors are logged, not returned: the run's data is committed and
// the state catches up on the next refresh.
func RefreshState(ctx context.Context, conn *pgx.Conn, log *slog.Logger) {
	res, err := state.Refresh(ctx, conn, state.RefreshOptions{Logger: log})
	if err != nil {
		log.Warn("derived state refresh failed (run result unaffected)", "err", err)
		return
	}
	log.Info("derived state refresh", "refreshes", res.Refreshes, "deferred", res.Deferred,
		"covered", res.Covered, "pending", res.Pending, "elapsed_ms", res.Elapsed.Milliseconds())
}

// RenormalizeOptions for Renormalize.
type RenormalizeOptions struct {
	DryRun           bool
	Now              func() time.Time
	Logger           *slog.Logger
	SkipStateRefresh bool
}

// Renormalize re-runs Normalize over the latest stored raw record of every
// key of the collector's source, with no network access, through the same
// apply path as a collect run, in one transaction (rolled back when DryRun).
//
// Differences from `collect --renormalize` (documented in docs/go.md):
// collector_state is not touched; records are processed in source_key order;
// RawRecord.IsBackfill is not stored in the database, so every event this
// creates is marked is_backfill=true (it was derived from data we already
// had, not observed live) and Stats.IsBackfill is true.
//
// On a database written by the same normalize logic, the result must show
// zero inserts and zero updates: that is the parity oracle for ports.
func Renormalize(ctx context.Context, conn *pgx.Conn, c collector.Collector, opt RenormalizeOptions) (*Stats, error) {
	o := Options{Now: opt.Now, Logger: opt.Logger}
	runAt := o.now()
	log := o.log()
	st := &Stats{Source: c.Name(), IsBackfill: true}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after Commit
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (source_key) source_key, payload::text, fetched_at
           FROM raw_record WHERE source = $1
           ORDER BY source_key, fetched_at DESC, id DESC`, c.Name())
	if err != nil {
		return nil, err
	}
	type kv struct {
		key, payload string
		fetched      time.Time
	}
	recs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (kv, error) {
		var x kv
		return x, r.Scan(&x.key, &x.payload, &x.fetched)
	})
	if err != nil {
		return nil, err
	}
	db := tx
	// the GHSA-id locks first (see RunCollector)
	var locks []*model.Normalized
	for _, r := range recs {
		if payload, err := pyjson.DecodeString(r.payload); err == nil {
			if norm, _, err := normalizeOne(c, model.RawRecord{Source: c.Name(), SourceKey: r.key, Payload: payload}); err == nil && norm != nil {
				locks = append(locks, ghsaOnly(norm))
			}
		}
	}
	if err := LockGHSAIDs(ctx, tx, locks); err != nil {
		return nil, err
	}
	for _, r := range recs {
		payload, err := pyjson.DecodeString(r.payload)
		if err != nil {
			return nil, fmt.Errorf("raw_record %s/%s: %w", c.Name(), r.key, err)
		}
		rec := model.RawRecord{Source: c.Name(), SourceKey: r.key, Payload: payload}
		st.Fetched++
		st.RawUnchanged++
		norm, nerr, err := normalizeOne(c, rec)
		if err != nil {
			return nil, err
		}
		if nerr != nil {
			st.NormalizeErrors++
			log.Warn(fmt.Sprintf("normalize failed for %s/%s: %s", rec.Source, rec.SourceKey, nerr.Msg))
			continue
		}
		stampProfiles(norm, r.fetched.UTC()) // as of the stored fetch, never the re-run
		if err := ApplyNormalized(ctx, db, norm, runAt, true, st); err != nil {
			return nil, err
		}
	}
	if opt.DryRun {
		return st, tx.Rollback(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return st, err
	}
	if !opt.SkipStateRefresh {
		RefreshState(ctx, conn, log)
	}
	return st, nil
}

// pyTypeName approximates Python's type(exc).__name__ for the stored error
// text: the Go error's concrete type name without package and pointer, or
// "Error" for anonymous standard-library error types.
func pyTypeName(err error) string {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			break
		}
		err = u
	}
	t := reflect.TypeOf(err)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch n := t.Name(); n {
	case "", "errorString", "wrapError", "wrapErrors", "joinError":
		return "Error"
	default:
		return n
	}
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
