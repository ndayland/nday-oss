package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// GHSA-keyed vulnerabilities (docs/ghsa.md).
//
// A GitHub advisory without a CVE is stored as a vuln keyed by its GHSA id.
// Once some record says which CVE the advisory belongs to (the advisory
// itself gaining a cve_id, or a CVE record naming it, both written as the
// alias (ghsa, G) -> C), the GHSA-keyed row and everything attached to it
// move to the CVE and only the alias stays. Two rules keep that true:
//
//   - redirectGHSA: rows a record wants to write under a GHSA id that is
//     already an alias go to the alias's vuln instead;
//   - mergeVuln: writing such an alias while the GHSA-keyed row exists
//     moves that row's data over and deletes it.
//
// So a GHSA-keyed vuln never sits next to an alias row for the same GHSA id.
//
// Concurrency: two runs can meet on one GHSA id (the ghsa collector writing
// the GHSA-keyed row, cvelist writing the alias). Both take the same
// transaction-level advisory lock on the GHSA id (lockVulnID) before they
// look at the alias or the row, so one of them sees what the other
// committed: either the alias (and redirects), or the row (and merges it).
// A collector run is one transaction holding every lock until it commits,
// so RunCollector and Renormalize take the GHSA-id locks of all their
// records up front (LockGHSAIDs), before any vuln row lock: two runs then
// cannot hold a vuln row while waiting for a GHSA-id lock the other holds.
// Row locks between runs can still meet in opposite orders (as they always
// could for CVE rows); PostgreSQL then aborts one run, which rolls back
// whole and is retried at its next start (docs/ghsa.md). The merge's lock
// order against the site's writes (comments, corrections) is explained at
// lockForMerge.

// redirectGHSA returns norm with every row keyed by a GHSA id that is
// already an alias of another vuln rewritten to that vuln (norm itself is
// not changed). The vuln upsert becomes a stub, like the one an advisory
// with a CVE brings. The advisory's own disclosed event goes along only
// while the target has no disclosed event from another source (the CVE
// record owns disclosure; see dropGHSADisclosed).
func redirectGHSA(ctx context.Context, db execer, norm *model.Normalized) (*model.Normalized, error) {
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		if strings.HasPrefix(id, "GHSA-") && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, v := range norm.Vulns {
		add(v.CVEID)
	}
	for _, a := range norm.Aliases {
		add(a.CVEID)
	}
	for _, a := range norm.Affected {
		add(a.CVEID)
	}
	for _, e := range norm.Events {
		add(e.CVEID)
	}
	// Lock every GHSA id this record touches, as a vuln id or as a ghsa
	// alias, in one order, before this record locks any vuln row
	// (upsertVuln, mergeVuln). That alone orders the locks of one record
	// only: a run's earlier records may already hold vuln rows, which is why
	// the runs take all these locks before their first record
	// (LockGHSAIDs); here they are then taken again at no cost.
	if err := lockGHSAIDs(ctx, db, ghsaLockIDs(norm, nil)); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return norm, nil
	}
	rows, err := db.Query(ctx, `SELECT alias, cve_id FROM vuln_alias
           WHERE alias_type = 'ghsa' AND alias = ANY($1) AND cve_id <> alias`, ids)
	if err != nil {
		return nil, err
	}
	to := map[string]string{}
	for rows.Next() {
		var g, c string
		if err := rows.Scan(&g, &c); err != nil {
			rows.Close()
			return nil, err
		}
		to[g] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(to) == 0 {
		return norm, nil
	}
	out := *norm
	out.Vulns = nil
	for _, v := range norm.Vulns {
		if c, ok := to[v.CVEID]; ok {
			v = model.VulnUpsert{CVEID: c, Title: v.Title, Description: v.Description}
		}
		out.Vulns = append(out.Vulns, v)
	}
	out.Aliases = nil
	for _, a := range norm.Aliases {
		if c, ok := to[a.CVEID]; ok {
			a.CVEID = c
		}
		out.Aliases = append(out.Aliases, a)
	}
	out.Affected = nil
	for _, a := range norm.Affected {
		if c, ok := to[a.CVEID]; ok {
			a.CVEID = c
		}
		out.Affected = append(out.Affected, a)
	}
	out.Events = nil
	for _, e := range norm.Events {
		if c, ok := to[e.CVEID]; ok {
			e.CVEID = c
			if e.Type == model.EventDisclosed && e.Source == ghsaSource {
				var other bool
				if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM event
                       WHERE cve_id = $1 AND type = 'disclosed' AND source <> 'ghsa')`, c).Scan(&other); err != nil {
					return nil, err
				}
				if other {
					continue
				}
			}
		}
		out.Events = append(out.Events, e)
	}
	return &out, nil
}

// ghsaLockIDs adds to set (nil: a new one) every GHSA id norm touches, as a
// vuln id or as a ghsa alias, and returns it.
func ghsaLockIDs(norm *model.Normalized, set map[string]bool) map[string]bool {
	if set == nil {
		set = map[string]bool{}
	}
	add := func(id string) {
		if model.IsGHSAID(id) {
			set[id] = true
		}
	}
	for _, v := range norm.Vulns {
		add(v.CVEID)
	}
	for _, a := range norm.Aliases {
		add(a.CVEID)
		if a.AliasType == ghsaSource {
			add(a.Alias)
		}
	}
	for _, a := range norm.Affected {
		add(a.CVEID)
	}
	for _, e := range norm.Events {
		add(e.CVEID)
	}
	return set
}

// lockGHSAIDs takes lockVulnID of every id in set, in sorted order.
func lockGHSAIDs(ctx context.Context, db execer, set map[string]bool) error {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := lockVulnID(ctx, db, id); err != nil {
			return err
		}
	}
	return nil
}

// LockGHSAIDs takes, inside db's transaction, the GHSA-id locks of every
// record a run is about to apply, before the run locks any vuln row (see
// "Concurrency" above). RunCollector and Renormalize call it; a bulk
// importer that applies records with ApplyNormalized in one transaction
// should too.
func LockGHSAIDs(ctx context.Context, db Execer, norms []*model.Normalized) error {
	set := map[string]bool{}
	for _, n := range norms {
		ghsaLockIDs(n, set)
	}
	return lockGHSAIDs(ctx, db, set)
}

// ghsaOnly keeps of norm only the rows that name GHSA ids, for LockGHSAIDs
// (so a run does not hold every normalized record in memory).
func ghsaOnly(norm *model.Normalized) *model.Normalized {
	out := &model.Normalized{}
	for id := range ghsaLockIDs(norm, nil) {
		out.Vulns = append(out.Vulns, model.VulnUpsert{CVEID: id})
	}
	return out
}

// lockVulnID takes the transaction-level advisory lock of a GHSA id (held
// until commit or rollback). The key is a 64-bit hash of a prefixed id, so
// it cannot meet the other advisory locks of the project (classify, tags,
// state refresh use fixed keys in other ranges with overwhelming odds).
func lockVulnID(ctx context.Context, db execer, id string) error {
	_, err := db.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nday.vuln-id:' || $1, 0))`, id)
	return err
}

// ghsaSource is the ghsa collector's name (not imported: the pipeline does
// not depend on collectors).
const ghsaSource = "ghsa"

// mergeGHSAAliases runs mergeVuln for every ghsa alias of norm whose GHSA id
// still has a vuln row of its own, into the vuln the alias row points at
// (the stored row: on a conflict the first CVE an advisory named keeps it).
func mergeGHSAAliases(ctx context.Context, db execer, norm *model.Normalized) error {
	for _, a := range norm.Aliases {
		if a.AliasType != ghsaSource || !model.IsGHSAID(a.Alias) {
			continue
		}
		// (redirectGHSA took the GHSA id's lock already)
		var target string
		err := db.QueryRow(ctx, `SELECT a.cve_id FROM vuln_alias a
               WHERE a.alias_type = 'ghsa' AND a.alias = $1 AND a.cve_id <> a.alias
                 AND EXISTS (SELECT 1 FROM vuln v WHERE v.cve_id = a.alias)`, a.Alias).Scan(&target)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := mergeVuln(ctx, db, a.Alias, target, nil); err != nil {
			return fmt.Errorf("merge %s into %s: %w", a.Alias, target, err)
		}
	}
	return nil
}

// MergeCounts is what one mergeVuln did: rows moved to the target and rows
// dropped because the target already had the same key, per table.
type MergeCounts struct {
	From, Into    string
	Merged        bool // false: from had no vuln row (nothing to do)
	CreatedTarget bool
	// Withdrawn: the advisory from stands for was withdrawn, so its own
	// rows were dropped instead of moved (see mergeVuln).
	Withdrawn bool
	Moved     map[string]int
	Dropped   map[string]int
}

// mergeMove is one table whose rows follow the vuln. key lists the columns
// that, with cve_id, make a row unique; nil means cve_id is in no unique
// key, so every row just moves.
type mergeMove struct {
	table string
	key   []string
}

// The tables that hold a vuln id, in the order they are moved. event and
// x_draft are handled on their own (see mergeVuln); classify_queue and
// tag_queue hold pending work, which moves too.
var mergeMoves = []mergeMove{
	{"vuln_alias", nil},
	{"affected", []string{"vendor", "product"}},
	{"vuln_cwe", []string{"cwe", "source", "source_org"}},
	{"vuln_cvss", []string{"version", "source", "source_org"}},
	{"vuln_classify_input", []string{"source", "source_key"}},
	{"vuln_tag", []string{"tag", "origin"}},
	{"vuln_tag_suppress", []string{"tag"}},
	{"x_post_no_cve_link", []string{"post_id"}},
	// comments: one UPDATE moves top-level comments and their replies
	// together, so the composite self-reference (parent_id, cve_id,
	// parent_is_reply) holds at the end of the statement (NO ACTION
	// constraints are checked there, they need not be deferrable).
	{"comments", nil},
	{"vuln_corrections", nil},
	{"classify_queue", nil},
	{"tag_queue", nil},
}

// advisoryRows are the rows of a GHSA-keyed vuln that its advisory itself
// produced (normalize and classify, source ghsa) or that are derived from
// them (rule tags; recomputed for the target anyway). A withdrawn advisory
// contributes nothing to a CVE, so mergeVuln drops these instead of moving
// them.
var advisoryRows = []struct{ table, cond string }{
	{"event", "source = 'ghsa'"},
	{"vuln_cwe", "source = 'ghsa'"},
	{"vuln_cvss", "source = 'ghsa'"},
	{"vuln_classify_input", "source = 'ghsa'"},
	{"vuln_tag", "origin = 'rule'"},
}

// mergeVuln moves the vuln keyed by from (a GHSA id) and every row attached
// to it to into (a CVE id), then deletes from's vuln row. It runs inside the
// caller's transaction and locks both vuln rows FOR UPDATE (after from's
// comments, see lockForMerge), so nothing can attach a row to from while it
// moves. Where into already has a row with the same key, into's row is kept
// and from's is dropped, except for x_draft (see mergeDrafts). Nothing a user
// wrote is dropped: comments and corrections have no such key and always
// move.
//
// from's own disclosed event (source ghsa) moves only when into has no
// disclosed event from another source: until the CVE record is ingested
// it is the vulnerability's only disclosure; once it is, the CVE record's
// event replaces it (dropGHSADisclosed).
//
// A withdrawn advisory (advisoryWithdrawn) contributes nothing to the CVE:
// its own rows (advisoryRows) are dropped, and the target takes none of
// its fields; everything else (comments, corrections, staff tags, drafts,
// other sources' events) still moves.
//
// The target gets the source's title/description/times where its own are
// empty (stub rule) and the earlier first_seen_at. Classification and tags
// of into are queued for recomputation; vuln_state_mat catches up at the
// refresh after the run. Idempotent: with no vuln row for from it does
// nothing.
func mergeVuln(ctx context.Context, db execer, from, into string, log *slog.Logger) (*MergeCounts, error) {
	mc := &MergeCounts{From: from, Into: into, Moved: map[string]int{}, Dropped: map[string]int{}}
	if from == into {
		return mc, nil
	}
	if !model.IsGHSAID(from) || !model.IsValidVulnID(into) {
		return nil, fmt.Errorf("merge %s into %s: not a GHSA id into a vuln id", pyjson.StrRepr(from), pyjson.StrRepr(into))
	}
	if log == nil {
		log = slog.Default()
	}
	have, err := lockForMerge(ctx, db, from, into)
	if err != nil {
		return nil, err
	}
	hasFrom, hasInto := false, false
	for _, id := range have {
		hasFrom = hasFrom || id == from
		hasInto = hasInto || id == into
	}
	if !hasFrom {
		return mc, nil
	}
	mc.Merged = true
	if mc.Withdrawn, err = advisoryWithdrawn(ctx, db, from); err != nil {
		return nil, err
	}
	switch {
	case !hasInto && mc.Withdrawn:
		tag, err := db.Exec(ctx, `INSERT INTO vuln (cve_id, first_seen_at) SELECT $2, first_seen_at FROM vuln WHERE cve_id = $1`, from, into)
		if err != nil {
			return nil, err
		}
		mc.CreatedTarget = tag.RowsAffected() == 1
	case !hasInto:
		tag, err := db.Exec(ctx, `INSERT INTO vuln (cve_id, title, description, title_zh, summary_zh,
                                 published_at, modified_at, first_seen_at)
               SELECT $2, title, description, title_zh, summary_zh, published_at, modified_at, first_seen_at
               FROM vuln WHERE cve_id = $1`, from, into)
		if err != nil {
			return nil, err
		}
		mc.CreatedTarget = tag.RowsAffected() == 1
	case mc.Withdrawn:
		// nothing of the advisory's text or times
	default:
		// stub rule: fill what the target lacks, never overwrite
		if _, err := db.Exec(ctx, `UPDATE vuln t SET
                   title         = CASE WHEN COALESCE(t.title, '') = '' THEN s.title ELSE t.title END,
                   description   = CASE WHEN COALESCE(t.description, '') = '' THEN s.description ELSE t.description END,
                   title_zh      = CASE WHEN COALESCE(t.title_zh, '') = '' THEN s.title_zh ELSE t.title_zh END,
                   summary_zh    = CASE WHEN COALESCE(t.summary_zh, '') = '' THEN s.summary_zh ELSE t.summary_zh END,
                   published_at  = COALESCE(t.published_at, s.published_at),
                   modified_at   = COALESCE(t.modified_at, s.modified_at),
                   first_seen_at = LEAST(t.first_seen_at, s.first_seen_at),
                   updated_at    = now()
               FROM vuln s
               WHERE t.cve_id = $2 AND s.cve_id = $1
                 AND (t.title, t.description, t.title_zh, t.summary_zh, t.published_at, t.modified_at, t.first_seen_at)
                     IS DISTINCT FROM
                     (CASE WHEN COALESCE(t.title, '') = '' THEN s.title ELSE t.title END,
                      CASE WHEN COALESCE(t.description, '') = '' THEN s.description ELSE t.description END,
                      CASE WHEN COALESCE(t.title_zh, '') = '' THEN s.title_zh ELSE t.title_zh END,
                      CASE WHEN COALESCE(t.summary_zh, '') = '' THEN s.summary_zh ELSE t.summary_zh END,
                      COALESCE(t.published_at, s.published_at), COALESCE(t.modified_at, s.modified_at),
                      LEAST(t.first_seen_at, s.first_seen_at))`, from, into); err != nil {
			return nil, err
		}
	}
	if mc.Withdrawn {
		for _, r := range advisoryRows {
			tag, err := db.Exec(ctx, "DELETE FROM "+r.table+" WHERE cve_id = $1 AND "+r.cond, from)
			if err != nil {
				return nil, fmt.Errorf("drop %s: %w", r.table, err)
			}
			mc.Dropped[r.table] += int(tag.RowsAffected())
		}
	}

	// events: the advisory's disclosed event first (see above), then
	// drafts pointing at an event about to be dropped follow the target's
	// event of the same key, then the rest moves.
	tag, err := db.Exec(ctx, `DELETE FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'
           AND EXISTS (SELECT 1 FROM event WHERE cve_id = $2 AND type = 'disclosed' AND source <> 'ghsa')`, from, into)
	if err != nil {
		return nil, err
	}
	mc.Dropped["event"] += int(tag.RowsAffected())
	if _, err := db.Exec(ctx, `UPDATE x_draft d SET event_id = t.id
           FROM event s JOIN event t ON t.cve_id = $2 AND t.type = s.type AND t.source = s.source
                                    AND t.dedupe_key = s.dedupe_key
           WHERE s.cve_id = $1 AND d.event_id = s.id`, from, into); err != nil {
		return nil, err
	}
	if err := moveRows(ctx, db, mergeMove{"event", []string{"type", "source", "dedupe_key"}}, from, into, mc); err != nil {
		return nil, err
	}
	if err := mergeDrafts(ctx, db, from, into, mc, log); err != nil {
		return nil, err
	}
	for _, m := range mergeMoves {
		if err := moveRows(ctx, db, m, from, into, mc); err != nil {
			return nil, err
		}
	}
	// vuln_title (migration 0031): the staff title follows the
	// vulnerability unless the target has its own (staff wrote it, like a
	// comment); from's composed parts go with its vuln row (ON DELETE
	// CASCADE): the target's are recomposed by the tag pass (tag_queue below).
	var hadStaff bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln_title WHERE cve_id = $1 AND staff_title IS NOT NULL)`, from).Scan(&hadStaff); err != nil {
		return nil, err
	}
	if hadStaff {
		tag, err := db.Exec(ctx, `INSERT INTO vuln_title AS t (cve_id, staff_title, staff_by, staff_at, staff_version)
               SELECT $2, s.staff_title, s.staff_by, s.staff_at, 1 FROM vuln_title s WHERE s.cve_id = $1
               ON CONFLICT (cve_id) DO UPDATE SET staff_title = EXCLUDED.staff_title, staff_by = EXCLUDED.staff_by,
                   staff_at = EXCLUDED.staff_at, staff_version = t.staff_version + 1
               WHERE t.staff_title IS NULL`, from, into)
		if err != nil {
			return nil, fmt.Errorf("move vuln_title: %w", err)
		}
		if tag.RowsAffected() == 1 {
			mc.Moved["vuln_title"]++
		} else {
			mc.Dropped["vuln_title"]++
		}
	}
	if _, err := db.Exec(ctx, `DELETE FROM vuln WHERE cve_id = $1`, from); err != nil {
		return nil, err
	}
	// The moves above already queue both ids where triggers watch the
	// tables (vuln_cwe, vuln_cvss, vuln_classify_input, event, ...); these
	// make sure the target is recomputed even when nothing watched moved.
	if _, err := db.Exec(ctx, `INSERT INTO classify_queue (cve_id) VALUES ($1)`, into); err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, `INSERT INTO tag_queue (cve_id) VALUES ($1)`, into); err != nil {
		return nil, err
	}
	log.Info(fmt.Sprintf("merged vuln %s into %s", from, into), "created_target", mc.CreatedTarget,
		"withdrawn", mc.Withdrawn, "moved", countsText(mc.Moved), "dropped", countsText(mc.Dropped))
	return mc, nil
}

// draftRank orders x_draft statuses by how far staff got with a draft.
const draftRank = `CASE %[1]s.status WHEN 'posted' THEN 3 WHEN 'discarded' THEN 2 ELSE 1 END`

// mergeDrafts moves from's drafts to into. x_draft holds one draft per
// (vuln, stage); where both have one, the one staff got furthest with stays
// (posted > discarded > draft, the statuses of migrations/0012; into's on a
// tie) and the other is deleted. Deleting a decided draft (posted or
// discarded) is logged at warn level with its id, stage, status and
// post_url, so no staff decision disappears without trace; admin_audit
// rows naming it (target x_draft, target_id = its id, no foreign key) stay
// as they are (the table is append-only), and their link on the audit page
// then points at a draft that no longer exists.
func mergeDrafts(ctx context.Context, db execer, from, into string, mc *MergeCounts, log *slog.Logger) error {
	rows, err := db.Query(ctx, `DELETE FROM x_draft d USING x_draft s, x_draft t
           WHERE s.cve_id = $1 AND t.cve_id = $2 AND s.stage = t.stage
             AND d.id = CASE WHEN `+fmt.Sprintf(draftRank, "s")+` > `+fmt.Sprintf(draftRank, "t")+` THEN t.id ELSE s.id END
           RETURNING d.id, d.cve_id, d.stage, d.status, COALESCE(d.post_url, ''), CASE WHEN d.id = s.id THEN t.id ELSE s.id END`,
		from, into)
	if err != nil {
		return fmt.Errorf("drop x_draft: %w", err)
	}
	type dropped struct {
		id, kept                int64
		cve, stage, status, url string
	}
	drops, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (dropped, error) {
		var x dropped
		return x, r.Scan(&x.id, &x.cve, &x.stage, &x.status, &x.url, &x.kept)
	})
	if err != nil {
		return fmt.Errorf("drop x_draft: %w", err)
	}
	mc.Dropped["x_draft"] += len(drops)
	for _, x := range drops {
		if x.status != "draft" {
			log.Warn(fmt.Sprintf("merge of %s into %s dropped a decided x_draft", from, into), "id", x.id, "cve", x.cve,
				"stage", x.stage, "status", x.status, "post_url", x.url, "kept", x.kept)
		}
	}
	return moveRows(ctx, db, mergeMove{"x_draft", []string{"stage"}}, from, into, mc)
}

// advisoryWithdrawn reports whether the advisory a GHSA-keyed vuln stands
// for is withdrawn: by its latest stored raw record (the ghsa run stores it
// before it applies it, so this sees the version that is being applied,
// also when that version is withdrawn and names the CVE at once, where
// normalize returns only the alias), or, without a raw record, by its
// disclosed event (state REJECTED).
func advisoryWithdrawn(ctx context.Context, db execer, id string) (bool, error) {
	var w bool
	err := db.QueryRow(ctx, `SELECT COALESCE(
               (SELECT payload->>'withdrawn_at' IS NOT NULL FROM raw_record
                WHERE source = 'ghsa' AND source_key = $1 ORDER BY fetched_at DESC, id DESC LIMIT 1),
               EXISTS (SELECT 1 FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'
                       AND detail->>'state' = 'REJECTED'))`, id).Scan(&w)
	return w, err
}

// correctionsVulnLock is the key prefix of the per-vulnerability advisory
// lock internal/corrections takes around a submission (its lock(ctx, tx,
// "vuln", id): "nday.corrections." + kind + ":" + key, hashed the same way).
const correctionsVulnLock = "nday.corrections.vuln:"

// mergeLockAttempts bounds how often lockForMerge backs off.
const mergeLockAttempts = 10

// lockForMerge takes the merge's locks and returns which of from and into
// have a vuln row. The order is what keeps the site's writes from
// deadlocking with a merge:
//
//  1. corrections' per-vulnerability advisory lock of from. A submission
//     takes it before its INSERT needs from's vuln row (foreign key), so it
//     either commits before the merge goes on (and its correction moves) or
//     waits here and then finds no vulnerability (ErrNoVuln).
//  2. from's threads (top-level comments, the rows a reply locks; the
//     partial index comments_cve_top_idx) FOR UPDATE, waiting for whoever
//     holds one: an edit, hide, delete or report (they need no other lock
//     the merge holds) or a reply, which locks its parent FOR SHARE and then
//     needs from's vuln row (foreign key; KEY SHARE). The merge does not
//     hold that row yet, so the reply commits and the merge goes on. (A
//     reply row held by an edit only makes the final UPDATE wait; that
//     holder needs nothing the merge holds.)
//  3. both vuln rows FOR UPDATE, in id order. This waits for new comments
//     and corrections in flight (they hold KEY SHARE and need nothing the
//     merge holds) and from then on blocks new ones; once the merge commits
//     they find the vuln gone (the not-found error).
//  4. from's threads again, FOR UPDATE NOWAIT: a thread committed between
//     2 and 3 may already be locked by a reply that now waits for step 3's
//     row. Waiting for it would close the cycle, so the merge instead rolls
//     back to before step 2 (releasing the vuln rows), and starts over; the
//     reply then commits. A bounded number of attempts, then the run fails
//     (and is retried at the next start).
//
// The collector run may already hold into's row (its upsert of the record
// being applied); no site write holds a comment of from while it waits for
// into's row, so that cannot close a cycle either. Outside a transaction
// (tests, one-off repairs on a plain connection) it only reads the rows.
func lockForMerge(ctx context.Context, db execer, from, into string) ([]string, error) {
	if !inTransaction(db) {
		return lockVulnRows(ctx, db, from, into)
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, correctionsVulnLock+from); err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		if _, err := db.Exec(ctx, `SAVEPOINT nday_merge_locks`); err != nil {
			return nil, err
		}
		have, err := func() ([]string, error) {
			if _, err := db.Exec(ctx, `SELECT 1 FROM comments WHERE cve_id = $1 AND parent_id IS NULL ORDER BY id FOR UPDATE`, from); err != nil {
				return nil, err
			}
			have, err := lockVulnRows(ctx, db, from, into)
			if err != nil {
				return nil, err
			}
			if _, err := db.Exec(ctx, `SELECT 1 FROM comments WHERE cve_id = $1 AND parent_id IS NULL ORDER BY id FOR UPDATE NOWAIT`, from); err != nil {
				return nil, err
			}
			return have, nil
		}()
		if err == nil {
			_, err = db.Exec(ctx, `RELEASE SAVEPOINT nday_merge_locks`)
			return have, err
		}
		if !lockNotAvailable(err) || attempt == mergeLockAttempts {
			return nil, fmt.Errorf("merge %s into %s: lock: %w", from, into, err)
		}
		// row locks taken after the savepoint are released with it
		if _, err := db.Exec(ctx, `ROLLBACK TO SAVEPOINT nday_merge_locks`); err != nil {
			return nil, err
		}
	}
}

func lockVulnRows(ctx context.Context, db execer, from, into string) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT cve_id FROM vuln WHERE cve_id = ANY($1) ORDER BY cve_id FOR UPDATE`,
		[]string{from, into})
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// inTransaction: db is a pgx.Tx, or a connection inside a transaction.
func inTransaction(db execer) bool {
	switch x := db.(type) {
	case pgx.Tx:
		return true
	case *pgx.Conn:
		return x.PgConn().TxStatus() != 'I'
	}
	return false
}

// lockNotAvailable: SQLSTATE 55P03 (NOWAIT, lock_timeout).
func lockNotAvailable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

// moveRows moves m.table's rows from -> into, then deletes from's rows left
// over (those whose key the target already had). Table and column names
// are constants of this file.
func moveRows(ctx context.Context, db execer, m mergeMove, from, into string, mc *MergeCounts) error {
	cond := ""
	if len(m.key) > 0 {
		var eq []string
		for _, k := range m.key {
			eq = append(eq, "t."+k+" = s."+k)
		}
		cond = " AND NOT EXISTS (SELECT 1 FROM " + m.table + " t WHERE t.cve_id = $2 AND " + strings.Join(eq, " AND ") + ")"
	}
	tag, err := db.Exec(ctx, "UPDATE "+m.table+" s SET cve_id = $2 WHERE s.cve_id = $1"+cond, from, into)
	if err != nil {
		return fmt.Errorf("move %s: %w", m.table, err)
	}
	if n := int(tag.RowsAffected()); n > 0 {
		mc.Moved[m.table] += n
	}
	if len(m.key) == 0 {
		return nil
	}
	tag, err = db.Exec(ctx, "DELETE FROM "+m.table+" WHERE cve_id = $1", from)
	if err != nil {
		return fmt.Errorf("drop %s: %w", m.table, err)
	}
	if n := int(tag.RowsAffected()); n > 0 {
		mc.Dropped[m.table] += n
	}
	return nil
}

func countsText(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	return b.String()
}

// dropGHSADisclosed removes the GHSA-sourced disclosed event of cveID: it
// stood in for the disclosure while only the advisory was known, and the
// CVE record's disclosed event (just written) replaces it.
func dropGHSADisclosed(ctx context.Context, db execer, cveID string) error {
	_, err := db.Exec(ctx, `DELETE FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'`, cveID)
	return err
}

// MergeVulnID is mergeVuln for tests and one-off repairs: it moves the
// GHSA-keyed vuln from and everything attached to it to into, inside db's
// transaction. See mergeVuln.
func MergeVulnID(ctx context.Context, db Execer, from, into string, log *slog.Logger) (*MergeCounts, error) {
	return mergeVuln(ctx, db, from, into, log)
}
