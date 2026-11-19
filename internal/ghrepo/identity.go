package ghrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The data model (docs/github.md "Identity, names, links"; migration 0025).
//
//   - A github_repo row whose github_id is set IS that GitHub repository
//     for good. Nothing here changes a non-NULL github_id (the database
//     refuses it: trigger github_repo_keep_id), deletes such a row or
//     merges two of them. Its review status is about that repository.
//   - A row with github_id NULL is a placeholder for a queued name: no
//     status (CHECK), listed nowhere. It either becomes the identity that
//     answers for its name (claim, the one statement that writes a
//     github_id into an existing row) or is folded into the row that
//     identity already has (absorb: its 'post' associations move, the
//     placeholder is deleted).
//   - github_repo_name maps a name key to at most one row: the identity
//     that most recently answered for the key (its current lower-cased
//     full_name) or a placeholder. An identity holds no other key.
//   - Rule trust comes only from stamps on root links (stampLinks); owner
//     trust only from the list of trusted accounts (owner.go).
//
// Every function below runs inside the caller's transaction, after
// lockStore.

// lockStore serialises the writers of github_repo_name (storeLockID) until
// the end of the transaction (tx must be one). It is always taken before
// any github_repo row lock: by the sweep, by the stores of the passes, and
// by an admin decision (GetForUpdate).
func lockStore(ctx context.Context, tx DB) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext(current_schema()))`, storeLockID)
	return err
}

// answer says how a repository object was obtained.
type answer struct {
	// key is the name key that was asked by name; "" for a request by id
	// and for a search result.
	key string
	// row is the github_repo row the request was made for (a placeholder
	// asked by name, an identity asked by id); 0 = none.
	row int64
	// etag of the response ("" = none; the stored one is then cleared).
	etag string
	// source is first_source of a row created for a new identity.
	source string
}

// observed is the result of observe.
type observed struct {
	id       int64 // the identity's row
	added    bool  // a new row was inserted for it
	absorbed int   // placeholders folded into it
}

// observe records that GitHub just returned the public repository r: the
// identity r.ID exists and its current name is r.FullName.
//
//  1. The identity's row is the row with that github_id. When there is
//     none: for an answer BY NAME, the placeholder the request was made
//     for, else the one queued under the asked key, becomes it (claim);
//     otherwise (search, or no such placeholder) a new row is inserted. A
//     search result never claims a placeholder: a placeholder was queued by
//     a post link, and only the answer for its own key may turn it into a
//     repository. A row that already has a github_id is never given
//     another one.
//  2. Names: the identity ends up holding exactly one key, its current
//     name. A key it held before is released. The asked key, when it is
//     not the current name (the answer came through GitHub's redirect of an
//     old name), is released by whoever held it. The current name is taken
//     from whoever held it: another identity keeps its id, status and
//     metadata and just loses the key (its next refresh by id learns its
//     real name, or that it is gone); a placeholder is absorbed when this
//     is an answer by name, and otherwise only loses the key (it stays
//     queued and is resolved by the request for its own name).
//  3. Metadata, seen_at, the content-based CVE associations.
//  4. Rejected names: an admin-rejected identity records the key it now
//     holds; an identity no admin decided about that turns up under a key
//     recorded for ANOTHER identity's rejection becomes rejected by rule.
//  5. Trusted accounts (syncOwners): an identity nobody decided about whose
//     owner is listed becomes trusted by 'owner'; one trusted by 'owner'
//     whose owner is no longer listed (transferred) goes back.
//
// observe never grants trust other than 'owner' and never touches an
// admin's decision.
func observe(ctx context.Context, tx pgx.Tx, r *Repo, a answer, now time.Time) (observed, error) {
	var o observed
	cur := strings.ToLower(r.FullName)
	err := tx.QueryRow(ctx, `SELECT id FROM github_repo WHERE github_id = $1 FOR NO KEY UPDATE`, r.ID).Scan(&o.id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = pgx.ErrNoRows
		if a.key != "" {
			err = tx.QueryRow(ctx, `SELECT p.id FROM github_repo p LEFT JOIN github_repo_name n ON n.repo_id = p.id
                WHERE p.github_id IS NULL AND (p.id = $1 OR n.name_key = $2)
                ORDER BY (p.id = $1) DESC, p.id LIMIT 1`, a.row, a.key).Scan(&o.id)
		}
		switch {
		case err == nil:
			if err := claim(ctx, tx, o.id, r.ID); err != nil {
				return o, err
			}
		case errors.Is(err, pgx.ErrNoRows):
			if err := tx.QueryRow(ctx, `INSERT INTO github_repo (github_id, queued_name, first_source) VALUES ($1, $2, $3) RETURNING id`,
				r.ID, cur, a.source).Scan(&o.id); err != nil {
				return o, err
			}
			o.added = true
		default:
			return o, err
		}
	case err != nil:
		return o, err
	}
	// names
	if a.key != "" && a.key != cur {
		if err := releaseKey(ctx, tx, a.key, o.id, &o.absorbed); err != nil {
			return o, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM github_repo_name WHERE repo_id = $1 AND name_key <> $2`, o.id, cur); err != nil {
		return o, err
	}
	if err := takeKey(ctx, tx, cur, o.id, a.key != "", &o.absorbed); err != nil {
		return o, err
	}
	if a.key != "" && a.row != 0 && a.row != o.id {
		// the placeholder the request was made for, if it held no key
		n, err := absorb(ctx, tx, a.row, o.id)
		if err != nil {
			return o, err
		}
		o.absorbed += n
	}
	// metadata (never github_id, status, status_by)
	var ownerID *int64
	if r.OwnerID > 0 {
		ownerID = &r.OwnerID
	}
	// unknown stars stay NULL, so the skipped-fork test (skippedForkSQL)
	// never treats them as 0
	var stars *int
	if r.StarsKnown {
		stars = &r.Stars
	}
	if _, err := tx.Exec(ctx, `UPDATE github_repo SET full_name = $2, owner_login = $3, owner_type = $4,
        description = $5, stars = $6, forks = $7, language = $8, topics = $9, is_fork = $10, is_archived = $11,
        repo_created_at = $12, pushed_at = $13, state = 'ok', attempts = 0, etag = $14, fetched_at = $15, seen_at = $15,
        owner_id = $16
        WHERE id = $1`, o.id, r.FullName, nullStr(r.OwnerLogin), nullStr(r.OwnerType), nullStr(r.Description),
		stars, r.Forks, nullStr(r.Language), nonNil(r.Topics), r.Fork, r.Archived, r.CreatedAt, r.PushedAt,
		nullStr(a.etag), now, ownerID); err != nil {
		return o, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM github_repo_cve WHERE repo_id = $1 AND basis <> 'post'`, o.id); err != nil {
		return o, err
	}
	for basis, ids := range r.Associations() {
		if _, err := tx.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT $1, unnest($2::text[]), $3
            ON CONFLICT DO NOTHING`, o.id, ids, basis); err != nil {
			return o, err
		}
	}
	// rejected names
	if _, err := tx.Exec(ctx, `INSERT INTO github_rejected_name (name_key, repo_id)
        SELECT $2, g.id FROM github_repo g WHERE g.id = $1 AND g.status = 'rejected' AND g.status_by = 'admin'
        ON CONFLICT DO NOTHING`, o.id, cur); err != nil {
		return o, err
	}
	keys := []string{cur}
	if a.key != "" {
		keys = append(keys, a.key)
	}
	if _, err := tx.Exec(ctx, `UPDATE github_repo g SET status = 'rejected', status_by = 'rule', status_at = now()
        WHERE g.id = $1 AND g.status_by IS DISTINCT FROM 'admin' AND g.status <> 'rejected'
          AND EXISTS (SELECT 1 FROM github_rejected_name j WHERE j.name_key = ANY($2) AND j.repo_id <> g.id)`, o.id, keys); err != nil {
		return o, err
	}
	// the owner is known now (or changed): trusted accounts (owner.go)
	if _, _, err := syncOwners(ctx, tx, o.id); err != nil {
		return o, err
	}
	return o, nil
}

// claim makes placeholder id the identity githubID: the only statement
// that writes a github_id into an existing row, and only into a NULL one.
func claim(ctx context.Context, tx pgx.Tx, id, githubID int64) error {
	tag, err := tx.Exec(ctx, `UPDATE github_repo SET github_id = $2 WHERE id = $1 AND github_id IS NULL`, id, githubID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("ghrepo: row %d is not a placeholder", id)
	}
	return nil
}

// absorb folds placeholder from into identity row to: its 'post'
// associations move and it is deleted (its name with it). A row that has a
// github_id is never absorbed (nothing happens). It returns the number of
// rows deleted.
func absorb(ctx context.Context, tx pgx.Tx, from, to int64) (int, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis, created_at)
        SELECT $2, c.cve_id, c.basis, c.created_at FROM github_repo_cve c JOIN github_repo p ON p.id = c.repo_id
        WHERE c.repo_id = $1 AND p.github_id IS NULL AND c.basis = 'post' ON CONFLICT DO NOTHING`, from, to); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM github_repo WHERE id = $1 AND github_id IS NULL`, from)
	return int(tag.RowsAffected()), err
}

// releaseKey takes name key away from whoever holds it without giving it
// to anyone: a placeholder is absorbed into row x, an identity just loses
// the key.
func releaseKey(ctx context.Context, tx pgx.Tx, key string, x int64, absorbed *int) error {
	var holder int64
	var gh *int64
	err := tx.QueryRow(ctx, `SELECT n.repo_id, p.github_id FROM github_repo_name n JOIN github_repo p ON p.id = n.repo_id
        WHERE n.name_key = $1`, key).Scan(&holder, &gh)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	case gh == nil && holder != x:
		n, err := absorb(ctx, tx, holder, x)
		*absorbed += n
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM github_repo_name WHERE name_key = $1`, key)
	return err
}

// takeKey points name key at identity row x: a free key is inserted (ON
// CONFLICT DO NOTHING, then looked at again: a concurrent Enqueue may have
// queued it); another identity holding it loses it; a placeholder holding
// it is absorbed into x when fold is set (an answer by name), and
// otherwise just loses the key and stays queued.
func takeKey(ctx context.Context, tx pgx.Tx, key string, x int64, fold bool, absorbed *int) error {
	for try := 0; try < 5; try++ {
		var holder int64
		var gh *int64
		err := tx.QueryRow(ctx, `SELECT n.repo_id, p.github_id FROM github_repo_name n JOIN github_repo p ON p.id = n.repo_id
            WHERE n.name_key = $1`, key).Scan(&holder, &gh)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			tag, err := tx.Exec(ctx, `INSERT INTO github_repo_name (name_key, repo_id) VALUES ($1, $2)
                ON CONFLICT (name_key) DO NOTHING`, key, x)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				return nil
			}
		case err != nil:
			return err
		case holder == x:
			return nil
		case gh == nil && fold:
			n, err := absorb(ctx, tx, holder, x)
			if err != nil {
				return err
			}
			*absorbed += n
		default:
			_, err := tx.Exec(ctx, `UPDATE github_repo_name SET repo_id = $2 WHERE name_key = $1`, key, x)
			return err
		}
	}
	return fmt.Errorf("ghrepo: name key %q kept changing hands", key)
}

// markGone makes the identity githubID 'gone' (404, 410, 451 or no longer
// public): its state only — the review status stays — and it releases its
// name, so a link to that name is queued and asked by name again. onlyOK
// limits it to an 'ok' row (search reporting a known repository as not
// public). It returns the number of rows changed.
func markGone(ctx context.Context, tx pgx.Tx, githubID int64, onlyOK bool, now time.Time) (int, error) {
	var id int64
	err := tx.QueryRow(ctx, `UPDATE github_repo SET state = 'gone', attempts = attempts + 1, fetched_at = $2
        WHERE github_id = $1 AND (NOT $3 OR state = 'ok') RETURNING id`, githubID, now, onlyOK).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, `DELETE FROM github_repo_name WHERE repo_id = $1`, id)
	return 1, err
}

// ruleHoldsSQL is the post rule's own test for identity g: some root link
// is stamped with it (stampLinks writes stamps only for links of stored
// posts, i.e. of allow-listed authors; it does not look at whether the
// author is still enabled). Owner trust falls back to it (owner.go).
const ruleHoldsSQL = `EXISTS (SELECT 1 FROM x_post_link l WHERE l.repo_github_id = g.github_id)`

// stampLinks records the outcome of a request BY NAME for key on the root
// links to that key (x_post_link.repo_root_key), and applies the trust
// rule. r is the public repository that answered, nil when there is none
// (404, 410, 451, not public).
//
//   - Links not checked yet get repo_checked_at. With late, links checked
//     before without a stamp are looked at again (the key's placeholder
//     was 'gone' and answered within its retry window).
//   - A link is stamped (repo_github_id = r.ID) only when r's creation time
//     is known and no later than the link row's created_at — the time nday
//     stored the link, which no sweep refreshes: the repository that
//     answers for the name existed when the researcher's link was stored,
//     it was not registered under the name afterwards.
//   - The trust rule, here and nowhere else: the identity r.ID is trusted
//     by rule iff nobody decided about it (owner trust doesn't count as a
//     decision: the rule replaces it) and some link is stamped with it.
//
// It returns the number of links stamped.
func stampLinks(ctx context.Context, tx pgx.Tx, key string, r *Repo, late bool, now time.Time) (int, error) {
	var gh *int64
	var created *time.Time
	if r != nil && r.CreatedAt != nil {
		gh, created = &r.ID, r.CreatedAt
	}
	rows, err := tx.Query(ctx, `UPDATE x_post_link SET repo_checked_at = COALESCE(repo_checked_at, $4),
        repo_github_id = CASE WHEN $2::bigint IS NOT NULL AND $3::timestamptz <= created_at THEN $2::bigint END
        WHERE repo_root_key = $1 AND repo_github_id IS NULL AND (repo_checked_at IS NULL OR $5)
        RETURNING repo_github_id IS NOT NULL`, key, gh, created, now, late)
	if err != nil {
		return 0, err
	}
	marks, err := pgx.CollectRows(rows, pgx.RowTo[bool])
	if err != nil {
		return 0, err
	}
	stamped := 0
	for _, m := range marks {
		if m {
			stamped++
		}
	}
	if r == nil {
		return stamped, nil
	}
	// the rule replaces owner trust when it fires: a stamp is evidence
	// about this very repository
	_, err = tx.Exec(ctx, `UPDATE github_repo g SET status = 'trusted', status_by = 'rule', status_at = now()
        WHERE g.github_id = $1 AND (g.status_by IS NULL OR g.status_by = 'owner') AND `+ruleHoldsSQL, r.ID)
	return stamped, err
}

// holdName makes sure identity row id holds the key of its stored
// full_name after a refresh that answered 304 (nothing changed at GitHub,
// so the stored name is its current name): a free key is taken, a
// placeholder holding it loses it. When ANOTHER identity holds the key —
// it answered for that name with a 200 more recently than this row's last
// 200 — the key stays there and this row's ETag is dropped instead, so its
// next refresh is unconditional and a 200 by id decides (observe).
func holdName(ctx context.Context, tx pgx.Tx, id int64) error {
	var key string
	var holds bool
	err := tx.QueryRow(ctx, `SELECT lower(g.full_name), EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = g.id)
        FROM github_repo g WHERE g.id = $1 AND g.github_id IS NOT NULL AND g.full_name IS NOT NULL`, id).Scan(&key, &holds)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && holds) {
		return nil
	}
	if err != nil {
		return err
	}
	var other bool
	err = tx.QueryRow(ctx, `SELECT p.github_id IS NOT NULL FROM github_repo_name n JOIN github_repo p ON p.id = n.repo_id
        WHERE n.name_key = $1`, key).Scan(&other)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if other {
		_, err := tx.Exec(ctx, `UPDATE github_repo SET etag = NULL WHERE id = $1`, id)
		return err
	}
	n := 0
	return takeKey(ctx, tx, key, id, false, &n)
}

// untrust takes rule trust back from the identity githubID when no link is
// stamped with it any more (the sweep cleared the last stamp: the link's
// root key changed), so an identity is trusted by rule only while a link
// is stamped with it (a stamp alone does not make it so: a repository
// trusted by owner, or seeded, may carry one); an admin's decision and a
// rejection by rule are not touched. An identity whose owner is listed
// falls back to owner trust.
func untrust(ctx context.Context, tx pgx.Tx, githubID int64) error {
	var id int64
	err := tx.QueryRow(ctx, `UPDATE github_repo g SET status = 'unverified', status_by = NULL, status_at = NULL
        WHERE g.github_id = $1 AND g.status = 'trusted' AND g.status_by = 'rule' AND NOT `+ruleHoldsSQL+` RETURNING g.id`, githubID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	// back to nobody's decision: a listed owner may vouch for it now
	_, _, err = syncOwners(ctx, tx, id)
	return err
}
