package ghrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ------------------------------------------------------------ trusted accounts
//
// GitHub accounts (users or organisations) whose repositories need no
// review (github_trusted_owner, migration 0036; docs/github.md "Trusted
// accounts"). An identity nobody decided about (status 'unverified',
// status_by NULL) whose owner is on the list and enabled is trusted with
// status_by 'owner', whatever links or stamps it has, unless it is a fork
// or a collection (those wait for a person). When the account is disabled,
// the repository moves to another owner or becomes a fork or collection,
// owner trust goes back: to 'rule' when the post rule holds for it now
// (ruleHoldsSQL, the rule's own test), else to nobody's decision. An
// admin's decision and a rejection by rule are never touched. The post
// rule replaces owner trust when it fires (stampLinks).
//
// Matching is by GitHub's numeric owner id only, on both sides: a login
// can be renamed and then registered by someone else, and a stored row's
// login may be months old. An account gets its id from the repository it
// was quick-added from, or from GET /users/{login} (LookupOwner) when it is
// added or, if that failed, by the next fetch pass (resolveOwners). Until
// then it is "id pending" and trusts nothing. A row without owner_id whose
// stored login names a listed account is only a candidate: the fetch pass
// asks it again unconditionally (ownerRefetchSQL), and the answer decides.
// A fork lives under the forker's account, so it would only match the
// forker; it is not trusted by owner anyway.
//
// An account may be linked to one allow-listed X account (x_user_id): a
// note for staff about who the researcher is. It changes no trust and is
// read only by admin pages.

// StatusByOwner is status_by of an identity trusted because its owner is
// a trusted account.
const StatusByOwner = "owner"

// Errors of the account functions.
var (
	ErrOwnerExists   = errors.New("ghrepo: this account is already listed")
	ErrOwnerNotFound = errors.New("ghrepo: no such trusted account")
	ErrNoOwner       = errors.New("ghrepo: the repository's owner is not known")
	// ErrLoginNotFound: GitHub says no account has that login (404).
	ErrLoginNotFound = errors.New("ghrepo: no GitHub account has this login")
)

// MaxOwnerNote is the longest note of an account (runes; the table's CHECK).
const MaxOwnerNote = 500

// ValidLogin reports whether s can be a GitHub login: 1 to 39 letters,
// digits and hyphens, not starting with a hyphen (old accounts may have
// double or trailing hyphens, so those are allowed).
func ValidLogin(s string) bool { return ownerRe.MatchString(s) }

// ownerMatchSQL: trusted account a covers repository r — by id only.
const ownerMatchSQL = `(a.owner_id IS NOT NULL AND r.owner_id IS NOT NULL AND a.owner_id = r.owner_id)`

// ownerEligibleSQL: repository r may be trusted by owner — not a fork, not
// a collection (the flags the public listing hides an untrusted
// repository by, internal/site AddSearchRepos).
var ownerEligibleSQL = `(NOT COALESCE(r.is_fork, false) AND (SELECT count(DISTINCT ` + vulnOfSQL + `) FROM github_repo_cve c
    WHERE c.repo_id = r.id AND c.basis <> 'post') <= ` + strconv.Itoa(CollectionMin) + `)`

// ownerCoversSQL: an enabled account covers r and r is eligible.
var ownerCoversSQL = `(` + ownerEligibleSQL + ` AND EXISTS (SELECT 1 FROM github_trusted_owner a WHERE a.enabled AND ` + ownerMatchSQL + `))`

// ownerRefetchSQL: row g has no owner id yet but its stored login names an
// enabled account; the fetch pass asks it again, unconditionally, once
// after the account was added or enabled and then at most daily ($6: now
// minus a day) until an answer gives it an id.
const ownerRefetchSQL = `(g.state = 'ok' AND g.github_id IS NOT NULL AND g.owner_id IS NULL AND g.owner_login IS NOT NULL
    AND EXISTS (SELECT 1 FROM github_trusted_owner a WHERE a.enabled AND lower(a.login) = lower(g.owner_login)
                AND g.fetched_at < GREATEST(a.updated_at, $6)))`

// LockOwners takes the store lock (lockStore) for an admin's change of the
// list: owner trust is written to github_repo rows, which the passes write
// under the same lock.
func LockOwners(ctx context.Context, tx DB) error { return lockStore(ctx, tx) }

// SyncOwners brings owner trust of every repository in line with the list
// (after an account was added, enabled, disabled or pinned). Run it in the
// transaction of the change, after LockOwners.
func SyncOwners(ctx context.Context, tx DB) (granted, reverted int, err error) {
	return syncOwners(ctx, tx, 0)
}

// syncOwners is SyncOwners for one repository row (repo > 0) or all (0):
// accounts with an id follow their owner's renames (display only: a login
// that differs other than in case, from a row fetched after the account
// last changed, so an older row never undoes a fresher lookup), then
// owner trust is taken back where no enabled account covers the
// repository any more (or it became a fork or collection) and granted
// where one does.
func syncOwners(ctx context.Context, tx DB, repo int64) (granted, reverted int, err error) {
	if _, err := tx.Exec(ctx, `UPDATE github_trusted_owner a SET login = x.login
        FROM (SELECT DISTINCT ON (r.owner_id) r.owner_id, r.owner_login AS login, r.fetched_at
              FROM github_repo r WHERE r.owner_id IS NOT NULL AND r.owner_login IS NOT NULL AND r.state = 'ok'
                AND ($1::bigint = 0 OR r.id = $1)
              ORDER BY r.owner_id, r.fetched_at DESC NULLS LAST, r.id DESC) x
        WHERE a.owner_id = x.owner_id AND lower(a.login) <> lower(x.login) AND x.fetched_at > a.updated_at
          AND NOT EXISTS (SELECT 1 FROM github_trusted_owner b WHERE b.id <> a.id AND lower(b.login) = lower(x.login))`, repo); err != nil {
		return 0, 0, err
	}
	rule := strings.ReplaceAll(ruleHoldsSQL, "g.", "r.")
	tag, err := tx.Exec(ctx, `UPDATE github_repo r SET status = CASE WHEN `+rule+` THEN 'trusted' ELSE 'unverified' END,
            status_by = CASE WHEN `+rule+` THEN 'rule' END,
            status_at = CASE WHEN `+rule+` THEN now() END
        WHERE r.status_by = 'owner' AND ($1::bigint = 0 OR r.id = $1) AND NOT `+ownerCoversSQL, repo)
	if err != nil {
		return 0, 0, err
	}
	reverted = int(tag.RowsAffected())
	tag, err = tx.Exec(ctx, `UPDATE github_repo r SET status = 'trusted', status_by = 'owner', status_at = now()
        WHERE r.status = 'unverified' AND r.status_by IS NULL AND r.github_id IS NOT NULL AND r.state = 'ok'
          AND ($1::bigint = 0 OR r.id = $1) AND `+ownerCoversSQL, repo)
	if err != nil {
		return 0, 0, err
	}
	return int(tag.RowsAffected()), reverted, nil
}

// PinOwner gives account id the owner id ownerID (and GitHub's spelling of
// its login, when login is not ""): ErrOwnerExists when another account
// has that id. Run SyncOwners after it.
func PinOwner(ctx context.Context, tx DB, id, ownerID int64, login string) error {
	var other bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM github_trusted_owner WHERE owner_id = $1 AND id <> $2)`, ownerID, id).Scan(&other); err != nil {
		return err
	}
	if other {
		return ErrOwnerExists
	}
	_, err := tx.Exec(ctx, `UPDATE github_trusted_owner a SET owner_id = $2,
            login = CASE WHEN $3 <> '' AND NOT EXISTS (SELECT 1 FROM github_trusted_owner b WHERE b.id <> a.id AND lower(b.login) = lower($3))
                         THEN $3 ELSE a.login END
        WHERE a.id = $1 AND a.owner_id IS NULL`, id, ownerID, login)
	return err
}

// OwnerLookupTimeout bounds LookupOwner.
const OwnerLookupTimeout = 10 * time.Second

// LookupOwner asks GitHub for account login (GET /users/{login}, one
// request to https://api.github.com through c): its numeric id and its
// login as GitHub spells it. ErrLoginNotFound on a 404; any other failure
// (network, rate limit, an unusable answer) is an error to retry later.
func LookupOwner(ctx context.Context, c *Client, login string) (int64, string, error) {
	if !ValidLogin(login) {
		return 0, "", ErrLoginNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerLookupTimeout)
	defer cancel()
	resp, err := c.get(ctx, "/users/"+login, "", 64<<10, 0)
	if err != nil {
		return 0, "", err
	}
	switch {
	case resp.Status == http.StatusNotFound:
		return 0, "", ErrLoginNotFound
	case resp.RateLimited():
		return 0, "", fmt.Errorf("ghrepo: user lookup rate limited (%d)", resp.Status)
	case resp.Status != http.StatusOK || resp.Body == nil:
		return 0, "", fmt.Errorf("ghrepo: user lookup answered %d", resp.Status)
	}
	var u struct {
		Login *string `json:"login"`
		ID    *int64  `json:"id"`
	}
	if err := json.Unmarshal(resp.Body, &u); err != nil || u.ID == nil || *u.ID <= 0 || u.Login == nil || !ValidLogin(*u.Login) ||
		!strings.EqualFold(*u.Login, login) {
		return 0, "", errors.New("ghrepo: unusable user lookup answer")
	}
	return *u.ID, *u.Login, nil
}

// MaxOwnerLookups is how many pending accounts one fetch pass tries to
// resolve (resolveOwners).
const MaxOwnerLookups = 5

// resolveOwners pins enabled accounts that have no id yet (their lookup
// failed when they were added), at most MaxOwnerLookups, oldest first,
// and syncs owner trust when one was pinned. A 404 leaves the account
// pending (an admin sees it); a failure stops for this pass. It returns
// the accounts pinned and the requests made.
func resolveOwners(ctx context.Context, db DB, c *Client, log *slog.Logger) (pinned, requests int, err error) {
	rows, err := db.Query(ctx, `SELECT id, login FROM github_trusted_owner WHERE enabled AND owner_id IS NULL
        ORDER BY updated_at, id LIMIT $1`, MaxOwnerLookups)
	if err != nil {
		return 0, 0, err
	}
	type acct struct {
		id    int64
		login string
	}
	todo, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (acct, error) {
		var a acct
		return a, r.Scan(&a.id, &a.login)
	})
	if err != nil {
		return 0, 0, err
	}
	for _, a := range todo {
		requests++
		oid, login, lerr := LookupOwner(ctx, c, a.login)
		if errors.Is(lerr, ErrLoginNotFound) {
			log.Info("github trusted account not found", "owner", a.id)
			continue
		}
		if lerr != nil {
			log.Info("github trusted account lookup failed; next pass", "owner", a.id, "err", lerr)
			return pinned, requests, nil
		}
		err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if err := lockStore(ctx, tx); err != nil {
				return err
			}
			if err := PinOwner(ctx, tx, a.id, oid, login); err != nil {
				return err
			}
			_, _, err := syncOwners(ctx, tx, 0)
			return err
		})
		if errors.Is(err, ErrOwnerExists) {
			log.Warn("github trusted account resolves to an id another account has", "owner", a.id)
			continue
		}
		if err != nil {
			return pinned, requests, err
		}
		pinned++
	}
	return pinned, requests, nil
}

// Owner is one trusted account. Login is cleaned API text or what an
// admin typed (ValidLogin); XHandle is the linked X account's handle as
// stored (check with xconfig.ValidHandle before display).
type Owner struct {
	ID      int64
	Login   string
	OwnerID int64 // 0 = not known yet
	Note    string
	Enabled bool
	XUserID string // linked X account (x_accounts.user_id), "" = none
	XHandle string
	// Repos: fetched repositories of this account (any status); Trusted:
	// those trusted because of it.
	Repos, Trusted int
	Created        time.Time
	Updated        time.Time
}

const ownerCols = `a.id, a.login, COALESCE(a.owner_id, 0), a.note, a.enabled, COALESCE(a.x_user_id, ''), COALESCE(x.handle, ''),
    (SELECT count(*) FROM github_repo r WHERE r.github_id IS NOT NULL AND r.state = 'ok' AND ` + ownerMatchSQL + `),
    (SELECT count(*) FROM github_repo r WHERE r.status_by = 'owner' AND ` + ownerMatchSQL + `),
    a.created_at, a.updated_at
    FROM github_trusted_owner a LEFT JOIN x_accounts x ON x.user_id = a.x_user_id`

func scanOwner(row pgx.CollectableRow) (Owner, error) {
	var o Owner
	err := row.Scan(&o.ID, &o.Login, &o.OwnerID, &o.Note, &o.Enabled, &o.XUserID, &o.XHandle, &o.Repos, &o.Trusted, &o.Created, &o.Updated)
	o.Created, o.Updated = o.Created.UTC(), o.Updated.UTC()
	return o, err
}

// CountOwners counts the listed accounts.
func CountOwners(ctx context.Context, db DB) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM github_trusted_owner`).Scan(&n)
	return n, err
}

// ListOwners returns at most limit accounts after offset: enabled first,
// then by login.
func ListOwners(ctx context.Context, db DB, limit, offset int) ([]Owner, error) {
	rows, err := db.Query(ctx, `SELECT `+ownerCols+` ORDER BY a.enabled DESC, lower(a.login), a.id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanOwner)
}

// GetOwner reads account id; with lock, its row is locked until the end of
// the transaction. ErrOwnerNotFound if absent.
func GetOwner(ctx context.Context, db DB, id int64, lock bool) (Owner, error) {
	q := `SELECT ` + ownerCols + ` WHERE a.id = $1`
	if lock {
		q += ` FOR NO KEY UPDATE OF a`
	}
	rows, err := db.Query(ctx, q, id)
	if err != nil {
		return Owner{}, err
	}
	o, err := pgx.CollectExactlyOneRow(rows, scanOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, ErrOwnerNotFound
	}
	return o, err
}

// AddOwner lists a new, enabled account: login (ValidLogin), ownerID the
// owner's GitHub id (0 = not known yet: the account is "id pending" and
// trusts nothing until it is pinned; never taken from a stored row's
// login), note, and xUserID (an x_accounts id or ""). ErrOwnerExists, with
// the listed account's id, when an account with that login
// (case-insensitively) or that owner id is listed already.
func AddOwner(ctx context.Context, tx DB, login string, ownerID int64, note, xUserID string) (int64, error) {
	var have int64
	err := tx.QueryRow(ctx, `SELECT id FROM github_trusted_owner WHERE lower(login) = lower($1) OR owner_id = $2
        ORDER BY id LIMIT 1`, login, ownerID).Scan(&have)
	switch {
	case err == nil:
		return have, ErrOwnerExists
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO github_trusted_owner (login, owner_id, note, x_user_id)
        VALUES ($1, NULLIF($2::bigint, 0), $3, NULLIF($4, '')) RETURNING id`, login, ownerID, note, xUserID).Scan(&id)
	return id, err
}

// UpdateOwner sets the note and the linked X account ("" = none) of
// account id; changed is false when both were already so.
func UpdateOwner(ctx context.Context, tx DB, id int64, note, xUserID string) (changed bool, err error) {
	tag, err := tx.Exec(ctx, `UPDATE github_trusted_owner SET note = $2, x_user_id = NULLIF($3, ''), updated_at = now()
        WHERE id = $1 AND (note <> $2 OR x_user_id IS DISTINCT FROM NULLIF($3, ''))`, id, note, xUserID)
	return tag.RowsAffected() == 1, err
}

// SetOwnerEnabled enables or disables account id (rows are never deleted);
// changed is false when it already was. Run SyncOwners after it.
func SetOwnerEnabled(ctx context.Context, tx DB, id int64, on bool) (changed bool, err error) {
	tag, err := tx.Exec(ctx, `UPDATE github_trusted_owner SET enabled = $2, updated_at = now() WHERE id = $1 AND enabled <> $2`, id, on)
	return tag.RowsAffected() == 1, err
}

// RepoOwner reads the owner of fetched repository row id for a quick add:
// its login, its id (0 = not known yet), its full name, and the
// allow-listed X accounts whose posts link it (a link stamped with it, or a
// root link to its current name; sorted). ErrRepoNotFound when there is no
// such fetched repository, ErrNoOwner when its owner login is unknown.
func RepoOwner(ctx context.Context, db DB, id int64) (login string, ownerID int64, fullName string, finders []string, err error) {
	var l *string
	err = db.QueryRow(ctx, `SELECT owner_login, COALESCE(owner_id, 0), COALESCE(full_name, '') FROM github_repo
        WHERE id = $1 AND github_id IS NOT NULL AND state = 'ok'`, id).Scan(&l, &ownerID, &fullName)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, "", nil, ErrRepoNotFound
	}
	if err != nil {
		return "", 0, "", nil, err
	}
	if l == nil || !ValidLogin(*l) {
		return "", 0, fullName, nil, ErrNoOwner
	}
	rows, err := db.Query(ctx, `SELECT DISTINCT xa.user_id FROM github_repo r
        JOIN x_post_link l ON l.repo_github_id = r.github_id OR (l.repo_root_key IS NOT NULL AND l.repo_root_key = lower(r.full_name))
        LEFT JOIN LATERAL (SELECT e.detail->>'author_id' AS author FROM event e
                           WHERE e.dedupe_key = l.post_id AND e.source = 'xposts' AND e.type = 'social_post' LIMIT 1) e ON true
        LEFT JOIN x_post_no_cve n ON n.post_id = l.post_id
        JOIN x_accounts xa ON xa.user_id = COALESCE(e.author, n.author_id)
        WHERE r.id = $1 ORDER BY 1`, id)
	if err != nil {
		return "", 0, "", nil, err
	}
	finders, err = pgx.CollectRows(rows, pgx.RowTo[string])
	return *l, ownerID, fullName, finders, err
}

// OwnerRef is a trusted account as /admin/x shows it next to the linked X
// account.
type OwnerRef struct {
	ID      int64
	Login   string
	Enabled bool
}

// OwnersOfX maps each of the X user ids to the trusted accounts linked to
// it (by login).
func OwnersOfX(ctx context.Context, db DB, xUserIDs []string) (map[string][]OwnerRef, error) {
	out := map[string][]OwnerRef{}
	if len(xUserIDs) == 0 {
		return out, nil
	}
	rows, err := db.Query(ctx, `SELECT x_user_id, id, login, enabled FROM github_trusted_owner
        WHERE x_user_id = ANY($1) ORDER BY x_user_id, lower(login), id`, xUserIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x string
		var o OwnerRef
		if err := rows.Scan(&x, &o.ID, &o.Login, &o.Enabled); err != nil {
			return nil, err
		}
		out[x] = append(out[x], o)
	}
	return out, rows.Err()
}

// ownerStateSQL is ReviewItem.Owner of repository r: 'on' when an enabled
// trusted account covers it, 'off' when only disabled ones do, NULL when
// none.
// For display it also counts a login match where one side has no id yet
// (a pending account, a row not refetched yet): that row is a candidate,
// not trusted.
const ownerStateSQL = `(SELECT CASE WHEN bool_or(a.enabled) THEN 'on' WHEN count(*) > 0 THEN 'off' END
    FROM github_trusted_owner a WHERE ` + ownerMatchSQL + `
       OR ((a.owner_id IS NULL OR r.owner_id IS NULL) AND lower(a.login) = lower(r.owner_login)))`
