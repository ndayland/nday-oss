package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xconfig"
)

// Trusted GitHub accounts on /admin/github (docs/github.md "Trusted
// accounts", ghrepo owner.go): repositories of a listed owner that nobody
// decided about are trusted by 'owner' without review. Admin only, behind
// the same route checks as every action (admin, POST, same origin, CSRF,
// rate limit, recent sign-in):
//
//	POST /api/admin/github/owners                {"login":"…","note":"…","x_handle":"…"}  add (x_handle optional)
//	POST /api/admin/github/owners/{id}/update    {"note":"…","x_handle":"…"}  ("" clears the link)
//	POST /api/admin/github/owners/{id}/enable | /disable
//	POST /api/admin/github/repos/{id}/owner      (no body) add that repository's owner
//
// Accounts are never deleted (disable instead), like the X allowlist. The
// X link is descriptive: it changes no trust, and only admin pages read it.
// Every change writes its audit row; one that changed a github PoC event
// asks for the state refresh, like a repository decision.

// GitHubOwnersPage is the list's page size.
const GitHubOwnersPage = ListPage

// Refusals of the account actions.
var (
	ErrXNotListed     = errors.New("no allow-listed X account has this handle")
	ErrNoGitHubChange = errors.New("nothing to change")
)

// GitHubOwnerList is one page of the trusted accounts.
type GitHubOwnerList struct {
	Owners []ghrepo.Owner
	Total  int
	W      Window
}

// GitHubOwners reads page page (1-based, clamped) of the list.
func (s *Service) GitHubOwners(ctx context.Context, page int) (*GitHubOwnerList, error) {
	l := &GitHubOwnerList{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		if l.Total, err = ghrepo.CountOwners(ctx, c); err != nil {
			return err
		}
		l.W = window(l.Total, page)
		l.Owners, err = ghrepo.ListOwners(ctx, c, GitHubOwnersPage, l.W.Offset())
		return err
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// GitHubOwnersOfX maps X user ids to the trusted accounts linked to them
// (/admin/x).
func (s *Service) GitHubOwnersOfX(ctx context.Context, ids []string) (map[string][]ghrepo.OwnerRef, error) {
	var m map[string][]ghrepo.OwnerRef
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		m, err = ghrepo.OwnersOfX(ctx, c, ids)
		return err
	})
	return m, err
}

// xByHandle finds the allow-listed X account with that handle
// (case-insensitively; an enabled one, then the most recently changed, if
// renames left two): ErrXNotListed when none.
func xByHandle(ctx context.Context, tx pgx.Tx, handle string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT user_id FROM x_accounts WHERE lower(handle) = lower($1)
        ORDER BY enabled DESC, updated_at DESC, user_id LIMIT 1`, handle).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrXNotListed
	}
	return id, err
}

// xHandleOf is the stored handle of X account id ("" when none).
func xHandleOf(ctx context.Context, tx pgx.Tx, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	var h string
	err := tx.QueryRow(ctx, `SELECT handle FROM x_accounts WHERE user_id = $1`, id).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return h, err
}

func ownerEntry(actor *string, action string, id int64, login string, d map[string]any) audit.Entry {
	d["owner"] = id
	d["login"] = login
	return audit.Entry{ActorID: actor, Action: action, TargetType: audit.TargetXAccount,
		TargetID: audit.GitHubOwnerTarget + strconv.FormatInt(id, 10), TargetLabel: login, Details: d}
}

// ownerTx runs fn under the store lock, then brings owner trust in line
// with the list and asks for a state refresh when a github event changed.
// fn's audit entries are written after the sync, with its counts.
func (s *Service) ownerTx(ctx context.Context, actor string, fn func(tx pgx.Tx) ([]audit.Entry, error)) error {
	pocChanged := false
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		// the auth pool's 5 s statement_timeout would cut the sync and the
		// deferred PoC triggers of an account with hundreds of repositories
		// (SET CONSTRAINTS runs them all as one statement); this
		// transaction gets its own bound
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '`+ownerTxTimeout+`'`); err != nil {
			return err
		}
		if err := ghrepo.LockOwners(ctx, tx); err != nil {
			return err
		}
		before, err := ghrepo.PoCFingerprint(ctx, tx)
		if err != nil {
			return err
		}
		entries, err := fn(tx)
		if err != nil {
			return err
		}
		granted, reverted, err := ghrepo.SyncOwners(ctx, tx)
		if err != nil {
			return err
		}
		// run the deferred PoC triggers now to see what changed
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			return err
		}
		after, err := ghrepo.PoCFingerprint(ctx, tx)
		if err != nil {
			return err
		}
		pocChanged = after != before
		for _, e := range entries {
			if granted > 0 {
				e.Details["trusted"] = granted
			}
			if reverted > 0 {
				e.Details["untrusted"] = reverted
			}
			if err := audit.Write(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && pocChanged {
		s.refreshStateSoon()
	}
	return err
}

// ownerTxTimeout bounds one change of the list (ownerTx).
const ownerTxTimeout = "120s"

// lookupOwner resolves login through Options.GitHubLookup (one request to
// api.github.com, outside any transaction): the owner id and GitHub's
// spelling of the login, or 0 when it cannot be told now (no lookup
// configured, network, rate limit: the account is saved "id pending" and
// the fetch pass retries). ghrepo.ErrLoginNotFound when GitHub says the
// login does not exist.
func (s *Service) lookupOwner(ctx context.Context, login string) (int64, string, error) {
	if s.o.GitHubLookup == nil {
		return 0, "", nil
	}
	id, canon, err := s.o.GitHubLookup(ctx, login)
	switch {
	case errors.Is(err, ghrepo.ErrLoginNotFound):
		return 0, "", err
	case err != nil:
		s.log.Warn("admin: github account lookup failed; saved as pending", "err", err)
		return 0, "", nil
	}
	return id, canon, nil
}

// GitHubAddOwner lists account login (ghrepo.ValidLogin) with a note and
// an optional link to the allow-listed X account xHandle ("" = none). The
// owner id is looked up on GitHub first (lookupOwner); without it the
// account is pending and trusts nothing yet. ghrepo.ErrOwnerExists (and
// the listed id) when it is listed already, ghrepo.ErrLoginNotFound.
func (s *Service) GitHubAddOwner(ctx context.Context, actor, login, note, xHandle string) (id int64, pending bool, err error) {
	ownerID, canon, err := s.lookupOwner(ctx, login)
	if err != nil {
		return 0, false, err
	}
	if canon != "" {
		login = canon
	}
	err = s.ownerTx(ctx, actor, func(tx pgx.Tx) ([]audit.Entry, error) {
		xid := ""
		if xHandle != "" {
			var err error
			if xid, err = xByHandle(ctx, tx, xHandle); err != nil {
				return nil, err
			}
		}
		var err error
		if id, err = ghrepo.AddOwner(ctx, tx, login, ownerID, note, xid); err != nil {
			return nil, err
		}
		o, err := ghrepo.GetOwner(ctx, tx, id, false)
		if err != nil {
			return nil, err
		}
		d := map[string]any{"note": note}
		if o.OwnerID != 0 {
			d["owner_id"] = o.OwnerID
		} else {
			d["pending"] = true
		}
		if xid != "" {
			d["x_user_id"], d["x_handle"] = xid, o.XHandle
		}
		return []audit.Entry{ownerEntry(&actor, audit.GitHubOwnerAdd, id, login, d)}, nil
	})
	return id, ownerID == 0, err
}

// GitHubOwnerAdded is what GitHubAddRepoOwner listed.
type GitHubOwnerAdded struct {
	ID      int64
	Login   string
	XHandle string // the X account it was linked to ("" = none)
	Pending bool   // the owner id is not known yet (trusts nothing yet)
}

// GitHubAddRepoOwner lists the owner of fetched repository repoID: its
// owner id from that row when the row has one, else looked up on GitHub
// by the row's login (lookupOwner; pending when that fails). When exactly
// one allow-listed X account posted a link to the repository, the account
// is linked to it; with several, nothing is linked (staff can set it).
// ErrRepoNotFound, ghrepo.ErrNoOwner, ghrepo.ErrLoginNotFound,
// ghrepo.ErrOwnerExists (the result then names the listed account).
func (s *Service) GitHubAddRepoOwner(ctx context.Context, actor string, repoID int64) (*GitHubOwnerAdded, error) {
	var login string
	var ownerID int64
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		login, ownerID, _, _, err = ghrepo.RepoOwner(ctx, c, repoID)
		return err
	})
	if err != nil {
		return nil, err
	}
	looked, canon := int64(0), ""
	if ownerID == 0 {
		if looked, canon, err = s.lookupOwner(ctx, login); err != nil {
			return nil, err
		}
	}
	res := &GitHubOwnerAdded{}
	err = s.ownerTx(ctx, actor, func(tx pgx.Tx) ([]audit.Entry, error) {
		login, ownerID, full, finders, err := ghrepo.RepoOwner(ctx, tx, repoID)
		if err != nil {
			return nil, err
		}
		if ownerID == 0 && strings.EqualFold(canon, login) {
			ownerID, login = looked, canon
		}
		xid := ""
		if len(finders) == 1 {
			xid = finders[0]
		}
		if res.ID, err = ghrepo.AddOwner(ctx, tx, login, ownerID, "", xid); err != nil {
			return nil, err
		}
		res.Pending = ownerID == 0
		res.Login = login
		if res.XHandle, err = xHandleOf(ctx, tx, xid); err != nil {
			return nil, err
		}
		d := map[string]any{"repo_id": repoID, "full_name": full, "note": ""}
		if ownerID != 0 {
			d["owner_id"] = ownerID
		} else {
			d["pending"] = true
		}
		if xid != "" {
			d["x_user_id"], d["x_handle"] = xid, res.XHandle
		}
		if len(finders) > 1 {
			d["x_finders"] = len(finders)
		}
		return []audit.Entry{ownerEntry(&actor, audit.GitHubOwnerAdd, res.ID, login, d)}, nil
	})
	if errors.Is(err, ghrepo.ErrOwnerExists) {
		return res, err // res.ID names the listed account
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GitHubUpdateOwner sets the note and the X link (xHandle "" = none) of
// account id: one audit row for the note (github.owner.update) and one for
// the link (github.owner.link or .unlink). ErrNoGitHubChange when both are
// as they were.
func (s *Service) GitHubUpdateOwner(ctx context.Context, actor string, id int64, note, xHandle string) error {
	return s.ownerTx(ctx, actor, func(tx pgx.Tx) ([]audit.Entry, error) {
		old, err := ghrepo.GetOwner(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		xid := ""
		if xHandle != "" {
			if xid, err = xByHandle(ctx, tx, xHandle); err != nil {
				return nil, err
			}
		}
		changed, err := ghrepo.UpdateOwner(ctx, tx, id, note, xid)
		if err != nil {
			return nil, err
		}
		if !changed {
			return nil, ErrNoGitHubChange
		}
		var out []audit.Entry
		if old.Note != note {
			out = append(out, ownerEntry(&actor, audit.GitHubOwnerUpdate, id, old.Login,
				map[string]any{"note": map[string]any{"from": old.Note, "to": note}}))
		}
		if old.XUserID != xid {
			d := map[string]any{}
			if old.XUserID != "" {
				d["from"] = map[string]any{"x_user_id": old.XUserID, "x_handle": old.XHandle}
			}
			action := audit.GitHubOwnerUnlink
			if xid != "" {
				h, err := xHandleOf(ctx, tx, xid)
				if err != nil {
					return nil, err
				}
				d["to"] = map[string]any{"x_user_id": xid, "x_handle": h}
				action = audit.GitHubOwnerLink
			}
			out = append(out, ownerEntry(&actor, action, id, old.Login, d))
		}
		return out, nil
	})
}

// GitHubSetOwnerEnabled enables or disables account id; disabling takes
// owner trust back from its repositories (an admin's decision stays).
func (s *Service) GitHubSetOwnerEnabled(ctx context.Context, actor string, id int64, on bool) error {
	return s.ownerTx(ctx, actor, func(tx pgx.Tx) ([]audit.Entry, error) {
		o, err := ghrepo.GetOwner(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		changed, err := ghrepo.SetOwnerEnabled(ctx, tx, id, on)
		if err != nil {
			return nil, err
		}
		if !changed {
			return nil, ErrNoGitHubChange
		}
		action := audit.GitHubOwnerDisable
		if on {
			action = audit.GitHubOwnerEnable
		}
		return []audit.Entry{ownerEntry(&actor, action, id, o.Login, map[string]any{})}, nil
	})
}

// ---- endpoints

// ownerFields checks note and X handle of a request ("" = valid).
func ownerFields(note, xHandle string) (code, param string) {
	switch {
	case !utf8.ValidString(note) || utf8.RuneCountInString(note) > ghrepo.MaxOwnerNote || strings.ContainsAny(note, "\x00\r\n"):
		return "bad_note", "note"
	case xHandle != "" && !xconfig.ValidHandle(xHandle):
		return "bad_handle", "x_handle"
	}
	return "", ""
}

func (s *Service) githubOwnerAdd(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		Login   string `json:"login"`
		Note    string `json:"note"`
		XHandle string `json:"x_handle"`
	}
	if !readBody(w, r, &in) {
		return
	}
	in.Login, in.Note = strings.TrimPrefix(strings.TrimSpace(in.Login), "@"), strings.TrimSpace(in.Note)
	in.XHandle = strings.TrimPrefix(strings.TrimSpace(in.XHandle), "@")
	if !ghrepo.ValidLogin(in.Login) {
		web.WriteError(w, http.StatusBadRequest, "bad_login", "invalid login", "login")
		return
	}
	if code, param := ownerFields(in.Note, in.XHandle); code != "" {
		web.WriteError(w, http.StatusBadRequest, code, "invalid "+param, param)
		return
	}
	id, pending, err := s.GitHubAddOwner(r.Context(), u.ID, in.Login, in.Note, in.XHandle)
	if err != nil {
		s.ownerFail(w, "github_owner_add", id, err)
		return
	}
	s.log.Info("admin: github owner added", "actor", u.ID, "owner", id, "pending", pending)
	writeOK(w, map[string]any{"ok": true, "id": id, "pending": pending})
}

func (s *Service) githubRepoOwner(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	if !readBody(w, r, nil) {
		return
	}
	n, err := strconv.ParseInt(id, 10, 64) // ValidRepoID passed: never fails
	if err != nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such repository", "")
		return
	}
	res, err := s.GitHubAddRepoOwner(r.Context(), u.ID, n)
	if err != nil {
		var id int64
		if res != nil {
			id = res.ID
		}
		s.ownerFail(w, "github_repo_owner", id, err)
		return
	}
	s.log.Info("admin: github owner added from a repository", "actor", u.ID, "owner", res.ID, "repo_id", n)
	writeOK(w, map[string]any{"ok": true, "id": res.ID, "login": res.Login, "x_handle": res.XHandle, "pending": res.Pending})
}

func (s *Service) githubOwnerUpdate(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	var in struct {
		Note    string `json:"note"`
		XHandle string `json:"x_handle"`
	}
	if !readBody(w, r, &in) {
		return
	}
	in.Note, in.XHandle = strings.TrimSpace(in.Note), strings.TrimPrefix(strings.TrimSpace(in.XHandle), "@")
	if code, param := ownerFields(in.Note, in.XHandle); code != "" {
		web.WriteError(w, http.StatusBadRequest, code, "invalid "+param, param)
		return
	}
	n, _ := strconv.ParseInt(id, 10, 64)
	if err := s.GitHubUpdateOwner(r.Context(), u.ID, n, in.Note, in.XHandle); err != nil {
		s.ownerFail(w, "github_owner_update", 0, err)
		return
	}
	s.log.Info("admin: github owner updated", "actor", u.ID, "owner", n)
	writeOK(w, map[string]any{"ok": true, "id": n})
}

func (s *Service) githubOwnerEnable(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.githubOwnerSwitch(w, r, u, id, true)
}

func (s *Service) githubOwnerDisable(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.githubOwnerSwitch(w, r, u, id, false)
}

func (s *Service) githubOwnerSwitch(w http.ResponseWriter, r *http.Request, u *auth.User, id string, on bool) {
	if !readBody(w, r, nil) {
		return
	}
	n, _ := strconv.ParseInt(id, 10, 64)
	if err := s.GitHubSetOwnerEnabled(r.Context(), u.ID, n, on); err != nil {
		s.ownerFail(w, "github_owner_switch", 0, err)
		return
	}
	s.log.Info("admin: github owner switched", "actor", u.ID, "owner", n, "enabled", on)
	writeOK(w, map[string]any{"ok": true, "id": n, "enabled": on})
}

func (s *Service) ownerFail(w http.ResponseWriter, op string, id int64, err error) {
	switch {
	case errors.Is(err, ghrepo.ErrOwnerExists):
		writeErrorWith(w, http.StatusConflict, "owner_exists", "this account is already listed", "login", map[string]any{"id": id})
	case errors.Is(err, ghrepo.ErrOwnerNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such account", "")
	case errors.Is(err, ghrepo.ErrRepoNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such repository", "")
	case errors.Is(err, ghrepo.ErrLoginNotFound):
		web.WriteError(w, http.StatusUnprocessableEntity, "github_not_found", "no GitHub account has this login", "login")
	case errors.Is(err, ghrepo.ErrNoOwner):
		web.WriteError(w, http.StatusUnprocessableEntity, "no_owner", "the repository's owner is not known", "")
	case errors.Is(err, ErrXNotListed):
		web.WriteError(w, http.StatusUnprocessableEntity, "x_not_listed", "no allow-listed X account has this handle", "x_handle")
	case errors.Is(err, ErrNoGitHubChange):
		web.WriteError(w, http.StatusConflict, "no_change", "nothing to change", "")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	default:
		s.log.Error("admin: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}
