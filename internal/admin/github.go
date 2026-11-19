package admin

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/web"
)

// Review of GitHub PoC repositories on /admin/github (docs/github.md): the
// unverified, trusted and rejected repositories (ghrepo.ListReview), and an
// administrator's decision (ghrepo.SetStatus: status_by 'admin', which no
// rule, sweep or fetch overwrites). Writes are writeTx transactions with
// their audit row, like the X candidate actions.
//
//	POST /api/admin/github/repos/{id}/trust   (no body)
//	POST /api/admin/github/repos/{id}/reject  (no body)
//	POST /api/admin/github/repos/{id}/reset   (no body; back to unverified)
//
// {id} is github_repo.id. The row is locked with ghrepo.GetForUpdate (FOR
// NO KEY UPDATE) for the rest of the transaction.

// GitHubReviewPage is the page size of each list on /admin/github
// (numbered, in ListReviewSorted's order).
const GitHubReviewPage = ListPage

var repoIDRe = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)

// ValidRepoID reports whether s is a github_repo id in text form: a
// positive decimal integer without leading zeros, at most 18 digits (always
// within int64).
func ValidRepoID(s string) bool { return repoIDRe.MatchString(s) }

// ErrNoRepoChange: the repository already has that status by an admin.
var ErrNoRepoChange = errors.New("the repository already has that status")

// GitHubReviewLists is one page of the unverified, trusted and rejected
// repositories, with their windows (totals).
type GitHubReviewLists struct {
	Unverified, Trusted, Rejected    []ghrepo.ReviewItem
	UnverifiedN, TrustedN, RejectedN int
	UnverifiedW, TrustedW, RejectedW Window
}

// GitHubPages are the requested pages of the three lists (1-based, clamped)
// and their orders (ghrepo.ReviewSort, each list its own; the zero value is
// the default order), with the words the text orders sort by.
type GitHubPages struct {
	Unverified, Trusted, Rejected             int
	UnverifiedSort, TrustedSort, RejectedSort ghrepo.ReviewSort
	Labels                                    ghrepo.ReviewLabels
}

// GitHubReview reads one page of each list on one ReadDB connection.
func (s *Service) GitHubReview(ctx context.Context, pg GitHubPages) (*GitHubReviewLists, error) {
	l := &GitHubReviewLists{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		for _, x := range []struct {
			status string
			items  *[]ghrepo.ReviewItem
			n      *int
			w      *Window
			page   int
			sort   ghrepo.ReviewSort
		}{{ghrepo.StatusUnverified, &l.Unverified, &l.UnverifiedN, &l.UnverifiedW, pg.Unverified, pg.UnverifiedSort},
			{ghrepo.StatusTrusted, &l.Trusted, &l.TrustedN, &l.TrustedW, pg.Trusted, pg.TrustedSort},
			{ghrepo.StatusRejected, &l.Rejected, &l.RejectedN, &l.RejectedW, pg.Rejected, pg.RejectedSort}} {
			var err error
			if *x.n, err = ghrepo.CountReview(ctx, c, x.status); err != nil {
				return err
			}
			*x.w = window(*x.n, x.page)
			if *x.items, err = ghrepo.ListReviewSorted(ctx, c, x.status, x.sort, pg.Labels, GitHubReviewPage, x.w.Offset()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// githubActions maps a status to its audit action.
var githubActions = map[string]string{ghrepo.StatusTrusted: audit.GitHubRepoTrust, ghrepo.StatusRejected: audit.GitHubRepoReject,
	ghrepo.StatusUnverified: audit.GitHubRepoReset}

// GitHubSetStatus records an administrator's decision about repository id
// (ghrepo.StatusTrusted, StatusRejected or StatusUnverified) with its audit
// row: ghrepo.ErrRepoNotFound, or ErrNoRepoChange when an admin already
// gave it that status (nothing is written).
func (s *Service) GitHubSetStatus(ctx context.Context, actor string, id int64, status string) error {
	return s.gitHubSetStatus(ctx, actor, id, status, "")
}

// gitHubSetStatus is GitHubSetStatus; with expect set, a repository whose
// status is another one is ErrStale (nothing is written).
func (s *Service) gitHubSetStatus(ctx context.Context, actor string, id int64, status, expect string) error {
	action, ok := githubActions[status]
	if !ok {
		return errors.New("admin: unknown repository status " + strconv.Quote(status))
	}
	pocChanged := false
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		full, from, fromBy, err := ghrepo.GetForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if expect != "" && from != expect {
			return ErrStale
		}
		before, err := ghrepo.PoCFingerprint(ctx, tx)
		if err != nil {
			return err
		}
		changed, err := ghrepo.SetStatus(ctx, tx, id, status)
		if err != nil {
			return err
		}
		if !changed {
			return ErrNoRepoChange
		}
		// run the deferred PoC triggers (migration 0032) now, to see
		// whether this decision changed a github event
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			return err
		}
		after, err := ghrepo.PoCFingerprint(ctx, tx)
		if err != nil {
			return err
		}
		pocChanged = after != before
		d := map[string]any{"repo_id": id, "from": from, "to": status}
		if fromBy != "" {
			d["from_by"] = fromBy
		}
		e := audit.Entry{ActorID: &actor, Action: action, TargetType: audit.TargetXAccount,
			TargetID: audit.GitHubRepoTarget + strconv.FormatInt(id, 10), Details: d}
		if full != "" {
			d["full_name"] = full
			e.TargetLabel = full
		}
		return audit.Write(ctx, tx, e)
	})
	if err == nil && pocChanged {
		s.refreshStateSoon()
	}
	return err
}

func (s *Service) githubTrust(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.githubSwitch(w, r, u, id, ghrepo.StatusTrusted)
}

func (s *Service) githubReject(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.githubSwitch(w, r, u, id, ghrepo.StatusRejected)
}

func (s *Service) githubReset(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.githubSwitch(w, r, u, id, ghrepo.StatusUnverified)
}

func (s *Service) githubSwitch(w http.ResponseWriter, r *http.Request, u *auth.User, id, status string) {
	if !readBody(w, r, nil) {
		return
	}
	n, err := strconv.ParseInt(id, 10, 64) // ValidRepoID passed: never fails
	if err != nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such repository", "")
		return
	}
	if err := s.GitHubSetStatus(r.Context(), u.ID, n, status); err != nil {
		s.githubFail(w, err)
		return
	}
	s.log.Info("admin: github repository status set", "actor", u.ID, "repo_id", n, "status", status)
	writeOK(w, map[string]any{"ok": true, "id": n, "status": status})
}

func (s *Service) githubFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ghrepo.ErrRepoNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such repository", "")
	case errors.Is(err, ErrNoRepoChange):
		web.WriteError(w, http.StatusConflict, "no_change", "nothing to change", "")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	default:
		s.log.Error("admin: internal error", "op", "github_repo_status", "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}
