package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/xconfig"
)

// Allowlist candidates on /admin/x (docs/xposts.md): X users that
// allowlisted researchers quote, reply to or mention (internal/xconfig
// candidates.go). An administrator adds one to x_accounts (its stored id and
// handle; no X API request), dismisses it, or restores a dismissed one.
// Writes are writeTx transactions with their audit row, like every X action.
//
//	POST /api/admin/x/candidates/{user id}/add      (no body)
//	POST /api/admin/x/candidates/{user id}/dismiss  (no body)
//	POST /api/admin/x/candidates/{user id}/restore  (no body)
//
// An added candidate keeps its x_account_candidate row as it was: every
// list excludes ids present in x_accounts (xconfig.ListCandidates), so it
// leaves the open list at once and comes back only if the account row ever
// went away (accounts are never deleted).

// XCandidatesPage caps each candidate list on /admin/x (the first ones in
// ListCandidates' order; the page shows the total).
const XCandidatesPage = 50

// ErrCandidateNoHandle: the candidate has no valid handle, so it cannot be
// listed (x_accounts needs one).
var ErrCandidateNoHandle = errors.New("the candidate has no valid handle")

// XCandidateLists is the open and the dismissed candidates, each capped at
// XCandidatesPage, with their totals.
type XCandidateLists struct {
	Open, Dismissed   []xconfig.Candidate
	OpenN, DismissedN int
}

// XCandidates reads both lists on one ReadDB connection.
func (s *Service) XCandidates(ctx context.Context) (*XCandidateLists, error) {
	l := &XCandidateLists{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		if l.OpenN, err = xconfig.CountCandidates(ctx, c, xconfig.CandidatePending); err != nil {
			return err
		}
		if l.DismissedN, err = xconfig.CountCandidates(ctx, c, xconfig.CandidateDismissed); err != nil {
			return err
		}
		if l.Open, err = xconfig.ListCandidates(ctx, c, xconfig.CandidatePending, XCandidatesPage, 0); err != nil {
			return err
		}
		l.Dismissed, err = xconfig.ListCandidates(ctx, c, xconfig.CandidateDismissed, XCandidatesPage, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// XAddCandidate lists a candidate (enabled, empty note) under its stored id
// and handle, whatever its status, and writes x.account.add with
// "candidate": true. ErrCandidateNotFound, ErrCandidateNoHandle, or
// xconfig.ErrExists when the id is already listed (nothing changes).
func (s *Service) XAddCandidate(ctx context.Context, actor, userID string) (handle string, err error) {
	err = s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		h, _, err := xconfig.GetCandidateForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		if h == nil || !xconfig.ValidHandle(*h) {
			return ErrCandidateNoHandle
		}
		handle = *h
		if err := xconfig.InsertAccount(ctx, tx, userID, handle, ""); err != nil {
			return err
		}
		return audit.Write(ctx, tx, accountEntry(&actor, audit.XAccountAdd, xconfig.Account{UserID: userID, Handle: handle},
			map[string]any{"user_id": userID, "handle": handle, "note": "", "lookup": false, "candidate": true}))
	})
	return handle, err
}

// XSetCandidateDismissed dismisses (or restores) a candidate:
// ErrCandidateNotFound, or ErrNoXChange when it already has that status.
func (s *Service) XSetCandidateDismissed(ctx context.Context, actor, userID string, dismiss bool) error {
	return s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		h, _, err := xconfig.GetCandidateForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		set, action := xconfig.RestoreCandidate, audit.XCandidateRestore
		if dismiss {
			set, action = xconfig.DismissCandidate, audit.XCandidateDismiss
		}
		changed, err := set(ctx, tx, userID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrNoXChange
		}
		e := audit.Entry{ActorID: &actor, Action: action, TargetType: audit.TargetXAccount, TargetID: userID}
		if h != nil && xconfig.ValidHandle(*h) {
			e.TargetLabel = "@" + *h
		}
		return audit.Write(ctx, tx, e)
	})
}

func (s *Service) xCandidateAdd(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	if !readBody(w, r, nil) {
		return
	}
	handle, err := s.XAddCandidate(r.Context(), u.ID, id)
	if err != nil {
		s.xFail(w, "x_candidate_add", err)
		return
	}
	s.log.Info("admin: x account added", "actor", u.ID, "x_user", id, "handle", handle, "candidate", true)
	writeOK(w, map[string]any{"ok": true, "user_id": id, "handle": handle, "result": "added"})
}

func (s *Service) xCandidateDismiss(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.xCandidateSwitch(w, r, u, id, true)
}

func (s *Service) xCandidateRestore(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.xCandidateSwitch(w, r, u, id, false)
}

func (s *Service) xCandidateSwitch(w http.ResponseWriter, r *http.Request, u *auth.User, id string, dismiss bool) {
	if !readBody(w, r, nil) {
		return
	}
	if err := s.XSetCandidateDismissed(r.Context(), u.ID, id, dismiss); err != nil {
		s.xFail(w, "x_candidate_switch", err)
		return
	}
	status := xconfig.CandidatePending
	if dismiss {
		status = xconfig.CandidateDismissed
	}
	s.log.Info("admin: x candidate switched", "actor", u.ID, "x_user", id, "status", status)
	writeOK(w, map[string]any{"ok": true, "user_id": id, "status": status})
}
