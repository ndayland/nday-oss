package admin

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xconfig"
)

// Batch decisions of the review lists (docs/admin.md section 4.3): the
// selected rows of one page of a list, decided in one request. Same route
// checks as every /api/admin/* action (admin, POST, same origin, CSRF, rate
// limit, recent sign-in); then each item is applied in its own transaction
// exactly as its single action (same rules, same audit row with the same
// action name), and only when it is still in the state the page was
// rendered with:
//
//	POST /api/admin/x/candidates/batch  {"action":"add"|"dismiss"|"restore","items":[{"id":"<user id>","state":"pending"|"dismissed"}]}
//	POST /api/admin/github/repos/batch  {"action":"trust"|"reject"|"reset","items":[{"id":"<repo id>","state":"unverified"|"trusted"|"rejected"}]}
//	POST /api/admin/x/drafts/batch      {"action":"discard","items":[{"id":"<draft id>","version":N}]}
//
// At most BatchMax items, each id once. A refused request (400 bad_request:
// not that JSON, unknown action, no items; 400 too_many; 400 duplicate)
// applies nothing. Otherwise the answer is 200:
//
//	{"ok":true,"done":N,"changed":N,"failed":N,"results":[{"id":"…","result":"ok"|…}]}
//
// in request order, result one of: ok; stale (not in the state the page
// showed: another state or version), not_found, no_change, exists (already
// listed), wrong_status — counted as changed since the page was loaded;
// invalid (a malformed id, state or version), no_handle (a candidate
// without a valid handle), own_account (the site's own X account), error (an internal error, logged) — counted as
// failed.

// BatchMax is the most items one batch request may carry: one page.
const BatchMax = ListPage

// ErrStale: the item is no longer in the state the page was rendered with.
var ErrStale = errors.New("changed since the page was loaded")

type batchItem struct {
	ID      string `json:"id"`
	State   string `json:"state,omitempty"`
	Version int64  `json:"version,omitempty"`
}

type batchIn struct {
	Action string      `json:"action"`
	Items  []batchItem `json:"items"`
}

type batchResult struct {
	ID     string `json:"id"`
	Result string `json:"result"`
}

// readBatch decodes a batch request: actions are the allowed actions; ok
// false when the request was answered (refused).
func readBatch(w http.ResponseWriter, r *http.Request, actions ...string) (*batchIn, bool) {
	var in batchIn
	if !readBody(w, r, &in) {
		return nil, false
	}
	known := false
	for _, a := range actions {
		known = known || a == in.Action
	}
	switch {
	case !known:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "unknown action", "action")
	case len(in.Items) == 0:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "no items", "items")
	case len(in.Items) > BatchMax:
		web.WriteError(w, http.StatusBadRequest, "too_many", "at most "+strconv.Itoa(BatchMax)+" items per request", "items")
	default:
		seen := map[string]bool{}
		for _, it := range in.Items {
			if seen[it.ID] {
				web.WriteError(w, http.StatusBadRequest, "duplicate", "an id is listed twice", "items")
				return nil, false
			}
			seen[it.ID] = true
		}
		return &in, true
	}
	return nil, false
}

// runBatch applies each item with apply (its own transaction) and writes
// the answer.
func (s *Service) runBatch(w http.ResponseWriter, op, actor string, in *batchIn, valid func(batchItem) bool, apply func(batchItem) error) {
	out := struct {
		OK      bool          `json:"ok"`
		Done    int           `json:"done"`
		Changed int           `json:"changed"`
		Failed  int           `json:"failed"`
		Results []batchResult `json:"results"`
	}{OK: true, Results: []batchResult{}}
	for _, it := range in.Items {
		res := "invalid"
		if valid(it) {
			res = s.batchOutcome(op, apply(it))
		}
		switch res {
		case "ok":
			out.Done++
		case "stale", "not_found", "no_change", "exists", "wrong_status":
			out.Changed++
		default:
			out.Failed++
		}
		out.Results = append(out.Results, batchResult{ID: it.ID, Result: res})
	}
	s.log.Info("admin: batch "+op, "actor", actor, "action", in.Action, "items", len(in.Items), "done", out.Done,
		"changed", out.Changed, "failed", out.Failed)
	writeOK(w, out)
}

// batchOutcome is an item's result code for the error of its action.
func (s *Service) batchOutcome(op string, err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrStale), errors.Is(err, ErrDraftStale):
		return "stale"
	case errors.Is(err, xconfig.ErrCandidateNotFound), errors.Is(err, ghrepo.ErrRepoNotFound), errors.Is(err, ErrDraftNotFound),
		errors.Is(err, xconfig.ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrNoXChange), errors.Is(err, ErrNoRepoChange):
		return "no_change"
	case errors.Is(err, xconfig.ErrExists):
		return "exists"
	case errors.Is(err, ErrDraftState):
		return "wrong_status"
	case errors.Is(err, ErrCandidateNoHandle):
		return "no_handle"
	case errors.Is(err, xconfig.ErrOwnAccount):
		return "own_account"
	default:
		s.log.Error("admin: internal error", "op", op, "err", err)
		return "error"
	}
}

// xCandidatesBatch: add, dismiss (open list) or restore (dismissed list).
func (s *Service) xCandidatesBatch(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	in, ok := readBatch(w, r, "add", "dismiss", "restore")
	if !ok {
		return
	}
	valid := func(it batchItem) bool {
		return xconfig.ValidUserID(it.ID) && it.Version == 0 &&
			(it.State == xconfig.CandidatePending || it.State == xconfig.CandidateDismissed)
	}
	s.runBatch(w, "x_candidates", u.ID, in, valid, func(it batchItem) error {
		switch in.Action {
		case "add":
			_, err := s.xAddCandidate(r.Context(), u.ID, it.ID, it.State)
			return err
		case "dismiss":
			return s.xSetCandidateDismissed(r.Context(), u.ID, it.ID, true, it.State)
		default:
			return s.xSetCandidateDismissed(r.Context(), u.ID, it.ID, false, it.State)
		}
	})
}

var batchRepoStatus = map[string]string{"trust": ghrepo.StatusTrusted, "reject": ghrepo.StatusRejected, "reset": ghrepo.StatusUnverified}

// githubBatch: trust, reject or reset repositories.
func (s *Service) githubBatch(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	in, ok := readBatch(w, r, "trust", "reject", "reset")
	if !ok {
		return
	}
	valid := func(it batchItem) bool {
		return ValidRepoID(it.ID) && it.Version == 0 &&
			(it.State == ghrepo.StatusUnverified || it.State == ghrepo.StatusTrusted || it.State == ghrepo.StatusRejected)
	}
	s.runBatch(w, "github_repo_status", u.ID, in, valid, func(it batchItem) error {
		id, _ := strconv.ParseInt(it.ID, 10, 64)
		return s.gitHubSetStatus(r.Context(), u.ID, id, batchRepoStatus[in.Action], it.State)
	})
}

// xDraftsBatch: discard pending drafts (marking posted needs a URL per
// draft, so it has no batch).
func (s *Service) xDraftsBatch(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	in, ok := readBatch(w, r, "discard")
	if !ok {
		return
	}
	valid := func(it batchItem) bool {
		return ValidDraftID(it.ID) && it.State == "" && it.Version >= 1 && it.Version <= math.MaxInt32
	}
	s.runBatch(w, "x_draft_discard", u.ID, in, valid, func(it batchItem) error {
		_, err := s.XDraftDiscard(r.Context(), u.ID, draftID(it.ID), int(it.Version))
		return err
	})
}
