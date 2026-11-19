package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup"
)

// The display name and profile description ("bio") of allowlisted X
// accounts (migration 0030, docs/xposts.md). They are stored whenever an
// account is looked up on X anyway (adding by handle, importing handle-only
// lines); accounts listed otherwise (by id, from a candidate) get them from
// the bounded refresh below, which an administrator starts on /admin/x:
//
//	POST /api/admin/x/accounts/profiles  (no body)
//
// One request looks up at most XProfileBatch due accounts (never looked
// up, or longer ago than xconfig.ProfileMaxAge; the never looked up first,
// then the oldest lookup); with none due it makes no X request and writes
// nothing by their stored handle in ONE X API
// request (GET /2/users/by, xlookup.MaxPerRequest usernames), and stores a
// profile only where X answers with the same user id (a handle can have
// changed hands). Accounts not found under their id are marked looked up
// and keep what they had. The page never calls X. Answer:
//
//	{"ok":true,"looked_up":N,"updated":N,"not_found":N,"failed":N,"missing":N}
//
// missing is how many accounts are still never looked up. One audit row
// x.account.profiles (target x_account "profiles") with the counts.

// XProfileBatch is the most accounts one refresh looks up (one request).
const XProfileBatch = xlookup.MaxPerRequest

// XProfileResult is what one refresh did.
type XProfileResult struct {
	LookedUp int `json:"looked_up"`
	Updated  int `json:"updated"`
	NotFound int `json:"not_found"`
	Failed   int `json:"failed"`
	Missing  int `json:"missing"`
}

func profileOf(r xlookup.Result) *xconfig.Profile {
	if r.Outcome != xlookup.Found {
		return nil
	}
	return &xconfig.Profile{Name: r.Name, Description: r.Description}
}

// XRefreshProfiles runs one bounded refresh (see above). The lookup is made
// outside any transaction; the writes and the audit row in one.
func (s *Service) XRefreshProfiles(ctx context.Context, actor string) (*XProfileResult, error) {
	if !s.xLookup().Configured() {
		return nil, xlookup.ErrNotConfigured
	}
	var todo []xconfig.Account
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		todo, err = xconfig.ProfileTodo(ctx, c, XProfileBatch)
		return err
	})
	if err != nil {
		return nil, err
	}
	res := &XProfileResult{}
	if len(todo) == 0 { // everything was looked up within xconfig.ProfileMaxAge: no request, nothing written
		return res, nil
	}
	found := map[string]xlookup.Result{}
	var handles []string
	for _, a := range todo {
		if xconfig.ValidHandle(a.Handle) {
			handles = append(handles, a.Handle)
		}
	}
	if len(handles) > 0 {
		if found, err = s.xLookup().Lookup(ctx, handles); err != nil {
			return nil, err
		}
	}
	// one transaction per account: an account whose profile cannot be
	// stored is marked looked up without it, counted and logged (without
	// its text), and never blocks the others
	for _, a := range todo {
		r := found[xlookup.Key(a.Handle)]
		var p *xconfig.Profile
		if r.Outcome == xlookup.Found && r.ID == a.UserID {
			p = profileOf(r)
		}
		err := s.writeTx(ctx, actor, func(tx pgx.Tx) error { return xconfig.SetProfile(ctx, tx, a.UserID, p) })
		switch {
		case err == nil && p != nil:
			res.Updated++
		case err == nil, errors.Is(err, xconfig.ErrNotFound):
			res.NotFound++
		case errors.Is(err, auth.ErrNotAdmin):
			return nil, err
		default:
			s.log.Error("admin: x profile not stored", "x_user", a.UserID, "err_type", fmt.Sprintf("%T", err))
			res.Failed++
			_ = s.writeTx(ctx, actor, func(tx pgx.Tx) error { return xconfig.SetProfile(ctx, tx, a.UserID, nil) })
		}
	}
	res.LookedUp = len(todo)
	err = s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		var err error
		if res.Missing, err = xconfig.CountProfileMissing(ctx, tx); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: audit.XAccountProfiles, TargetType: audit.TargetXAccount,
			TargetID: "profiles", Details: map[string]any{"looked_up": res.LookedUp, "updated": res.Updated, "not_found": res.NotFound,
				"failed": res.Failed}})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) xProfiles(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	if !readBody(w, r, nil) {
		return
	}
	res, err := s.XRefreshProfiles(r.Context(), u.ID)
	if err != nil {
		s.xFail(w, "x_profiles", err)
		return
	}
	s.log.Info("admin: x profiles refreshed", "actor", u.ID, "looked_up", res.LookedUp, "updated", res.Updated)
	writeOK(w, map[string]any{"ok": true, "looked_up": res.LookedUp, "updated": res.Updated, "not_found": res.NotFound, "failed": res.Failed,
		"missing": res.Missing})
}
