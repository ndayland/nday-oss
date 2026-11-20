package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xprofiles"
)

// nday x-profiles [--dry-run] [--only-missing | --all]
//
// Backfill of the authors' X profiles (xprofiles.Run, docs/xposts.md
// "Author profiles and avatars"): the enabled allow-listed accounts that
// have no x_user row or one older than 30 days (--only-missing, the
// default; --all takes every enabled account), looked up on X by id (GET
// /2/users?ids=…, 100 a request, at most 10 requests, 1 s apart, 2 minutes
// in all; HTTP 429 stops the run cleanly). Names and avatar URLs are
// cleaned and validated like the collector's and written with seen_at =
// now (newest fetch wins); --dry-run writes nothing. No images are
// fetched: the next `nday site-icons` does that. The token
// (NDAY_X_BEARER_TOKEN, database settings else environment) is never
// printed. Output: the counts as JSON; one summary log line.
func runXProfiles(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{{name: "--dry-run"}, {name: "--only-missing"}, {name: "--all"}}, rest, 0)
	if err != nil {
		return err
	}
	_, all := p.flags["--all"]
	if _, om := p.flags["--only-missing"]; om && all {
		return &usageError{prog, "argument --all: not allowed with argument --only-missing"}
	}
	_, dry := p.flags["--dry-run"]
	envSnap := environSnapshot()
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	token, _ := loadSnapshot(sctx, conn).Lookup(envSnap)(xlookup.TokenEnv)
	lk, err := xlookup.New(xlookup.Options{Token: token, Transport: env.Transport})
	if err != nil {
		return err
	}
	if !lk.Configured() {
		return fmt.Errorf("x-profiles needs %s (in the database settings or the environment)", xlookup.TokenEnv)
	}
	res, err := xprofiles.Run(sctx, conn, lk, xprofiles.Options{DryRun: dry, OnlyMissing: !all, Now: env.Now})
	if err != nil && missingTable(err) {
		err = errors.New("x-profiles: migration 0038 not applied (run `nday migrate`)")
	}
	lvl := slog.LevelInfo
	if err != nil || res.RateLimited {
		lvl = slog.LevelWarn
	}
	slog.Log(context.Background(), lvl, "x profiles pass", "considered", res.Considered, "requested", res.Requested,
		"returned", res.Returned, "with_name", res.WithName, "avatar_accepted", res.AvatarAccepted,
		"avatar_rejected", res.AvatarRejected, "rejected_sample", res.RejectedSample, "not_returned", res.NotReturned,
		"written", res.Written, "requests", res.Requests, "rate_limited", res.RateLimited, "timed_out", res.TimedOut,
		"capped", res.Capped, "dry_run", res.DryRun, "err", errString(err))
	printJSON(env, res)
	return err
}
