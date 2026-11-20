package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/siteicon"
	"nday.land/nday/internal/xavatar"
)

// nday site-icons [--limit N]
//
// One run of the site icon job (siteicon.Run, docs/siteicons.md): at most
// N due hosts (default siteicon.DefaultLimit, at most siteicon.MaxLimit)
// of the links the vulnerability page shows, one at a time, a second
// apart, each through the SSRF-guarded https-only fetcher (favicon.ico,
// else the home page's <link rel=icon>), at most 15 minutes in all; then
// the X avatar pass (xavatar.Run, docs/xposts.md "Author profiles and
// avatars"): at most xavatar.DefaultLimit due avatars of allow-listed
// authors, through the same kind of guarded client pinned to
// pbs.twimg.com, at most 3 minutes. Run by
// deploy/systemd/nday-site-icons.timer (its sandbox covers both passes).
// Output: the counts as JSON (the avatar pass under "avatars"); one
// summary log line per pass.
func runSiteIcons(ctx context.Context, env Env, prog string, rest []string) error {
	limit, err := limitArg(prog, rest, siteicon.DefaultLimit)
	if err != nil {
		return err
	}
	if limit > siteicon.MaxLimit {
		return &usageError{prog, fmt.Sprintf("argument --limit: invalid value: '%d' (1..%d)", limit, siteicon.MaxLimit)}
	}
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	run := jobrun.Start(ctx, conn, jobrun.SiteIcons, env.Now)
	var out siteIconsResult
	out.Result, err = siteicon.Run(sctx, conn, siteicon.Options{Limit: limit, Now: env.Now})
	if err != nil && missingTable(err) {
		err = errors.New("site icons: migration 0028 not applied (run `nday migrate`)")
	}
	res := out.Result
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	slog.Log(context.Background(), lvl, "site icons pass", "candidates", res.Candidates, "ok", res.OK, "none", res.None,
		"error", res.Error, "kept", res.Kept, "requests", res.Requests, "refused", res.Refused, "timed_out", res.TimedOut,
		"err", errString(err))
	// the avatar pass runs even after a failed icon pass (they share
	// nothing but the connection), unless the caller cancelled
	if sctx.Err() == nil {
		av, aerr := xavatar.Run(sctx, conn, xavatar.Options{Now: env.Now})
		if aerr != nil && missingTable(aerr) {
			aerr = errors.New("x avatars: migration 0038 not applied (run `nday migrate`)")
		}
		out.Avatars = &av
		lvl = slog.LevelInfo
		if aerr != nil {
			lvl = slog.LevelWarn
		}
		slog.Log(context.Background(), lvl, "x avatars pass", "candidates", av.Candidates, "ok", av.OK, "none", av.None,
			"error", av.Error, "refused", av.Refused, "timed_out", av.TimedOut, "err", errString(aerr))
		err = errors.Join(err, aerr)
	}
	run.Finish(ctx, err, out)
	printJSON(env, out)
	return err
}

// siteIconsResult is the output of `nday site-icons`: the icon counts as
// before (flat), the avatar pass under "avatars" (absent when it did not
// run).
type siteIconsResult struct {
	siteicon.Result
	Avatars *xavatar.Result `json:"avatars,omitempty"`
}
