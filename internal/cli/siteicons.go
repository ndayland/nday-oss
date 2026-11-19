package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/siteicon"
)

// nday site-icons [--limit N]
//
// One run of the site icon job (siteicon.Run, docs/siteicons.md): at most
// N due hosts (default siteicon.DefaultLimit, at most siteicon.MaxLimit)
// of the links the vulnerability page shows, one at a time, a second
// apart, each through the SSRF-guarded https-only fetcher (favicon.ico,
// else the home page's <link rel=icon>), at most 15 minutes in all. Run by
// deploy/systemd/nday-site-icons.timer. Output: the counts as JSON; one
// summary log line.
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
	res, err := siteicon.Run(sctx, conn, siteicon.Options{Limit: limit, Now: env.Now})
	if err != nil && missingTable(err) {
		err = errors.New("site icons: migration 0028 not applied (run `nday migrate`)")
	}
	run.Finish(ctx, err, res)
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	slog.Log(context.Background(), lvl, "site icons pass", "candidates", res.Candidates, "ok", res.OK, "none", res.None,
		"error", res.Error, "kept", res.Kept, "requests", res.Requests, "refused", res.Refused, "timed_out", res.TimedOut,
		"err", errString(err))
	printJSON(env, res)
	return err
}
