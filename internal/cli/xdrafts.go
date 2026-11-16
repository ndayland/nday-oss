package cli

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/xdraft"
)

// nday x-drafts [--dry-run]
//
// Writes draft posts for the brand X account (internal/xdraft,
// docs/xposts.md): one per (CVE, stage) when a vulnerability newly reaches
// POC, ITW or KEV. The same pass runs after every collector run; this
// command is the manual run. It waits up to xdraft.WaitLock (a few seconds)
// for collectors that are writing events, then gives up ("deferred"; exit 0,
// try again); --dry-run never waits, prints what it would create and writes
// nothing (not even the watermark). Output: the run's result as JSON.
func runXDrafts(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{{name: "--dry-run"}}, rest, 0)
	if err != nil {
		return err
	}
	_, dry := p.flags["--dry-run"]
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := xdraft.Generate(sctx, conn, xdraft.Options{DryRun: dry, Now: env.Now})
	if err != nil {
		return err
	}
	printJSON(env, res)
	if res.Deferred != "" {
		slog.Warn("busy, nothing done: try again in a moment", "why", res.Deferred)
	}
	if dry {
		slog.Info("dry run: rolled back, nothing written")
	}
	return nil
}

// postRunXDrafts is the draft pass after a collector run (after the tag
// pass). It never waits for a lock (a busy lock defers to the writer's own
// pass or the next run) and never fails the collector run: errors are
// logged.
func postRunXDrafts(ctx context.Context, conn *pgx.Conn, env Env) {
	res, err := xdraft.Generate(ctx, conn, xdraft.Options{NoWait: true, Now: env.Now})
	if err != nil {
		var ue interface{ SQLState() string }
		if errors.As(err, &ue) && ue.SQLState() == "42P01" {
			slog.Warn("x draft pass skipped: migration 0012 not applied (run `nday migrate`)")
			return
		}
		slog.Warn("x draft pass failed (run result unaffected)", "err", err)
		return
	}
	if res.Deferred != "" {
		slog.Info("x draft pass deferred", "why", res.Deferred)
		return
	}
	slog.Info("x draft pass", "baseline", res.Baseline, "from", res.From, "to", res.To, "candidates", res.Candidates,
		"created", res.Created, "skipped_cap", res.SkippedCap, "skipped_old", res.SkippedOld, "existing", res.Existing)
}
