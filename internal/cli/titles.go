package cli

import (
	"context"
	"log/slog"
	"strings"

	"nday.land/nday/internal/tags"
)

// nday titles [--all] [--limit N] [--batch-size N]
//
// Composes the titles of vulnerabilities whose record has none
// (internal/titles, docs/titles.md): every vulnerability without a
// vuln_title row of the current rule version (the one-time backfill after
// migration 0031, and after a rule version bump), or with --all every
// vulnerability. Short transactions in cve_id order, resumable and
// idempotent; prints a JSON summary. Waits for a concurrent tag run.
func runTitles(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{
		{name: "--all"}, {name: "--limit", hasValue: true}, {name: "--batch-size", hasValue: true},
	}, rest, 0)
	if err != nil {
		return err
	}
	if len(p.pos) > 0 {
		return &usageError{prog, "unrecognized arguments: " + strings.Join(p.pos, " ")}
	}
	o := tags.TitlesOptions{Logger: slog.Default()}
	_, o.All = p.flags["--all"]
	if o.Limit, err = intOpt(prog, p, "--limit", 0, 0, 1<<30); err != nil {
		return err
	}
	if o.BatchSize, err = intOpt(prog, p, "--batch-size", tags.DefaultTitleBatch, 1, 20000); err != nil {
		return err
	}
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	st, err := tags.Titles(sctx, conn, o)
	if st != nil {
		printJSON(env, st)
	}
	return err
}
