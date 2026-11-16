package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
)

// nday tags (--all | --cve ID [ID ...] | --pending) [--dry-run] [--batch-size N]
//
// Derives CVE tags (internal/tags, docs/tags.md): --all recomputes every
// CVE (the one-time backfill after migration 0011, and after a rule version
// bump), --cve the given CVEs, --pending drains tag_queue (what the pass
// after every collector run does). Waits for a concurrent tag run.
func runTags(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{
		{name: "--all"}, {name: "--cve"}, {name: "--pending"}, {name: "--dry-run"}, {name: "--batch-size", hasValue: true},
	}, rest, 1<<20)
	if err != nil {
		return err
	}
	_, all := p.flags["--all"]
	_, byCVE := p.flags["--cve"]
	_, pending := p.flags["--pending"]
	n := 0
	for _, b := range []bool{all, byCVE, pending} {
		if b {
			n++
		}
	}
	if n != 1 {
		return &usageError{prog, "exactly one of --all, --cve ID [ID ...] or --pending is required"}
	}
	if !byCVE && len(p.pos) > 0 {
		return &usageError{prog, "unrecognized arguments: " + strings.Join(p.pos, " ")}
	}
	var ids []string
	if byCVE {
		if len(p.pos) == 0 {
			return &usageError{prog, "argument --cve: expected at least one CVE id"}
		}
		for _, a := range p.pos {
			id, ok := site.ParseCVEID(a)
			if !ok {
				return &usageError{prog, fmt.Sprintf("argument --cve: not a CVE id: '%s'", a)}
			}
			ids = append(ids, id)
		}
	}
	o := tags.Options{Wait: true, Logger: slog.Default()}
	if o.BatchSize, err = intOpt(prog, p, "--batch-size", tags.DefaultBatchSize, 1, 50000); err != nil {
		return err
	}
	_, o.DryRun = p.flags["--dry-run"]
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var st *tags.Stats
	switch {
	case all:
		st, err = tags.All(sctx, conn, o)
	case byCVE:
		st, err = tags.ByCVE(sctx, conn, ids, o)
	default:
		st, err = tags.Pending(sctx, conn, o)
	}
	if st != nil {
		printJSON(env, st)
	}
	if err == nil && o.DryRun {
		slog.Info("dry run: every batch rolled back, nothing written")
	}
	return err
}

// postRunTags is the incremental tag pass after a collector run (after the
// classification pass, whose writes it reads): drain tag_queue (bounded),
// without waiting for a concurrent tag run. Failures are logged and never
// fail the collector run (the queue keeps the work for the next pass).
func postRunTags(ctx context.Context, conn *pgx.Conn) {
	st, err := tags.Pending(ctx, conn, tags.Options{MaxQueue: 500000, Logger: slog.Default()})
	if err != nil {
		var ue interface{ SQLState() string }
		if errors.As(err, &ue) && ue.SQLState() == "42P01" {
			slog.Warn("tag pass skipped: migration 0011 not applied (run `nday migrate`)")
			return
		}
		slog.Warn("tag pass failed (run result unaffected; the queue is kept)", "err", err)
		return
	}
	if st.Deferred {
		return
	}
	if v, err := tags.RuleVersionState(ctx, conn); err == nil && v != tags.RuleVersion {
		slog.Warn("tags: rows may be stale: run `nday tags --all`", "rule_version", tags.RuleVersion, "last_all_rule_version", v)
	}
	slog.Info("tag pass", "queue_rows", st.QueueRows, "cves", st.CVEs, "changed", st.Changed,
		"inserted", st.Inserted, "deleted", st.Deleted, "sec", fmt.Sprintf("%.2f", st.ElapsedSec))
}
