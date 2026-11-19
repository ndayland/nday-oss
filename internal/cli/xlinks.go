package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/webpages"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlinks"
)

// nday x-links-resolve [--limit N]
//
// Expands pending t.co links of stored X posts (x_post_link, internal/xlinks,
// docs/xposts.md): one request per link to https://t.co only, redirects not
// followed, the Location header stored. The same pass runs after every
// successful `nday collect xposts`. Output: the pass's counts as JSON.
func runXLinksResolve(ctx context.Context, env Env, prog string, rest []string) error {
	limit, err := limitArg(prog, rest, xlinks.DefaultLimit)
	if err != nil {
		return err
	}
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := xlinks.Resolve(sctx, conn, xlinks.Options{Limit: limit, Transport: env.Transport, Now: env.Now})
	printJSON(env, res)
	return err
}

// postRunXLinks is the link pass after a successful `nday collect xposts`
// (after the draft pass): the t.co resolve pass, then the hand-off of the
// links to the web page queue (xlinks.EnqueuePages), then one web page
// fetch pass (webpages.FetchPending). It never fails the collector run:
// errors are logged. The fetch pass requests arbitrary third-party hosts,
// so it runs only with the built-in guarded client: with an injected
// Env.Transport (tests, tools/replay) it is skipped. Enqueue and fetch
// share their own deadline (postRunPagesTimeout) and fetch at most
// postRunPagesLimit pages, so they never hold the collector run for long;
// `nday pages-fetch` has neither bound.
func postRunXLinks(ctx context.Context, conn *pgx.Conn, env Env) {
	res, err := xlinks.Resolve(ctx, conn, xlinks.Options{Transport: env.Transport, Now: env.Now})
	if err != nil {
		if missingTable(err) {
			slog.Warn("x link pass skipped: migration 0019 not applied (run `nday migrate`)")
			return
		}
		slog.Warn("x link pass failed (run result unaffected)", "err", err, "resolved", res.Resolved)
		return
	}
	slog.Info("x link pass", "candidates", res.Candidates, "resolved", res.Resolved, "retry", res.Retry,
		"failed", res.Failed, "refused", res.Refused, "requests", res.Requests)
	pctx, cancel := context.WithTimeout(ctx, postRunPagesTimeout)
	defer cancel()
	run := jobrun.Start(ctx, conn, jobrun.PagesFetch, env.Now)
	eq, err := xlinks.EnqueuePages(pctx, conn, nil)
	if err != nil {
		if missingTable(err) {
			slog.Warn("web page queue skipped: migration 0020 not applied (run `nday migrate`)")
			run.Finish(ctx, errors.New("web page queue: migration 0020 not applied"), nil)
			return
		}
		slog.Warn("x link enqueue failed (run result unaffected)", "err", err, "added", eq.Added)
		run.Finish(ctx, err, eq)
		return
	}
	slog.Info("x link enqueue", "candidates", eq.Candidates, "added", eq.Added, "refused", eq.Refused)
	if env.Transport != nil {
		slog.Info("web page fetch pass skipped: injected transport (tests, replay)")
		run.Finish(ctx, nil, eq)
		return
	}
	pr, err := webpages.FetchPending(pctx, conn, webpages.Options{Limit: postRunPagesLimit, Now: env.Now,
		Backfill: webpages.DefaultBackfill})
	run.Finish(ctx, err, pr)
	if err != nil {
		slog.Warn("web page fetch pass failed (run result unaffected)", "err", err, "ok", pr.OK)
		return
	}
	slog.Info("web page fetch pass", "candidates", pr.Candidates, "ok", pr.OK, "none", pr.None, "retry", pr.Retry,
		"failed", pr.Failed, "refused", pr.Refused, "requests", pr.Requests, "backfilled", pr.Backfilled, "published", pr.Published)
}

// Bounds of the page steps after `nday collect xposts`.
const (
	postRunPagesTimeout = 2 * time.Minute
	postRunPagesLimit   = 25
)

// missingTable reports whether err is Postgres' undefined_table (a
// migration not applied yet).
func missingTable(err error) bool {
	var ue interface{ SQLState() string }
	return errors.As(err, &ue) && ue.SQLState() == "42P01"
}

// nday x-links-enqueue
//
// Hands the links of stored X posts to the web page queue
// (xlinks.EnqueuePages; idempotent, also the backfill). The same step runs
// after every successful `nday collect xposts`. Output: counts as JSON.
func runXLinksEnqueue(ctx context.Context, env Env, prog string, rest []string) error {
	if _, err := parseArgs(prog, nil, rest, 0); err != nil {
		return err
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := xlinks.EnqueuePages(ctx, conn, nil)
	printJSON(env, res)
	return err
}

// nday pages-fetch [--limit N]
//
// One pass of the web page queue (webpages.FetchPending, docs/webpages.md):
// fetches pending third-party pages through the SSRF-guarded client
// (internal/pagefetch; never an injected transport) and stores their
// titles and publication times, then re-fetches up to
// webpages.DefaultBackfill older 'ok' pages once for their publication
// time. The same pass runs after every successful `nday collect xposts`.
// Output: the pass's counts as JSON.
func runPagesFetch(ctx context.Context, env Env, prog string, rest []string) error {
	limit, err := limitArg(prog, rest, webpages.DefaultLimit)
	if err != nil {
		return err
	}
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	run := jobrun.Start(ctx, conn, jobrun.PagesFetch, env.Now)
	res, err := webpages.FetchPending(sctx, conn, webpages.Options{Limit: limit, Now: env.Now, Backfill: webpages.DefaultBackfill})
	run.Finish(ctx, err, res)
	printJSON(env, res)
	return err
}

// nday x-candidates [--limit N]
//
// Lists pending allowlist candidates (internal/xconfig ListCandidates): X
// users that allowlisted researchers quote, reply to or mention, most
// distinct referrers first. One line each:
//
//	<user id> @<handle>|(no handle) referrers=N refs=N kinds=a,b first=YYYY-MM-DD last=YYYY-MM-DD posts=id,id
func runXCandidates(ctx context.Context, env Env, prog string, rest []string) error {
	limit, err := limitArg(prog, rest, 50)
	if err != nil {
		return err
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	cs, err := xconfig.ListCandidates(ctx, conn, xconfig.CandidatePending, limit, 0)
	if err != nil {
		return err
	}
	for _, c := range cs {
		h := "(no handle)"
		if c.Handle != nil && xconfig.ValidHandle(*c.Handle) {
			h = "@" + *c.Handle
		}
		fmt.Fprintf(env.Stdout, "%s %s referrers=%d refs=%d kinds=%s first=%s last=%s posts=%s\n", c.UserID, h,
			c.Referrers, c.Refs, strings.Join(c.Kinds, ","), c.FirstSeenAt.Format(time.DateOnly),
			c.LastSeenAt.Format(time.DateOnly), strings.Join(c.SamplePosts, ","))
	}
	fmt.Fprintf(env.Stdout, "x-candidates: %d shown\n", len(cs))
	return nil
}

// limitArg parses the only option of the commands above, --limit N (N >= 1).
func limitArg(prog string, rest []string, def int) (int, error) {
	p, err := parseArgs(prog, []optSpec{{name: "--limit", hasValue: true}}, rest, 0)
	if err != nil {
		return 0, err
	}
	v, ok := p.flags["--limit"]
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(pystr.Strip(v))
	if err != nil || n < 1 {
		return 0, &usageError{prog, fmt.Sprintf("argument --limit: invalid int value: '%s'", v)}
	}
	return n, nil
}
