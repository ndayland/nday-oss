package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector/ghsa"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pystr"
)

// Bounds of the GitHub steps after `nday collect xposts` (as the page
// steps: postRunPagesTimeout, postRunPagesLimit).
const (
	postRunGitHubTimeout = 2 * time.Minute
	postRunGitHubLimit   = 25
	postRunGitHubRefresh = 5
)

// githubToken is the optional GitHub token of the repository module: the
// NDAY_GITHUB_TOKEN setting (the ghsa collector's; database settings,
// encrypted, layered over envSnap). "" = unauthenticated. Never logged.
func githubToken(ctx context.Context, conn *pgx.Conn, envSnap func(string) (string, bool)) string {
	tok, _ := loadSnapshot(ctx, conn).Lookup(envSnap)(ghsa.TokenEnv)
	return pystr.Strip(tok)
}

// postRunGitHub is the GitHub repository step after a successful `nday
// collect xposts` (after the web page step): the enqueue sweep
// (ghrepo.Enqueue) and one fetch pass (ghrepo.FetchPending) to
// https://api.github.com only, sharing their own deadline
// (postRunGitHubTimeout) with at most postRunGitHubLimit repositories
// (postRunGitHubRefresh of them refreshes). It never fails the collector
// run: errors are logged. With an injected Env.Transport (tests,
// tools/replay) the fetch pass is skipped.
func postRunGitHub(ctx context.Context, conn *pgx.Conn, env Env, envSnap func(string) (string, bool)) {
	gctx, cancel := context.WithTimeout(ctx, postRunGitHubTimeout)
	defer cancel()
	before := pocFingerprint(ctx, conn)
	defer refreshIfPoCChanged(ctx, conn, before)
	run := jobrun.Start(ctx, conn, jobrun.GitHubFetch, env.Now)
	eq, err := ghrepo.Enqueue(gctx, conn, nil)
	if err != nil {
		if missingTable(err) || missingColumn(err) {
			slog.Warn("github repository queue skipped: migration 0023 not applied (run `nday migrate`)")
			run.Finish(ctx, errors.New("github repository queue: migration 0023 not applied"), nil)
			return
		}
		slog.Warn("github enqueue failed (run result unaffected)", "err", err, "added", eq.Added)
		run.Finish(ctx, err, eq)
		return
	}
	slog.Info("github enqueue", "candidates", eq.Candidates, "added", eq.Added, "not_repo", eq.NotRepo, "post_cves", eq.PostCVEs)
	if env.Transport != nil {
		slog.Info("github fetch pass skipped: injected transport (tests, replay)")
		run.Finish(ctx, nil, eq)
		return
	}
	tok := githubToken(gctx, conn, envSnap)
	res, err := ghrepo.FetchPending(gctx, conn, ghrepo.Options{Limit: postRunGitHubLimit, RefreshLimit: postRunGitHubRefresh,
		Token: tok, Now: env.Now})
	logGitHubPass(res, err, tok != "")
	run.Finish(ctx, err, res)
}

func logGitHubPass(res ghrepo.Result, err error, authenticated bool) {
	if err != nil {
		slog.Warn("github fetch pass failed (run result unaffected)", "err", err, "ok", res.OK)
		return
	}
	slog.Info("github fetch pass", "candidates", res.Candidates, "ok", res.OK, "not_modified", res.NotModified, "gone", res.Gone,
		"merged", res.Merged, "retry", res.Retry, "failed", res.Failed, "rate_limited", res.RateLimited, "requests", res.Requests,
		"remaining", res.Remaining, "locked", res.Locked, "authenticated", authenticated)
}

// missingColumn reports whether err is Postgres' undefined_column (e.g.
// x_post_link.repo_queued_url before migration 0023).
func missingColumn(err error) bool {
	var ue interface{ SQLState() string }
	return errors.As(err, &ue) && ue.SQLState() == "42703"
}

// nday github-enqueue
//
// Queues the GitHub repositories linked from stored X posts
// (ghrepo.Enqueue; idempotent, also the backfill; docs/github.md). The
// same step runs after every successful `nday collect xposts`. Output:
// counts as JSON.
func runGitHubEnqueue(ctx context.Context, env Env, prog string, rest []string) error {
	if _, err := parseArgs(prog, nil, rest, 0); err != nil {
		return err
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := ghrepo.Enqueue(ctx, conn, nil)
	printJSON(env, res)
	return err
}

// nday github-discover [--max-requests N]
//
// One discovery run (ghrepo.Discover, docs/github.md "Discovery"): the
// new-repository scan and the targeted search for hot CVEs through
// GET https://api.github.com/search/repositories, at most N requests
// (default ghrepo.DefaultMaxRequests, at most ghrepo.MaxMaxRequests),
// spaced so the per-minute search limit cannot be reached, with
// NDAY_GITHUB_TOKEN when set. Stops cleanly at the rate limit; a run
// while another holds the lock does nothing ("locked": true). Run by
// deploy/systemd/nday-github-discover.timer. Output: the counts as JSON;
// one summary log line.
func runGitHubDiscover(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{{name: "--max-requests", hasValue: true}}, rest, 0)
	if err != nil {
		return err
	}
	maxReq := ghrepo.DefaultMaxRequests
	if v, ok := p.flags["--max-requests"]; ok {
		n, err := strconv.Atoi(pystr.Strip(v))
		if err != nil || n < 1 || n > ghrepo.MaxMaxRequests {
			return &usageError{prog, fmt.Sprintf("argument --max-requests: invalid value: '%s' (1..%d)", v, ghrepo.MaxMaxRequests)}
		}
		maxReq = n
	}
	envSnap := environSnapshot()
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tok := githubToken(sctx, conn, envSnap)
	before := pocFingerprint(ctx, conn)
	run := jobrun.Start(ctx, conn, jobrun.GitHubDiscover, env.Now)
	res, err := ghrepo.Discover(sctx, conn, ghrepo.DiscoverOptions{MaxRequests: maxReq, Token: tok, Now: env.Now})
	if err != nil && (missingTable(err) || missingColumn(err)) {
		err = errors.New("github discovery: migration 0025 not applied (run `nday migrate`)")
	}
	logDiscover(res, err, tok != "")
	run.Finish(ctx, err, res)
	printJSON(env, res)
	// the hourly safety net of the PoC events (migration 0032): what no
	// trigger sees (a changed publication date, the predates test) and
	// anything out of step is repaired here
	prun := jobrun.Start(ctx, conn, jobrun.GitHubPoC, env.Now)
	if pr, perr := ghrepo.SyncPoC(context.WithoutCancel(ctx), conn, false); perr != nil {
		if missingFunction(perr) {
			prun.Finish(ctx, errors.New("github poc repair: migration 0032 not applied"), nil)
		} else {
			slog.Warn("github poc repair failed (run result unaffected)", "err", perr)
			prun.Finish(ctx, perr, nil)
		}
	} else {
		slog.Info("github poc repair", "vulns", pr.Vulns, "added", pr.Added, "removed", pr.Removed, "updated", pr.Updated)
		prun.Finish(ctx, nil, pr)
	}
	refreshIfPoCChanged(ctx, conn, before)
	return err
}

// pocFingerprint is ghrepo.PoCFingerprint, "" when it cannot be read.
func pocFingerprint(ctx context.Context, conn *pgx.Conn) string {
	fp, err := ghrepo.PoCFingerprint(context.WithoutCancel(ctx), conn)
	if err != nil {
		slog.Warn("github poc fingerprint failed", "err", err)
		return ""
	}
	return fp
}

// refreshIfPoCChanged refreshes vuln_state_mat (pipeline.RefreshState:
// non-blocking, a busy refresh takes the request over) when the github
// PoC events differ from before, so the lists agree with the
// vulnerability pages without waiting for the next collector run.
func refreshIfPoCChanged(ctx context.Context, conn *pgx.Conn, before string) {
	if before == "" {
		return
	}
	if after := pocFingerprint(ctx, conn); after != "" && after != before {
		pipeline.RefreshState(context.WithoutCancel(ctx), conn, slog.Default())
	}
}

func logDiscover(res ghrepo.DiscoverResult, err error, authenticated bool) {
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	slog.Log(context.Background(), lvl, "github discover pass", "requests", res.Requests, "scan_pages", res.ScanPages,
		"scan_windows", res.ScanWindows, "scan_dropped", res.ScanDropped, "cves", res.CVEs, "cve_failed", res.CVEFailed,
		"items", res.Items, "added", res.Added, "updated", res.Updated, "skipped", res.Skipped, "skipped_forks", res.SkippedForks,
		"hidden", res.Hidden,
		"malformed", res.Malformed, "failed", res.Failed, "incomplete", res.Incomplete, "rate_limited", res.RateLimited,
		"timed_out", res.TimedOut, "remaining", res.Remaining, "locked", res.Locked, "authenticated", authenticated,
		"err", errString(err))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// nday github-fetch [--limit N]
//
// One pass of the GitHub repository queue (ghrepo.FetchPending,
// docs/github.md): GET https://api.github.com/repos/{owner}/{repo} for
// pending repositories and due refreshes, with NDAY_GITHUB_TOKEN when set
// (database settings or the environment), else unauthenticated. Stops
// cleanly at the rate limit. Never an injected transport. Output: the
// pass's counts as JSON.
func runGitHubFetch(ctx context.Context, env Env, prog string, rest []string) error {
	limit, err := limitArg(prog, rest, ghrepo.DefaultLimit)
	if err != nil {
		return err
	}
	envSnap := environSnapshot()
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tok := githubToken(sctx, conn, envSnap)
	before := pocFingerprint(ctx, conn)
	run := jobrun.Start(ctx, conn, jobrun.GitHubFetch, env.Now)
	res, err := ghrepo.FetchPending(sctx, conn, ghrepo.Options{Limit: limit, Token: tok, Now: env.Now})
	run.Finish(ctx, err, res)
	printJSON(env, res)
	refreshIfPoCChanged(ctx, conn, before)
	return err
}

// nday github-poc [--dry-run]
//
// Backfill and repair of the PoC events trusted GitHub repositories give
// (ghrepo.SyncPoC, migrations/0032_github_poc.sql, docs/github.md "PoC
// events"): brings the github events of every associated vulnerability in
// step, marking what it adds as history (is_backfill: no X draft). The
// migration already does this once; a second run prints zeros. Refreshes
// the derived state when something changed. Output: the counts as JSON.
func runGitHubPoC(ctx context.Context, env Env, prog string, rest []string) error {
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
	res, err := ghrepo.SyncPoC(sctx, conn, dry)
	if err != nil && (missingTable(err) || missingFunction(err)) {
		err = errors.New("github poc: migration 0032 not applied (run `nday migrate`)")
	}
	printJSON(env, res)
	if err == nil && !dry && res.Changed() {
		pipeline.RefreshState(sctx, conn, slog.Default())
	}
	return err
}

// missingFunction reports Postgres' undefined_function (before 0032).
func missingFunction(err error) bool {
	var ue interface{ SQLState() string }
	return errors.As(err, &ue) && ue.SQLState() == "42883"
}
