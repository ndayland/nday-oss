package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/collector/nvd"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/site"
)

// nday import-nvd-baseline (--dir DIR | --download) [--year YYYY ...]
//
//	[--dry-run] [--limit N] [--batch-size N]
//
// One-off import of NVD's yearly JSON 2.0 feeds into raw_record (source
// nvd); see internal/collector/nvd (ImportBaseline) and docs/nvd.md. It does
// not classify: run `nday classify --all` (or --source nvd) afterwards.
//
// nday classify (--all | --source S | --cve ID [ID ...] | --pending) [--dry-run] [--batch-size N]
//
// Derives vuln_cwe / vuln_cvss from the latest raw records (internal/classify).

// takeRepeated removes every "--name V" / "--name=V" from args (argparse
// action="append") and returns the values and the rest.
func takeRepeated(prog string, args []string, name string) ([]string, []string, error) {
	var vals, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if a == name {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return nil, nil, &usageError{prog, fmt.Sprintf("argument %s: expected one argument", name)}
			}
			vals = append(vals, args[i+1])
			i++
			continue
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			vals = append(vals, v)
			continue
		}
		rest = append(rest, a)
	}
	return vals, rest, nil
}

func intOpt(prog string, p *parsed, name string, def, lo, hi int) (int, error) {
	v, ok := p.flags[name]
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(pystr.Strip(v))
	if err != nil || n < lo || (hi > 0 && n > hi) {
		return 0, &usageError{prog, fmt.Sprintf("argument %s: invalid value: '%s'", name, v)}
	}
	return n, nil
}

func signalContext(ctx context.Context) (context.Context, func()) {
	return signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
}

func printJSON(env Env, v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(env.Stdout, string(out))
}

func runImportNVDBaseline(ctx context.Context, env Env, prog string, rest []string) error {
	yearVals, rest, err := takeRepeated(prog, rest, "--year")
	if err != nil {
		return err
	}
	p, err := parseArgs(prog, []optSpec{
		{name: "--dir", hasValue: true}, {name: "--download"}, {name: "--dry-run"},
		{name: "--limit", hasValue: true}, {name: "--batch-size", hasValue: true},
	}, rest, 0)
	if err != nil {
		return err
	}
	o := nvd.BaselineOptions{Logger: slog.Default(), Now: env.Now}
	dir, haveDir := p.flags["--dir"]
	_, download := p.flags["--download"]
	if haveDir == download {
		return &usageError{prog, "exactly one of --dir DIR or --download is required"}
	}
	for _, v := range yearVals {
		for _, part := range strings.Split(v, ",") {
			y, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || y < nvd.FirstYear || y > 9999 {
				return &usageError{prog, fmt.Sprintf("argument --year: invalid value: '%s' (feeds start at %d)", v, nvd.FirstYear)}
			}
			o.Years = append(o.Years, y)
		}
	}
	sort.Ints(o.Years)
	if o.Limit, err = intOpt(prog, p, "--limit", 0, 1, 0); err != nil {
		return err
	}
	if o.BatchSize, err = intOpt(prog, p, "--batch-size", nvd.DefaultBatchSize, 1, 50000); err != nil {
		return err
	}
	_, o.DryRun = p.flags["--dry-run"]
	if haveDir {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return &usageError{prog, fmt.Sprintf("argument --dir: not a directory: '%s'", dir)}
		}
		o.Dir = dir
	} else {
		o.Fetcher = nvd.NewFetcher(nvd.FetcherOptions{Transport: env.Transport, Logger: slog.Default()})
	}
	sctx, stop := signalContext(ctx)
	defer stop()
	conn, err := connect(sctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	st, runErr := nvd.ImportBaseline(sctx, conn, o)
	if st != nil {
		printJSON(env, st)
	}
	if runErr == nil && !o.DryRun {
		slog.Info("next: `nday classify --source nvd` (or --all after a cvelist baseline) to fill vuln_cwe / vuln_cvss")
	}
	return runErr
}

func runClassify(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{
		{name: "--all"}, {name: "--source", hasValue: true}, {name: "--cve"}, {name: "--pending"},
		{name: "--dry-run"}, {name: "--batch-size", hasValue: true},
	}, rest, 1<<20)
	if err != nil {
		return err
	}
	_, all := p.flags["--all"]
	source, bySource := p.flags["--source"]
	_, byCVE := p.flags["--cve"]
	_, pending := p.flags["--pending"]
	n := 0
	for _, b := range []bool{all, bySource, byCVE, pending} {
		if b {
			n++
		}
	}
	if n != 1 {
		return &usageError{prog, "exactly one of --all, --source S, --cve ID [ID ...] or --pending is required"}
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
	if bySource {
		ok := false
		for _, f := range classify.Families {
			ok = ok || f == source
		}
		if !ok {
			return &usageError{prog, fmt.Sprintf("argument --source: invalid choice: '%s' (choose from %s)", source, quoteChoices(classify.Families))}
		}
	}
	o := classify.Options{Wait: true, Logger: slog.Default()}
	if o.BatchSize, err = intOpt(prog, p, "--batch-size", classify.DefaultBatchSize, 1, 50000); err != nil {
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
	var st *classify.Stats
	switch {
	case all:
		st, err = classify.All(sctx, conn, o)
	case bySource:
		st, err = classify.BySource(sctx, conn, source, o)
	case byCVE:
		st, err = classify.ByCVE(sctx, conn, ids, o)
	default:
		st, err = classify.Pending(sctx, conn, o)
	}
	if st != nil {
		printJSON(env, st)
	}
	if err == nil && o.DryRun {
		slog.Info("dry run: every batch rolled back, nothing written")
	}
	return err
}

// postRunClassify is the incremental classification pass after a collector
// run: drain classify_queue (bounded), without waiting for a concurrent
// classify run. Failures are logged and never fail the collector run (its
// data is committed; the queue keeps the work for the next pass).
func postRunClassify(ctx context.Context, conn *pgx.Conn) {
	st, err := classify.Pending(ctx, conn, classify.Options{MaxQueue: 200000, Logger: slog.Default()})
	if err != nil {
		var ue interface{ SQLState() string }
		if errors.As(err, &ue) && ue.SQLState() == "42P01" {
			slog.Warn("classification pass skipped: migration 0009 not applied (run `nday migrate`)")
			return
		}
		slog.Warn("classification pass failed (run result unaffected; the queue is kept)", "err", err)
		return
	}
	if st.Deferred {
		return
	}
	slog.Info("classification pass", "queue_rows", st.QueueRows, "cves", st.CVEs, "changed", st.Changed,
		"cwe_inserted", st.CWEInserted, "cvss_inserted", st.CVSSInserted, "no_vuln", st.NoVuln,
		"sec", fmt.Sprintf("%.2f", st.ElapsedSec))
}
