package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"nday.land/nday/internal/config"
	"nday.land/nday/internal/stats"
	"nday.land/nday/internal/web"
)

// nday stats-rollup: roll the access logs of NDAY_LOG_DIR up into the
// stats_* tables (internal/stats, docs/stats.md).
//
//	nday stats-rollup [--dir DIR] [--day YYYY-MM-DD ...] [--all] [--dry-run]
//
// Without --day/--all, every access-*.log whose (size, mtime) changed since
// its last rollup is recomputed. --day may be repeated. The log directory
// is only read.

func runStatsRollup(ctx context.Context, env Env, prog string, rest []string) error {
	o := stats.Options{Log: slog.Default()}
	if env.Now != nil {
		o.Now = env.Now
	}
	dirSet := false
	for i := 0; i < len(rest); i++ {
		name, val, hasEq := strings.Cut(rest[i], "=")
		takeValue := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(rest) || strings.HasPrefix(rest[i+1], "-") {
				return "", &usageError{prog, fmt.Sprintf("argument %s: expected one argument", name)}
			}
			i++
			return rest[i], nil
		}
		switch name {
		case "--dir":
			v, err := takeValue()
			if err != nil {
				return err
			}
			o.Dir, dirSet = v, true
		case "--day":
			v, err := takeValue()
			if err != nil {
				return err
			}
			if _, err := stats.ParseDay(v); err != nil {
				return &usageError{prog, "argument --day: " + err.Error()}
			}
			o.Days = append(o.Days, v)
		case "--all", "--dry-run":
			if hasEq {
				return &usageError{prog, fmt.Sprintf("argument %s: ignored explicit argument '%s'", name, val)}
			}
			if name == "--all" {
				o.All = true
			} else {
				o.DryRun = true
			}
		default:
			return &usageError{prog, "unrecognized arguments: " + strings.Join(rest[i:], " ")}
		}
	}
	if o.All && len(o.Days) > 0 {
		return &usageError{prog, "argument --all: not allowed with argument --day"}
	}
	if !dirSet {
		if err := config.LoadDotenv(""); err != nil {
			return err
		}
		o.Dir = os.Getenv(web.EnvLogDir)
		if o.Dir == "" {
			return &usageError{prog, "no log directory: pass --dir or set " + web.EnvLogDir}
		}
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	res, err := stats.Rollup(ctx, conn, o)
	if res != nil {
		for _, d := range res.Days {
			fmt.Fprintf(env.Stdout, "%s %s files=%d lines=%d bad=%d partial=%d misfiled_in=%d misfiled_out=%d requests=%d pv=%d uv=%d\n",
				d.Day, d.Status, len(d.Files), d.Lines, d.Bad, d.Partial, d.MisfiledIn, d.MisfiledOut, d.Requests, d.PageViews, d.Visitors)
		}
		if err == nil {
			fmt.Fprintf(env.Stdout, "days: %d, visitor rows pruned: %d\n", len(res.Days), res.PrunedVisitors)
			if res.DryRun {
				fmt.Fprintln(env.Stdout, "dry run: every transaction rolled back, nothing written")
			}
		}
	}
	return err
}
