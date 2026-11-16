package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/cveimport"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/state"
)

// nday import-cve-baseline: one-off bulk import of the full CVE history (the
// cvelistV5 midnight baseline) through the cvelist collector's Normalize and
// the pipeline's writes; see internal/cveimport (Import documents the rules).
//
//	nday import-cve-baseline (--file PATH | --tmp-dir DIR)
//	    [--dry-run] [--limit N] [--batch-size N] [--year YYYY]
//	    [--snapshot-date YYYY-MM-DD] [--analyze] [--no-refresh]
//	    [--keep-download] [--max-download-bytes N] [--workers N] [--progress-every N]
//
// The first SIGINT/SIGTERM finishes the batch in flight and stops (exit 1,
// stats printed, re-run to continue); a second one aborts the batch in
// flight (rolled back).

func runImportCVEBaseline(ctx context.Context, env Env, prog string, rest []string) error {
	p, err := parseArgs(prog, []optSpec{
		{name: "--file", hasValue: true}, {name: "--tmp-dir", hasValue: true},
		{name: "--dry-run"}, {name: "--limit", hasValue: true}, {name: "--batch-size", hasValue: true},
		{name: "--year", hasValue: true}, {name: "--snapshot-date", hasValue: true},
		{name: "--analyze"}, {name: "--no-refresh"}, {name: "--keep-download"},
		{name: "--max-download-bytes", hasValue: true}, {name: "--workers", hasValue: true},
		{name: "--progress-every", hasValue: true},
	}, rest, 0)
	if err != nil {
		return err
	}
	intFlag := func(name string, def, lo int) (int, error) {
		v, ok := p.flags[name]
		if !ok {
			return def, nil
		}
		n, err := strconv.Atoi(pystr.Strip(v))
		if err != nil || n < lo {
			return 0, &usageError{prog, fmt.Sprintf("argument %s: invalid value: '%s'", name, v)}
		}
		return n, nil
	}
	o := cveimport.Options{}
	if o.Limit, err = intFlag("--limit", 0, 1); err != nil {
		return err
	}
	if o.BatchSize, err = intFlag("--batch-size", cveimport.DefaultBatchSize, 1); err != nil {
		return err
	}
	if o.BatchSize > 50000 {
		return &usageError{prog, "argument --batch-size: at most 50000"}
	}
	if o.Year, err = intFlag("--year", 0, 1999); err != nil {
		return err
	}
	if o.Workers, err = intFlag("--workers", 0, 1); err != nil {
		return err
	}
	if o.ProgressEvery, err = intFlag("--progress-every", cveimport.DefaultProgressEvery, 1); err != nil {
		return err
	}
	maxDL := cveimport.DefaultMaxDownloadBytes
	if v, ok := p.flags["--max-download-bytes"]; ok {
		n, err := strconv.ParseInt(pystr.Strip(v), 10, 64)
		if err != nil || n < 1 {
			return &usageError{prog, fmt.Sprintf("argument --max-download-bytes: invalid value: '%s'", v)}
		}
		maxDL = n
	}
	_, o.DryRun = p.flags["--dry-run"]
	_, analyze := p.flags["--analyze"]
	_, noRefresh := p.flags["--no-refresh"]
	_, keep := p.flags["--keep-download"]
	file, haveFile := p.flags["--file"]
	tmpDir := p.flags["--tmp-dir"]
	if !haveFile && tmpDir == "" {
		return &usageError{prog, "one of --file or --tmp-dir is required (--tmp-dir: where to download the baseline)"}
	}
	var snapshot time.Time
	if v, ok := p.flags["--snapshot-date"]; ok {
		d, err := time.Parse("2006-01-02", pystr.Strip(v))
		if err != nil {
			return &usageError{prog, fmt.Sprintf("argument --snapshot-date: invalid date: '%s'", v)}
		}
		snapshot = d.UTC()
	}
	if haveFile && snapshot.IsZero() {
		d, ok := cveimport.SnapshotDateFromName(file)
		if !ok {
			return &usageError{prog, "cannot tell the snapshot date from the file name; pass --snapshot-date YYYY-MM-DD"}
		}
		snapshot = d
	}

	// Signals: first -> stop after the batch in flight; second -> abort.
	hard, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		n := 0
		for {
			select {
			case s := <-sigs:
				n++
				if n == 1 {
					slog.Warn("signal received: finishing the current batch, then stopping (send again to abort it)", "signal", s.String())
					close(stop)
				} else {
					slog.Warn("second signal: aborting the current batch", "signal", s.String())
					cancel()
					return
				}
			case <-hard.Done():
				return
			}
		}
	}()
	o.Stop = stop
	log := slog.Default()
	o.Logger = log

	downloaded := ""
	if !haveFile {
		b, err := cveimport.Locate(hard, cveimport.LocateOptions{Transport: env.Transport, Logger: log})
		if err != nil {
			return err
		}
		log.Info("latest baseline located", "tag", b.Tag, "asset", b.Asset, "bytes", b.Size, "etag", b.ETag, "url", b.URL)
		dl, err := cveimport.Download(hard, b, tmpDir, cveimport.DownloadOptions{Transport: env.Transport,
			MaxBytes: maxDL, Logger: log})
		if err != nil {
			return err
		}
		log.Info("baseline downloaded", "path", dl.Path, "bytes", dl.Size, "sha256", dl.SHA256, "resumed", dl.Resumed)
		file, downloaded = dl.Path, dl.Path
		if snapshot.IsZero() {
			snapshot = b.Date
		}
	}
	o.SnapshotAt = snapshot

	arc, err := cveimport.OpenArchive(file, tmpDir, 0, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := arc.Close(); err != nil {
			log.Warn("could not remove the extracted archive", "err", err)
		}
	}()
	c, err := cvelist.New(cvelist.Options{})
	if err != nil {
		return err
	}
	conn, err := connect(hard)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))

	st, runErr := cveimport.Import(hard, conn, arc, c, o)
	if st != nil {
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(env.Stdout, string(out))
	}
	if !o.DryRun && st != nil && st.Imported > 0 && hard.Err() == nil {
		if noRefresh {
			log.Warn("--no-refresh: vuln_state_mat NOT refreshed; run `nday refresh-state`")
		} else {
			t0 := time.Now()
			res, err := state.Refresh(hard, conn, state.RefreshOptions{Wait: true, Logger: log})
			if err != nil {
				log.Error("derived state refresh failed; run `nday refresh-state`", "err", err)
			} else {
				log.Info("derived state refreshed", "refreshes", res.Refreshes, "refresh_ms", res.Elapsed.Milliseconds(),
					"total_ms", time.Since(t0).Milliseconds())
			}
		}
		if analyze {
			t0 := time.Now()
			if _, err := conn.Exec(hard, `ANALYZE raw_record, vuln, vuln_alias, affected, event, vuln_state_mat`); err != nil {
				log.Error("ANALYZE failed", "err", err)
			} else {
				log.Info("ANALYZE done", "ms", time.Since(t0).Milliseconds())
			}
		}
	}
	if runErr != nil {
		if downloaded != "" {
			log.Info("download kept for the next run", "path", downloaded)
		}
		return runErr
	}
	if st.Interrupted {
		if downloaded != "" {
			log.Info("download kept for the next run", "path", downloaded)
		}
		return errors.New("interrupted: the batch in flight was committed; re-run the same command to continue")
	}
	if downloaded != "" && !o.DryRun && !keep {
		if err := os.Remove(downloaded); err != nil {
			log.Warn("could not remove the download", "path", downloaded, "err", err)
		} else {
			log.Info("download removed", "path", downloaded)
		}
	}
	return nil
}
