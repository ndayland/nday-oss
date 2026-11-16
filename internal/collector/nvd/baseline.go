package nvd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
)

// BaselineOptions for ImportBaseline.
type BaselineOptions struct {
	// Dir holds nvdcve-2.0-YYYY.json.gz (or YYYY.json.gz) files and, ideally,
	// their nvdcve-2.0-YYYY.meta; Fetcher != nil downloads instead.
	Dir     string
	Fetcher *Fetcher
	// Years to import (default FirstYear..current year).
	Years     []int
	DryRun    bool
	Limit     int // total records written across files (0 = none)
	BatchSize int
	Now       func() time.Time
	Logger    *slog.Logger
}

// BaselineStats sums the files.
type BaselineStats struct {
	Files      []*FileStats `json:"files"`
	Missing    []string     `json:"missing,omitempty"`
	Unverified []string     `json:"unverified,omitempty"`
	Total      WriteStats   `json:"total"`
	ElapsedSec float64      `json:"elapsed_sec"`
}

// DefaultYears is FirstYear..the current year.
func DefaultYears(now time.Time) []int {
	var ys []int
	for y := FirstYear; y <= now.UTC().Year(); y++ {
		ys = append(ys, y)
	}
	return ys
}

// ImportBaseline imports yearly feeds into raw_record (source nvd) through
// ImportFeed. It never touches collector_state (the incremental collector's
// cursor), vuln or event. Per file:
//   - download (Fetcher): the .meta is fetched first and the .json.gz must
//     match it (gzSize, complete gzip, size, SHA-256) before anything is
//     parsed; snapshot = the .meta lastModifiedDate;
//   - Dir: if the .meta is next to the file it is verified the same way;
//     otherwise the file is imported unverified (listed in Unverified) with
//     snapshot = the file's modification time.
//
// Files are streamed (gzip -> json.Decoder token stream), so memory stays
// bounded whatever the file size; with Fetcher the compressed bytes of one
// file are held in memory (at most MaxGzBytes).
// Re-running imports nothing new; an interrupted run is resumed by running
// it again (unchanged records are skipped by content hash).
func ImportBaseline(ctx context.Context, conn *pgx.Conn, o BaselineOptions) (*BaselineStats, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if len(o.Years) == 0 {
		o.Years = DefaultYears(o.Now())
	}
	if (o.Dir == "") == (o.Fetcher == nil) {
		return nil, errors.New("nvd baseline: exactly one of Dir or Fetcher")
	}
	start := time.Now()
	st := &BaselineStats{Files: []*FileStats{}}
	written := 0
	for _, y := range o.Years {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		name := yearName(y)
		var (
			src      io.Reader
			closeFn  = func() {}
			snapshot time.Time
			verified bool
		)
		if o.Fetcher != nil {
			m, body, err := o.Fetcher.MetaAndFeed(ctx, name)
			if err != nil {
				return st, fmt.Errorf("nvd %s: %w", name, err)
			}
			src, snapshot, verified = bytes.NewReader(body), m.LastModified, true
			o.Logger.Info("nvd feed downloaded and verified", "feed", name, "gz_bytes", len(body), "unpacked_bytes", m.Size,
				"last_modified", m.Raw)
		} else {
			path := ""
			for _, cand := range []string{"nvdcve-2.0-" + name + ".json.gz", name + ".json.gz"} {
				if _, err := os.Stat(filepath.Join(o.Dir, cand)); err == nil {
					path = filepath.Join(o.Dir, cand)
					break
				}
			}
			if path == "" {
				st.Missing = append(st.Missing, name)
				o.Logger.Warn("nvd baseline file missing, skipped", "year", y, "dir", o.Dir)
				continue
			}
			fi, err := os.Stat(path)
			if err != nil {
				return st, err
			}
			snapshot = fi.ModTime()
			metaPath := filepath.Join(o.Dir, "nvdcve-2.0-"+name+".meta")
			if mb, err := os.ReadFile(metaPath); err == nil {
				m, err := ParseMeta(mb)
				if err != nil {
					return st, fmt.Errorf("%s: %w", metaPath, err)
				}
				if fi.Size() != m.GzSize {
					return st, &ChecksumError{Msg: fmt.Sprintf("%s: %d bytes, .meta gzSize %d", path, fi.Size(), m.GzSize)}
				}
				f, err := os.Open(path)
				if err != nil {
					return st, err
				}
				err = Verify(f, m)
				f.Close()
				if err != nil {
					return st, fmt.Errorf("%s: %w", path, err)
				}
				snapshot, verified = m.LastModified, true
			} else if !errors.Is(err, os.ErrNotExist) {
				return st, err
			} else {
				st.Unverified = append(st.Unverified, name)
				o.Logger.Warn("no .meta next to the file: importing without checksum verification; snapshot = file mtime",
					"file", path, "mtime", snapshot.UTC().Format(time.RFC3339))
			}
			f, err := os.Open(path)
			if err != nil {
				return st, err
			}
			src, closeFn = f, func() { f.Close() }
		}
		var limit int
		if o.Limit > 0 {
			limit = o.Limit - written
		}
		fs, err := func() (*FileStats, error) {
			defer closeFn()
			r, err := Unpack(src, MaxUnpackedBytes)
			if err != nil {
				return nil, err
			}
			return ImportFeed(ctx, conn, r, ImportOptions{Snapshot: snapshot, BatchSize: o.BatchSize, DryRun: o.DryRun,
				Limit: limit, Logger: o.Logger, Label: name})
		}()
		if fs != nil {
			fs.Verified = verified
			st.Files = append(st.Files, fs)
			st.Total.add(fs.WriteStats)
			written += fs.New + fs.Reverted
			o.Logger.Info("nvd feed imported", "feed", name, "entries", fs.Entries, "new", fs.New, "reverted", fs.Reverted,
				"unchanged", fs.Unchanged, "stale", fs.Stale, "bad", fs.BadEntries, "sec", fmt.Sprintf("%.1f", fs.ElapsedSec))
		}
		if err != nil {
			return st, fmt.Errorf("nvd %s: %w", name, err)
		}
		if fs.LimitReached {
			o.Logger.Info("--limit reached", "written", written)
			break
		}
	}
	st.ElapsedSec = time.Since(start).Seconds()
	return st, nil
}
