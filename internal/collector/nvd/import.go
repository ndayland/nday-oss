package nvd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// DefaultBatchSize: records per transaction of a file import.
const DefaultBatchSize = 2000

// ImportOptions for ImportFeed.
type ImportOptions struct {
	// Snapshot is the fetched_at of every record of this feed: the feed's
	// .meta lastModifiedDate (or, without a .meta, the file's mtime).
	Snapshot  time.Time
	BatchSize int
	DryRun    bool
	// Limit stops after this many records were written (new or reverted);
	// 0 = no limit. Stats.LimitReached tells.
	Limit  int
	Logger *slog.Logger
	// ProgressEvery logs every this many entries (0 = 20000).
	ProgressEvery int
	// OneTx: write the whole feed in tx (already open, owned by the caller)
	// instead of one transaction per batch.
	OneTx pgx.Tx
	Label string // for logs
}

// FileStats is the result of importing one feed.
type FileStats struct {
	Label        string  `json:"feed"`
	Snapshot     string  `json:"snapshot"`
	Verified     bool    `json:"verified"`
	LimitReached bool    `json:"limit_reached,omitempty"`
	ElapsedSec   float64 `json:"elapsed_sec"`
	WriteStats
}

// ImportFeed streams an UNPACKED feed document from r into raw_record (see
// writeRecords for the per-record rules), BatchSize records per
// transaction (or all in OneTx). Unusable entries are counted, not fatal.
// Re-running on the same data writes nothing.
func ImportFeed(ctx context.Context, conn *pgx.Conn, r io.Reader, o ImportOptions) (*FileStats, error) {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.ProgressEvery <= 0 {
		o.ProgressEvery = 20000
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	snap := o.Snapshot.UTC().Truncate(time.Microsecond)
	fs := &FileStats{Label: o.Label, Snapshot: snap.Format(time.RFC3339)}
	start := time.Now()
	var batch []record
	written := func() int { return fs.New + fs.Reverted }
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		var err error
		if o.OneTx != nil {
			err = writeRecords(ctx, o.OneTx, batch, snap, o.DryRun, &fs.WriteStats)
		} else {
			var bst WriteStats
			err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
				bst = WriteStats{}
				return writeRecords(ctx, tx, batch, snap, o.DryRun, &bst)
			})
			if err == nil {
				fs.add(bst)
			}
		}
		batch = batch[:0]
		return err
	}
	errLimit := fmt.Errorf("limit reached")
	next := o.ProgressEvery
	_, _, err := Parse(r, MaxRecordBytes, func(e Entry) error {
		fs.Entries++
		rec, bad := decodeEntry(e)
		if bad != "" {
			fs.bad(bad)
			o.Logger.Warn("nvd entry skipped", "feed", o.Label, "err", bad)
		} else {
			batch = append(batch, rec)
		}
		if len(batch) >= o.BatchSize {
			if err := flush(); err != nil {
				return err
			}
			if o.Limit > 0 && written() >= o.Limit {
				return errLimit
			}
		}
		if fs.Entries >= next {
			o.Logger.Info("nvd import progress", "feed", o.Label, "entries", fs.Entries, "new", fs.New,
				"reverted", fs.Reverted, "unchanged", fs.Unchanged, "stale", fs.Stale, "bad", fs.BadEntries)
			next += o.ProgressEvery
		}
		return nil
	})
	if err == errLimit {
		fs.LimitReached = true
		err = nil
	} else if err == nil {
		err = flush()
	}
	fs.ElapsedSec = time.Since(start).Seconds()
	return fs, err
}
