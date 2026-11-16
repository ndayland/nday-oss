package nvd

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
)

// record is a decoded feed entry ready to store.
type record struct {
	rec  model.RawRecord
	hash string
}

// WriteStats counts raw_record outcomes.
type WriteStats struct {
	// Entries parsed from the feed(s).
	Entries int `json:"entries"`
	// New: a content version stored for the first time. Reverted: an older
	// stored version became the latest again (its fetched_at was bumped,
	// like the pipeline does).
	New      int `json:"raw_new"`
	Reverted int `json:"raw_reverted"`
	// Unchanged: equal to the latest stored version (not touched).
	Unchanged int `json:"raw_unchanged"`
	// Stale: the stored latest version comes from a NEWER feed snapshot
	// (e.g. a baseline file older than the last modified-feed run); kept.
	Stale int `json:"raw_stale"`
	// Duplicates: the same CVE id twice in one feed (first one kept).
	Duplicates int `json:"duplicates"`
	// BadEntries: entry without a "cve" object or a valid CVE id, or whose
	// JSON could not be decoded for hashing. Counted, not stored.
	BadEntries int      `json:"bad_entries"`
	Errors     []string `json:"errors,omitempty"`
}

func (s *WriteStats) bad(msg string) {
	s.BadEntries++
	if len(s.Errors) < 20 {
		s.Errors = append(s.Errors, msg)
	}
}

func (s *WriteStats) add(b WriteStats) {
	s.Entries += b.Entries
	s.New += b.New
	s.Reverted += b.Reverted
	s.Unchanged += b.Unchanged
	s.Stale += b.Stale
	s.Duplicates += b.Duplicates
	s.BadEntries += b.BadEntries
	for _, e := range b.Errors {
		if len(s.Errors) < 20 {
			s.Errors = append(s.Errors, e)
		}
	}
}

// decodeEntry turns a feed entry into a raw record: source nvd, key = the
// CVE id, payload = the "cve" object as delivered, decoded with pyjson so
// the content hash and stored JSON follow the same rules as every other
// source. Returns an error message for an unusable entry.
func decodeEntry(e Entry) (record, string) {
	if len(e.CVE) == 0 || string(e.CVE) == "null" {
		return record{}, fmt.Sprintf("entry %d: no cve object", e.Offset)
	}
	if !model.IsValidCVEID(e.ID) || !asciiCVE(e.ID) {
		return record{}, fmt.Sprintf("entry at byte %d: bad cve.id %q", e.Offset, truncate(e.ID, 40))
	}
	v, err := pyjson.Decode(e.CVE)
	if err != nil {
		return record{}, fmt.Sprintf("%s: %v", e.ID, err)
	}
	if _, ok := v.(*pyjson.Object); !ok {
		return record{}, fmt.Sprintf("%s: cve is not an object", e.ID)
	}
	r := model.RawRecord{Source: Name, SourceKey: e.ID, Payload: v}
	h, err := r.ContentHash()
	if err != nil {
		return record{}, fmt.Sprintf("%s: content hash: %v", e.ID, err)
	}
	return record{rec: r, hash: h}, ""
}

// asciiCVE: the database CHECK on vuln.cve_id is ASCII-only; model's check
// accepts any Unicode digit (a Python quirk kept for parity).
func asciiCVE(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type latest struct {
	hash string
	at   time.Time
}

// writeRecords stores recs (one feed snapshot, all with fetched_at =
// snapshot) inside tx. Rules per key, against the latest stored version
// (fetched_at DESC, id DESC, as everywhere):
//   - same content hash: nothing (not even a fetched_at bump; the pipeline
//     skips unchanged records the same way);
//   - the latest stored version has a later fetched_at (a newer snapshot):
//     nothing (never regress to an older file);
//   - otherwise pipeline.StoreRaw: insert, or bump the fetched_at of an
//     older stored version with this hash (a revert).
//
// Keys are written in sorted order so concurrent writers (baseline import
// and the collector) lock rows in the same order and cannot deadlock.
// dryRun only reads.
func writeRecords(ctx context.Context, tx pgx.Tx, recs []record, snapshot time.Time, dryRun bool, st *WriteStats) error {
	if len(recs) == 0 {
		return nil
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].rec.SourceKey < recs[j].rec.SourceKey })
	keys := make([]string, 0, len(recs))
	uniq := recs[:0:0]
	for i, r := range recs {
		if i > 0 && r.rec.SourceKey == recs[i-1].rec.SourceKey {
			st.Duplicates++
			continue
		}
		keys = append(keys, r.rec.SourceKey)
		uniq = append(uniq, r)
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (source_key) source_key, content_hash, fetched_at
        FROM raw_record WHERE source = $1 AND source_key = ANY($2)
        ORDER BY source_key, fetched_at DESC, id DESC`, Name, keys)
	if err != nil {
		return err
	}
	have := make(map[string]latest, len(keys))
	for rows.Next() {
		var k string
		var l latest
		if err := rows.Scan(&k, &l.hash, &l.at); err != nil {
			rows.Close()
			return err
		}
		have[k] = l
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range uniq {
		l, ok := have[r.rec.SourceKey]
		switch {
		case ok && l.hash == r.hash:
			st.Unchanged++
			continue
		case ok && l.at.After(snapshot):
			st.Stale++
			continue
		}
		if dryRun {
			st.New++ // would be written (new or revert: not distinguished without writing)
			continue
		}
		ins, err := pipeline.StoreRaw(ctx, tx, r.rec, r.hash, snapshot)
		if err != nil {
			return fmt.Errorf("store raw %s: %w", r.rec.SourceKey, err)
		}
		if ins {
			st.New++
		} else {
			st.Reverted++
		}
	}
	return nil
}
