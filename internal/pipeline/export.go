package pipeline

import (
	"context"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
)

// Exported entry points for bulk importers (internal/cveimport) that must
// write rows exactly like RunCollector does but manage their own
// transactions. They are thin wrappers: the SQL and semantics are those of
// the unexported functions used by RunCollector.

// StoreRaw is the raw_record write of RunCollector: insert a new content
// version (hash = rec.ContentHash()) or, if (source, source_key, hash) is
// already stored, bump its fetched_at. Returns true if a row was inserted.
func StoreRaw(ctx context.Context, db Execer, rec model.RawRecord, hash string, fetchedAt time.Time) (bool, error) {
	return storeRaw(ctx, db, rec, hash, fetchedAt)
}

// NormalizeOne runs c.Normalize plus the constructor-time validation, like
// RunCollector: (norm, nil, nil) on success; (nil, nerr, nil) for a
// collector.NormalizeError (RunCollector counts it and continues); (nil,
// nil, err) for any other failure (RunCollector aborts the whole run).
func NormalizeOne(c collector.Collector, rec model.RawRecord) (*model.Normalized, *collector.NormalizeError, error) {
	return normalizeOne(c, rec)
}

// SaveState is RunCollector's collector_state write, for collectors that
// stream their records instead of returning a FetchResult (nvd): on success
// it stores cursor and sets last_success_at = runAt; on failure
// (success=false) it keeps the previous cursor and last_success_at.
func SaveState(ctx context.Context, db Execer, source string, runAt time.Time, status string,
	errText *string, cursor any, success bool) error {
	return saveState(ctx, db, source, runAt, status, errText, cursor, success)
}

// Execer is satisfied by *pgx.Conn and pgx.Tx (the argument type of
// ApplyNormalized and StoreRaw).
type Execer = execer
