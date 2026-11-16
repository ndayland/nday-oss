package xconfig

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ------------------------------------------------------------------ candidates
//
// Allowlist candidates: X users that stored posts of allowlisted researchers
// quote, reply to or mention (tables x_account_candidate and
// x_account_candidate_ref, migrations/0019_xposts_links_candidates.sql; the
// pipeline writes them from the xposts raw records). An admin dismisses a
// candidate or adds it to x_accounts; these functions only read the list and
// switch the status.

// Candidate statuses.
const (
	CandidatePending   = "pending"
	CandidateDismissed = "dismissed"
)

// ErrCandidateNotFound: no candidate with that user id.
var ErrCandidateNotFound = errors.New("xconfig: candidate not found")

// Candidate is one row of ListCandidates.
type Candidate struct {
	UserID string
	// Handle is upstream text (NULL when the API sent no valid handle):
	// check it with ValidHandle before any display or link.
	Handle      *string
	Status      string
	Referrers   int      // distinct ENABLED allowlisted accounts that referred to it
	Refs        int      // reference rows (any referrer)
	Kinds       []string // distinct kinds: mentioned, quoted, replied_to (sorted)
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	DecidedAt   *time.Time
	SamplePosts []string // up to 3 referring post ids, newest first
}

// ListCandidates returns at most limit candidates with the given status
// ("" = pending), skipping offset, excluding every user id already in
// x_accounts (enabled or not). Order: distinct enabled referrers desc, then
// reference count desc, then last seen desc, then numeric user id.
func ListCandidates(ctx context.Context, db DB, status string, limit, offset int) ([]Candidate, error) {
	if status == "" {
		status = CandidatePending
	}
	if status != CandidatePending && status != CandidateDismissed {
		return nil, fmt.Errorf("xconfig: unknown candidate status %q", status)
	}
	if limit < 0 || offset < 0 {
		return nil, fmt.Errorf("xconfig: negative limit %d or offset %d", limit, offset)
	}
	rows, err := db.Query(ctx, `SELECT c.user_id, c.handle, c.status, c.first_seen_at, c.last_seen_at, c.decided_at,
            count(DISTINCT r.referrer_id) FILTER (WHERE a.enabled) AS referrers,
            count(*) AS refs,
            array_agg(DISTINCT r.kind ORDER BY r.kind) AS kinds,
            (SELECT array_agg(s.post_id ORDER BY s.at DESC, char_length(s.post_id) DESC, s.post_id DESC)
               FROM (SELECT r2.post_id, max(r2.posted_at) AS at FROM x_account_candidate_ref r2
                      WHERE r2.user_id = c.user_id GROUP BY r2.post_id
                      ORDER BY at DESC, char_length(r2.post_id) DESC, r2.post_id DESC LIMIT 3) s) AS samples
        FROM x_account_candidate c
        JOIN x_account_candidate_ref r ON r.user_id = c.user_id
        LEFT JOIN x_accounts a ON a.user_id = r.referrer_id
        WHERE c.status = $1 AND NOT EXISTS (SELECT 1 FROM x_accounts x WHERE x.user_id = c.user_id)
        GROUP BY c.user_id
        ORDER BY referrers DESC, refs DESC, c.last_seen_at DESC, char_length(c.user_id), c.user_id
        LIMIT $2 OFFSET $3`, status, limit, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Candidate, error) {
		var c Candidate
		err := r.Scan(&c.UserID, &c.Handle, &c.Status, &c.FirstSeenAt, &c.LastSeenAt, &c.DecidedAt,
			&c.Referrers, &c.Refs, &c.Kinds, &c.SamplePosts)
		c.FirstSeenAt, c.LastSeenAt = c.FirstSeenAt.UTC(), c.LastSeenAt.UTC()
		if c.DecidedAt != nil {
			t := c.DecidedAt.UTC()
			c.DecidedAt = &t
		}
		return c, err
	})
}

// CountCandidates counts what ListCandidates would list for status ("" =
// pending) without a limit: candidates with at least one reference and no
// row in x_accounts.
func CountCandidates(ctx context.Context, db DB, status string) (int, error) {
	if status == "" {
		status = CandidatePending
	}
	if status != CandidatePending && status != CandidateDismissed {
		return 0, fmt.Errorf("xconfig: unknown candidate status %q", status)
	}
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM x_account_candidate c
        WHERE c.status = $1 AND EXISTS (SELECT 1 FROM x_account_candidate_ref r WHERE r.user_id = c.user_id)
          AND NOT EXISTS (SELECT 1 FROM x_accounts x WHERE x.user_id = c.user_id)`, status).Scan(&n)
	return n, err
}

// GetCandidateForUpdate reads one candidate's handle (nil when the API sent
// no valid one) and status, locking its row until the end of the caller's
// transaction (db must be a pgx.Tx). ErrCandidateNotFound if absent.
func GetCandidateForUpdate(ctx context.Context, db DB, userID string) (handle *string, status string, err error) {
	err = db.QueryRow(ctx, `SELECT handle, status FROM x_account_candidate WHERE user_id = $1 FOR NO KEY UPDATE`, userID).Scan(&handle, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrCandidateNotFound
	}
	return handle, status, err
}

// setCandidateStatus switches one candidate; changed is false when it
// already had that status (decided_at is then left alone).
func setCandidateStatus(ctx context.Context, db DB, userID, status string) (changed bool, err error) {
	var exists bool
	err = db.QueryRow(ctx, `WITH u AS (
            UPDATE x_account_candidate SET status = $2,
                decided_at = CASE WHEN $2 = 'dismissed' THEN now() ELSE NULL END
            WHERE user_id = $1 AND status <> $2 RETURNING 1)
        SELECT EXISTS (SELECT 1 FROM u), EXISTS (SELECT 1 FROM x_account_candidate WHERE user_id = $1)`,
		userID, status).Scan(&changed, &exists)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrCandidateNotFound
	}
	return changed, nil
}

// DismissCandidate marks a candidate dismissed (decided_at = now); the
// pipeline never resets it. ErrCandidateNotFound if absent.
func DismissCandidate(ctx context.Context, db DB, userID string) (changed bool, err error) {
	return setCandidateStatus(ctx, db, userID, CandidateDismissed)
}

// RestoreCandidate puts a dismissed candidate back to pending (decided_at
// cleared). ErrCandidateNotFound if absent.
func RestoreCandidate(ctx context.Context, db DB, userID string) (changed bool, err error) {
	return setCandidateStatus(ctx, db, userID, CandidatePending)
}
