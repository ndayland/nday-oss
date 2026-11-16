package state

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// refreshLockClass is the high half of the session advisory lock that
// serialises refreshes; the low half is the oid of vuln_state_mat, so every
// database/schema (e.g. each isolated test schema) has its own lock.
const refreshLockClass int64 = 0x6E647374 << 32 // "ndst"

const lockKeySQL = `($1::bigint | 'vuln_state_mat'::regclass::oid::bigint)`

// RefreshOptions for Refresh.
type RefreshOptions struct {
	// Wait blocks until the refresh lock is free and then refreshes (unless a
	// refresh that started after this call's request already completed).
	// Without Wait (the pipeline's mode) the call returns immediately when
	// another session holds the lock: that session re-checks the request
	// counter after its own refresh and refreshes again, so the request is
	// never lost and runs never queue up behind each other.
	Wait bool
	// MaxRounds bounds the refreshes one call performs (default 4). Requests
	// still pending afterwards are picked up by the next Refresh call.
	MaxRounds int
	Logger    *slog.Logger
}

// RefreshResult reports what one Refresh call did.
type RefreshResult struct {
	// Refreshes is the number of REFRESH statements this call executed.
	Refreshes int
	// Deferred: the lock was held by another session, which takes over the
	// pending request (see RefreshOptions.Wait).
	Deferred bool
	// Covered: a refresh that started after this request had already
	// completed, nothing to do.
	Covered bool
	// Pending: MaxRounds reached while newer requests kept arriving.
	Pending bool
	// Elapsed is the time spent in REFRESH statements.
	Elapsed time.Duration
}

// Refresh brings vuln_state_mat up to date with every write committed
// before the call. conn must not be inside a transaction.
//
// Protocol (vuln_state_refresh holds one row: requested, refreshed_seq):
//  1. bump requested (autocommit) — after the caller's data commit;
//  2. take the session advisory lock (try, or wait with Wait);
//  3. read requested R and refreshed_seq F; if F >= R every request is
//     already covered: unlock and stop;
//  4. REFRESH MATERIALIZED VIEW CONCURRENTLY (snapshot taken after reading
//     R, so every write whose bump is <= R is included), then set
//     refreshed_seq = R and unlock;
//  5. loop to 2 (bounded by MaxRounds); a failed try-lock there means the
//     new holder will do step 3 itself.
//
// Readers are never blocked (CONCURRENTLY takes only an EXCLUSIVE lock that
// conflicts with other refreshes, which the advisory lock already
// serialises), so concurrent collector runs neither deadlock nor pile up:
// at most one session refreshes, the others return in milliseconds.
func Refresh(ctx context.Context, conn *pgx.Conn, opt RefreshOptions) (res RefreshResult, err error) {
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	rounds := opt.MaxRounds
	if rounds <= 0 {
		rounds = 4
	}
	var mine int64
	if err := conn.QueryRow(ctx,
		`UPDATE vuln_state_refresh SET requested = requested + 1 WHERE id = 1 RETURNING requested`).Scan(&mine); err != nil {
		return res, fmt.Errorf("request state refresh: %w", err)
	}
	for round := 0; ; round++ {
		if opt.Wait && round == 0 {
			if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock`+lockKeySQL, refreshLockClass); err != nil {
				return res, fmt.Errorf("refresh lock: %w", err)
			}
		} else {
			var got bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock`+lockKeySQL, refreshLockClass).Scan(&got); err != nil {
				return res, fmt.Errorf("refresh lock: %w", err)
			}
			if !got {
				res.Deferred = true
				return res, nil
			}
		}
		done, err := refreshLocked(ctx, conn, &res, res.Refreshes < rounds)
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock`+lockKeySQL, refreshLockClass); uerr != nil && err == nil {
			err = fmt.Errorf("refresh unlock: %w", uerr)
		}
		if err != nil {
			return res, err
		}
		if done {
			if res.Refreshes == 0 && !res.Pending {
				res.Covered = true
			}
			if res.Pending {
				log.Warn("vuln_state_mat refresh: requests still pending after max rounds; the next refresh picks them up",
					"rounds", rounds)
			}
			return res, nil
		}
	}
}

// refreshLocked runs steps 3-4 with the advisory lock held. done reports that
// no request was pending, or that one was pending but may is false (then
// res.Pending is set).
func refreshLocked(ctx context.Context, conn *pgx.Conn, res *RefreshResult, may bool) (done bool, err error) {
	var requested, refreshed int64
	if err := conn.QueryRow(ctx, `SELECT requested, refreshed_seq FROM vuln_state_refresh WHERE id = 1`).
		Scan(&requested, &refreshed); err != nil {
		return false, err
	}
	if refreshed >= requested {
		return true, nil
	}
	if !may {
		res.Pending = true
		return true, nil
	}
	start := time.Now()
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// The view's hash aggregates spill to disk with the default 4MB.
		if _, err := tx.Exec(ctx, `SET LOCAL work_mem = '64MB'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `REFRESH MATERIALIZED VIEW CONCURRENTLY vuln_state_mat`)
		return err
	})
	elapsed := time.Since(start)
	if err != nil {
		msg := err.Error()
		if utf8.RuneCountInString(msg) > 1000 {
			msg = string([]rune(msg)[:1000])
		}
		_, _ = conn.Exec(context.WithoutCancel(ctx), `UPDATE vuln_state_refresh
            SET last_error = $1, last_error_at = clock_timestamp() WHERE id = 1`, msg)
		return false, fmt.Errorf("refresh vuln_state_mat: %w", err)
	}
	res.Refreshes++
	res.Elapsed += elapsed
	if _, err := conn.Exec(ctx, `UPDATE vuln_state_refresh
        SET refreshed_seq = GREATEST(refreshed_seq, $1), refreshed_at = clock_timestamp(),
            duration_ms = $2, last_error = NULL, last_error_at = NULL
        WHERE id = 1`, requested, elapsed.Milliseconds()); err != nil {
		return false, err
	}
	return false, nil
}
