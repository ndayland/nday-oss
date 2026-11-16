package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetryTooManyClientsRetriesThenSucceeds(t *testing.T) {
	calls := 0
	want := &pgx.Conn{}
	c, err := retryTooManyClients(context.Background(), func() (*pgx.Conn, error) {
		calls++
		if calls < 3 {
			return nil, &pgconn.PgError{Code: "53300"}
		}
		return want, nil
	})
	if err != nil || c != want || calls != 3 {
		t.Fatalf("c=%v err=%v calls=%d", c, err, calls)
	}
}

func TestRetryTooManyClientsOtherErrorReturnsAtOnce(t *testing.T) {
	calls := 0
	boom := &pgconn.PgError{Code: "28P01"}
	_, err := retryTooManyClients(context.Background(), func() (*pgx.Conn, error) {
		calls++
		return nil, boom
	})
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestRetryTooManyClientsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()
	_, err := retryTooManyClients(ctx, func() (*pgx.Conn, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil, &pgconn.PgError{Code: "53300"}
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "53300" {
		t.Fatalf("err=%v", err)
	}
	if calls != 2 || time.Since(start) > 5*time.Second {
		t.Fatalf("calls=%d elapsed=%v", calls, time.Since(start))
	}
}
