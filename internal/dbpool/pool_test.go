package dbpool_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/testutil"
)

var ctx = context.Background()

func newPool(t *testing.T, opt dbpool.Options) (*dbpool.Pool, *testutil.TestDB, string) {
	t.Helper()
	t.Parallel()
	d := testutil.NewDB(t)
	app := fmt.Sprintf("pooltest_%d", time.Now().UnixNano())
	u := d.URL + "&application_name=" + app
	cfg, err := pgx.ParseConfig(u)
	if err != nil {
		t.Fatal(err)
	}
	if opt.Dial == nil {
		opt.Dial = func(ctx context.Context) (*pgx.Conn, error) { return testutil.Connect(ctx, u) }
	}
	p := dbpool.New(cfg, opt)
	t.Cleanup(p.Close)
	return p, d, app
}

func acquire(t *testing.T, p *dbpool.Pool) *dbpool.Conn {
	t.Helper()
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pid(t *testing.T, c *dbpool.Conn) uint32 {
	t.Helper()
	return c.PgConn().PID()
}

func TestBoundedReuseAndContextWait(t *testing.T) {
	p, _, _ := newPool(t, dbpool.Options{Size: 2})
	a, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(wctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("third acquire: %v", err)
	}
	pa := pid(t, a)
	got := make(chan *dbpool.Conn)
	go func() {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Error(err)
		}
		got <- c
	}()
	time.Sleep(50 * time.Millisecond)
	a.Release()
	a.Release() // idempotent
	c := <-got
	if pid(t, c) != pa {
		t.Error("idle connection not reused")
	}
	c.Release()
	b.Release()
	if s := p.Stats(); s.Dials != 2 || s.InUse != 0 || s.Idle != 2 {
		t.Errorf("stats %+v", s)
	}
}

func TestBrokenConnectionIsDiscardedAndReplaced(t *testing.T) {
	p, d, _ := newPool(t, dbpool.Options{Size: 1})
	c := acquire(t, p)
	old := pid(t, c)
	if _, err := d.Conn.Exec(ctx, "SELECT pg_terminate_backend($1)", old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := c.Exec(ctx, "SELECT 1"); err == nil {
		t.Fatal("query on terminated backend succeeded")
	}
	c.Release()
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	if pid(t, c) == old {
		t.Error("broken connection reused")
	}
	var one int
	if err := c.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal(err)
	}
	if s := p.Stats(); s.Discarded != 1 || s.Dials != 2 {
		t.Errorf("stats %+v", s)
	}
}

func TestIdleConnectionKilledIsHealthChecked(t *testing.T) {
	p, d, _ := newPool(t, dbpool.Options{Size: 1, HealthCheckAfter: time.Nanosecond})
	c := acquire(t, p)
	old := pid(t, c)
	c.Release()
	if _, err := d.Conn.Exec(ctx, "SELECT pg_terminate_backend($1)", old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	err := p.WithConn(ctx, func(c *pgx.Conn) error {
		if c.PgConn().PID() == old {
			return errors.New("dead connection handed out")
		}
		_, err := c.Exec(ctx, "SELECT 1")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenTransactionIsDiscarded(t *testing.T) {
	p, _, _ := newPool(t, dbpool.Options{Size: 1})
	c := acquire(t, p)
	old := pid(t, c)
	if _, err := c.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	c.Release()
	c = acquire(t, p)
	defer c.Release()
	if pid(t, c) == old || c.PgConn().TxStatus() != 'I' {
		t.Error("connection left in a transaction was reused")
	}
}

func TestConcurrentUseNeverExceedsSize(t *testing.T) {
	const size = 3
	p, d, app := newPool(t, dbpool.Options{Size: size})
	var cur, peak, peakBackends int32
	var wg sync.WaitGroup
	for g := 0; g < 30; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				err := p.WithConn(ctx, func(c *pgx.Conn) error {
					n := atomic.AddInt32(&cur, 1)
					for {
						old := atomic.LoadInt32(&peak)
						if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
							break
						}
					}
					defer atomic.AddInt32(&cur, -1)
					_, err := c.Exec(ctx, "SELECT pg_sleep(0.001)")
					return err
				})
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-done:
				return
			default:
			}
			var n int32
			_ = d.Conn.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1", app).Scan(&n)
			if n > atomic.LoadInt32(&peakBackends) {
				atomic.StoreInt32(&peakBackends, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	wg.Wait()
	close(done)
	<-monitorDone
	if peak > size || peakBackends > size {
		t.Errorf("peak in use %d, backends %d > %d", peak, peakBackends, size)
	}
	if s := p.Stats(); s.Dials > size || s.Acquires != 300 {
		t.Errorf("stats %+v", s)
	}
}

func TestClose(t *testing.T) {
	p, _, _ := newPool(t, dbpool.Options{Size: 2})
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idle, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idle.Release()
	p.Close()
	if _, err := p.Acquire(ctx); !errors.Is(err, dbpool.ErrClosed) {
		t.Errorf("acquire after close: %v", err)
	}
	c.Release()
	if !c.IsClosed() || !idle.IsClosed() {
		t.Error("connections not closed")
	}
}

func TestDialFailureFreesSlot(t *testing.T) {
	t.Parallel()
	calls := 0
	p := dbpool.New(nil, dbpool.Options{Size: 1, Dial: func(context.Context) (*pgx.Conn, error) {
		calls++
		return nil, errors.New("down")
	}})
	for i := 0; i < 3; i++ {
		if _, err := p.Acquire(ctx); err == nil || err.Error() != "down" {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Errorf("calls %d", calls)
	}
}
