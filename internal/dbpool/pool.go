// Package dbpool is a small fixed-size pool of *pgx.Conn (pgxpool cannot be
// used: its dependency is not available to this build).
//
// Behaviour:
//   - at most Size connections exist at any time (in use + idle);
//   - Acquire waits for a free slot and honours ctx (cancel/deadline);
//   - connections are dialled lazily and reused LIFO;
//   - a connection that is closed, busy, or left inside a transaction when
//     released is closed and discarded; the slot is freed and the next
//     Acquire dials a new one ("discard and reconnect");
//   - an idle connection unused for longer than HealthCheckAfter is pinged
//     before being handed out; one older than MaxLifetime is replaced;
//   - Close closes idle connections at once and in-use ones on release.
package dbpool

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrClosed is returned by Acquire after Close.
var ErrClosed = errors.New("dbpool: pool closed")

// Options configure a Pool.
type Options struct {
	// Size is the maximum number of connections (default 4).
	Size int
	// HealthCheckAfter: ping idle connections older than this before reuse
	// (default 30s; negative disables).
	HealthCheckAfter time.Duration
	// MaxLifetime: close connections older than this instead of reusing them
	// (default 30m; negative disables).
	MaxLifetime time.Duration
	// Dial overrides how connections are opened (tests).
	Dial func(ctx context.Context) (*pgx.Conn, error)
}

type idleConn struct {
	c       *pgx.Conn
	created time.Time
	usedAt  time.Time
}

// Pool is a bounded set of connections. Safe for concurrent use.
type Pool struct {
	opt   Options
	slots chan struct{} // one token per connection slot in use

	mu     sync.Mutex
	idle   []idleConn
	closed bool
	stats  Stats
}

// Stats are cumulative counters.
type Stats struct {
	Dials     int64 // connections opened
	Discarded int64 // connections closed because they were broken/busy/in a tx/too old
	Acquires  int64
	Idle      int // currently idle
	InUse     int // currently acquired
}

// New creates a pool; no connection is opened until the first Acquire.
func New(cfg *pgx.ConnConfig, opt Options) *Pool {
	if opt.Size <= 0 {
		opt.Size = 4
	}
	if opt.HealthCheckAfter == 0 {
		opt.HealthCheckAfter = 30 * time.Second
	}
	if opt.MaxLifetime == 0 {
		opt.MaxLifetime = 30 * time.Minute
	}
	if opt.Dial == nil {
		opt.Dial = func(ctx context.Context) (*pgx.Conn, error) { return pgx.ConnectConfig(ctx, cfg.Copy()) }
	}
	return &Pool{opt: opt, slots: make(chan struct{}, opt.Size)}
}

// Conn is an acquired connection. Call Release exactly once.
type Conn struct {
	*pgx.Conn
	p       *Pool
	created time.Time
	once    sync.Once
}

// Acquire returns a connection, waiting for a free slot if all are in use.
func (p *Pool) Acquire(ctx context.Context) (*Conn, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p.mu.Lock()
	p.stats.Acquires++
	p.mu.Unlock()
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			<-p.slots
			return nil, ErrClosed
		}
		var ic idleConn
		ok := false
		if n := len(p.idle); n > 0 {
			ic, ok = p.idle[n-1], true
			p.idle = p.idle[:n-1]
		}
		p.mu.Unlock()
		if !ok {
			break
		}
		now := time.Now()
		if ic.c.IsClosed() || (p.opt.MaxLifetime > 0 && now.Sub(ic.created) > p.opt.MaxLifetime) {
			p.discard(ic.c)
			continue
		}
		if p.opt.HealthCheckAfter >= 0 && now.Sub(ic.usedAt) > p.opt.HealthCheckAfter {
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := ic.c.Ping(pctx)
			cancel()
			if err != nil {
				p.discard(ic.c)
				if ctx.Err() != nil {
					<-p.slots
					return nil, ctx.Err()
				}
				continue
			}
		}
		return &Conn{Conn: ic.c, p: p, created: ic.created}, nil
	}
	c, err := p.opt.Dial(ctx)
	if err != nil {
		<-p.slots
		return nil, err
	}
	p.mu.Lock()
	p.stats.Dials++
	p.mu.Unlock()
	return &Conn{Conn: c, p: p, created: time.Now()}, nil
}

func (p *Pool) discard(c *pgx.Conn) {
	p.mu.Lock()
	p.stats.Discarded++
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// Release returns the connection to the pool, or closes it if it is not
// reusable. Calling Release more than once is a no-op.
func (c *Conn) Release() {
	c.once.Do(func() {
		p := c.p
		reusable := !c.Conn.IsClosed() && !c.Conn.PgConn().IsBusy() && c.Conn.PgConn().TxStatus() == 'I'
		p.mu.Lock()
		closed := p.closed
		if reusable && !closed {
			p.idle = append(p.idle, idleConn{c: c.Conn, created: c.created, usedAt: time.Now()})
			p.mu.Unlock()
		} else {
			p.mu.Unlock()
			if reusable { // pool closed: plain close, not a discard
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = c.Conn.Close(ctx)
				cancel()
			} else {
				p.discard(c.Conn)
			}
		}
		<-p.slots
	})
}

// WithConn acquires a connection, runs fn and releases it.
func (p *Pool) WithConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	c, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	return fn(c.Conn)
}

// Stats returns a snapshot of the counters.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	s.Idle = len(p.idle)
	s.InUse = len(p.slots) // slots taken (acquired or being dialled)
	return s
}

// Size is the configured maximum number of connections.
func (p *Pool) Size() int { return p.opt.Size }

// Close closes idle connections and makes Acquire fail; connections in use
// are closed when released.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, ic := range idle {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = ic.c.Close(ctx)
		cancel()
	}
}
