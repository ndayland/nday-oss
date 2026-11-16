package web

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

// Cache is a small in-process TTL cache with request coalescing
// (singleflight): concurrent Get calls for the same key run fn once and
// share its result; results stay fresh for ttl. Errors are never cached.
// Entries are bounded by MaxEntries (expired entries are evicted first,
// then arbitrary ones). Safe for concurrent use.
type Cache struct {
	MaxEntries int
	// Timeout bounds one fn run; fn runs detached from the caller's
	// cancellation (a client hanging up must not fail the other waiters).
	Timeout time.Duration
	now     func() time.Time

	mu       sync.Mutex
	entries  map[string]cacheEntry
	inflight map[string]*call
	hits     int64
	misses   int64
}

type cacheEntry struct {
	v       any
	expires time.Time
}

type call struct {
	done chan struct{}
	v    any
	err  error
}

// NewCache returns a cache holding at most maxEntries values.
func NewCache(maxEntries int, timeout time.Duration) *Cache {
	return &Cache{MaxEntries: maxEntries, Timeout: timeout, now: time.Now,
		entries: map[string]cacheEntry{}, inflight: map[string]*call{}}
}

// Get returns the cached value for key, or runs fn (once for all concurrent
// callers) and caches its result for ttl. hit reports a cache hit (a
// coalesced wait counts as a hit).
func (c *Cache) Get(ctx context.Context, key string, ttl time.Duration, fn func(ctx context.Context) (any, error)) (v any, hit bool, err error) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Before(e.expires) {
		c.hits++
		c.mu.Unlock()
		return e.v, true, nil
	}
	if cl, ok := c.inflight[key]; ok {
		c.hits++
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.v, true, cl.err
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[key] = cl
	c.misses++
	c.mu.Unlock()

	go func() {
		defer close(cl.done)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.Timeout)
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				cl.err = &panicError{v: p, stack: debug.Stack()}
			}
			c.mu.Lock()
			delete(c.inflight, key)
			if cl.err == nil && ttl > 0 {
				c.evictLocked()
				c.entries[key] = cacheEntry{v: cl.v, expires: c.now().Add(ttl)}
			}
			c.mu.Unlock()
		}()
		cl.v, cl.err = fn(rctx)
	}()
	select {
	case <-cl.done:
		return cl.v, false, cl.err
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

func (c *Cache) evictLocked() {
	if len(c.entries) < c.MaxEntries {
		return
	}
	now := c.now()
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) < c.MaxEntries {
			break
		}
		delete(c.entries, k)
	}
}

// Stats returns hit/miss counters and the current size.
func (c *Cache) Stats() (hits, misses int64, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, len(c.entries)
}

type panicError struct {
	v     any
	stack []byte
}

func (p *panicError) Error() string {
	return fmt.Sprintf("panic in cached computation: %v\n%s", p.v, p.stack)
}
