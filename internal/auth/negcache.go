package auth

import (
	"container/list"
	"sync"
	"time"
)

// deadTokens remembers session token hashes that were looked up and not
// found, so a revoked
// or expired but correctly tagged cookie replayed in a loop costs neither a
// lookup slot nor a query.
//
// Why an entry can never become wrong: a session row is only ever written
// by Store.CreateSession (INSERT of a fresh random 256-bit token, before the
// cookie is sent) and by Store.LoadSession (UPDATE of last_seen_at, done only
// after the row passed both the absolute expiry and the idle check).
// expires_at never changes and a deleted token is never inserted again, so
// once LoadSession reports "not found" (missing, past expires_at, or idle
// longer than SessionIdle) the same token can never load again while the
// process runs with the same SessionIdle. The cache is in memory, so a
// restart with another SessionIdle starts empty.
type deadTokens struct {
	mu  sync.Mutex
	max int
	ttl time.Duration
	m   map[string]*list.Element
	lru *list.List // front = newest
}

type deadEntry struct {
	key string
	exp time.Time
}

// Bounds of the dead-token cache.
const (
	deadTokensMax = 50000
	deadTokensTTL = 10 * time.Minute
)

func newDeadTokens(max int, ttl time.Duration) *deadTokens {
	return &deadTokens{max: max, ttl: ttl, m: map[string]*list.Element{}, lru: list.New()}
}

func (d *deadTokens) has(hash []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.m[string(hash)]
	if !ok {
		return false
	}
	if time.Now().After(e.Value.(*deadEntry).exp) {
		d.lru.Remove(e)
		delete(d.m, string(hash))
		return false
	}
	return true
}

func (d *deadTokens) add(hash []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := string(hash)
	if e, ok := d.m[k]; ok {
		e.Value.(*deadEntry).exp = time.Now().Add(d.ttl)
		d.lru.MoveToFront(e)
		return
	}
	d.m[k] = d.lru.PushFront(&deadEntry{key: k, exp: time.Now().Add(d.ttl)})
	for d.lru.Len() > d.max {
		old := d.lru.Back()
		d.lru.Remove(old)
		delete(d.m, old.Value.(*deadEntry).key)
	}
}

func (d *deadTokens) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lru.Len()
}
