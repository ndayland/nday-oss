package auth

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// ClientAddr is the client address used for rate limiting:
// CF-Connecting-IP when it parses as an IP address, else the socket peer
// address. CF-Connecting-IP is only as trustworthy as the guarantee that
// nobody but Cloudflare can reach the origin (firewall + Authenticated
// Origin Pulls, see docs/auth.md §1.1); serve logs a warning when no origin
// client CA is configured. IPv6 addresses are reduced to their /64, so one
// host cannot rotate through its subnet to escape the limit (and to their
// /48 while a limiter is under pressure, see RateLimiter).
func ClientAddr(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" && len(v) <= 45 {
		if a, err := netip.ParseAddr(v); err == nil {
			return bucketKey(a)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return bucketKey(a)
	}
	return "unknown"
}

func bucketKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// coarseKey maps an IPv6 /64 key to its /48 (other keys unchanged).
func coarseKey(key string) string {
	p, err := netip.ParsePrefix(key)
	if err != nil || !p.Addr().Is6() || p.Bits() != 64 {
		return key
	}
	q, _ := p.Addr().Prefix(48)
	return q.String()
}

// RateLimiter is a token bucket per key: Burst requests at once, refilled
// at one request per Every.
//
// Memory is bounded by MaxKeys buckets. When the table is full, the least
// recently used bucket is evicted for a new key (O(1)), so a flood of
// distinct keys can never lock new clients out; idle buckets are dropped by
// a sweep that runs at most once per SweepEvery and only walks the idle tail
// of the LRU list. IPv6 /64 keys are counted per /48 while in coarse mode,
// so one /48 cannot occupy the table. Coarse mode has hysteresis: it starts when
// the table is at least half full and ends
// only when it is under a quarter full AND at least CoarseHold (default 10
// minutes) after it started, so it cannot flap and hand out a fresh /64
// burst at every switch.
type RateLimiter struct {
	Burst      float64
	Every      time.Duration
	MaxKeys    int
	SweepEvery time.Duration // default 1 minute
	CoarseHold time.Duration // default 10 minutes
	Now        func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	head      *bucket // most recently used
	tail      *bucket // least recently used
	lastSweep time.Time
	coarse    bool
	coarseAt  time.Time
}

type bucket struct {
	key        string
	tokens     float64
	at         time.Time
	prev, next *bucket
}

// NewRateLimiter returns a limiter allowing burst requests, then one per every.
func NewRateLimiter(burst int, every time.Duration) *RateLimiter {
	return &RateLimiter{Burst: float64(burst), Every: every, MaxKeys: 100000, buckets: map[string]*bucket{}}
}

// Len is the number of buckets held.
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Allow takes one token for key; when none is left it returns false and
// the time until the next token.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	every := l.SweepEvery
	if every <= 0 {
		every = time.Minute
	}
	if now.Sub(l.lastSweep) >= every {
		l.sweep(now)
	}
	maxKeys := max(l.MaxKeys, 1)
	hold := l.CoarseHold
	if hold <= 0 {
		hold = 10 * time.Minute
	}
	switch n := len(l.buckets); {
	case !l.coarse && n >= maxKeys/2:
		l.coarse, l.coarseAt = true, now
	case l.coarse && n < maxKeys/4 && now.Sub(l.coarseAt) >= hold:
		l.coarse = false
	}
	if l.coarse {
		key = coarseKey(key)
	}
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxKeys {
			l.evict(l.tail)
		}
		b = &bucket{key: key, tokens: l.Burst, at: now}
		l.buckets[key] = b
	} else {
		l.unlink(b)
	}
	l.pushFront(b)
	b.tokens = min(l.Burst, b.tokens+float64(now.Sub(b.at))/float64(l.Every))
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(l.Every))
}

// sweep drops buckets that have been idle long enough to be full again.
// The list is ordered by last use, so it stops at the first active bucket.
func (l *RateLimiter) sweep(now time.Time) {
	l.lastSweep = now
	full := time.Duration(l.Burst * float64(l.Every))
	for l.tail != nil && now.Sub(l.tail.at) >= full {
		l.evict(l.tail)
	}
}

func (l *RateLimiter) evict(b *bucket) {
	if b == nil {
		return
	}
	l.unlink(b)
	delete(l.buckets, b.key)
}

func (l *RateLimiter) unlink(b *bucket) {
	if b.prev != nil {
		b.prev.next = b.next
	} else {
		l.head = b.next
	}
	if b.next != nil {
		b.next.prev = b.prev
	} else {
		l.tail = b.prev
	}
	b.prev, b.next = nil, nil
}

func (l *RateLimiter) pushFront(b *bucket) {
	b.next = l.head
	if l.head != nil {
		l.head.prev = b
	}
	l.head = b
	if l.tail == nil {
		l.tail = b
	}
}
