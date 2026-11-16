package jose_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nday.land/nday/internal/auth/jose"
)

// After a failed refresh the
// cached keys keep being served and the JWKS is not fetched again before the
// back-off (RefetchInterval) has passed; concurrent callers share one fetch
// and nobody waits on a lock held across the network call.
func TestJWKSFailureBackoff(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	var fail atomic.Bool
	var hits atomic.Int64
	var delay atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(time.Duration(delay.Load()))
		if fail.Load() {
			http.Error(w, "down", 503)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jose.JWK(&k.PublicKey, "k1")}})
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	j := &jose.JWKS{URL: srv.URL, Client: srv.Client(), Now: clock, RefetchInterval: 30 * time.Second}
	ctx := context.Background()
	if _, err := j.Key(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	advance(10 * time.Minute) // keys expired
	fail.Store(true)
	before := hits.Load()
	for i := 0; i < 20; i++ {
		advance(time.Second)
		if _, err := j.Key(ctx, "k1"); err != nil {
			t.Fatalf("stale key not served: %v", err)
		}
	}
	if n := hits.Load() - before; n != 1 {
		t.Errorf("20 Key() calls over 20 s after a failed refresh: %d fetches, want 1", n)
	}
	advance(15 * time.Second) // back-off over
	j.Key(ctx, "k1")
	if n := hits.Load() - before; n != 2 {
		t.Errorf("after the back-off: %d fetches, want 2", n)
	}
	// slow, failing provider: concurrent callers share one fetch
	advance(31 * time.Second)
	delay.Store(int64(300 * time.Millisecond))
	before = hits.Load()
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); advance(time.Second); _, _ = j.Key(ctx, "k1") }()
	}
	wg.Wait()
	if n := hits.Load() - before; n != 1 {
		t.Errorf("8 concurrent Key() calls: %d fetches, want 1", n)
	}
	if d := time.Since(start); d > 550*time.Millisecond {
		t.Errorf("8 concurrent Key() calls took %v (serialised behind the fetch?)", d)
	}
	// the provider recovers: refreshed after the back-off
	fail.Store(false)
	delay.Store(0)
	advance(31 * time.Second)
	before = hits.Load()
	for i := 0; i < 5; i++ {
		j.Key(ctx, "k1")
	}
	if n := hits.Load() - before; n != 1 {
		t.Errorf("after recovery: %d fetches, want 1", n)
	}
}
