package discuss_test

import (
	"sync"
	"testing"
	"time"
)

// TestSetLimits: new limits apply to the next request; a limiter whose
// burst and interval did not change keeps every client's bucket.
func TestSetLimits(t *testing.T) {
	l := testLimits()
	l.ReadBurst, l.ReadEvery = 3, time.Second
	h := newHarness(t, hopt{terms: terms, limits: l})
	ada := h.member("ada")
	h.establish(ada.id)
	c := ada.create(cveA, "v0", nil)
	for i := 1; i <= 2; i++ { // EditBurst 2: used up
		resp, body := ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"v`+string(rune('0'+i))+`"}`)
		expect(t, "edit", resp, body, 200, "")
	}
	anon := h.browser()
	for i := 0; i < 3; i++ {
		anon.stream(cveA, "")
	}
	resp, body := anon.do("GET", "/api/discuss/"+cveA, "")
	expect(t, "read limit before", resp, body, 429, "rate_limited")

	n := *l
	n.ReadBurst = 5
	h.dsvc.SetLimits(n)
	if got := h.dsvc.Limits(); got != n {
		t.Fatalf("Limits() %+v", got)
	}
	for i := 0; i < 5; i++ {
		anon.stream(cveA, "")
	}
	resp, body = anon.do("GET", "/api/discuss/"+cveA, "")
	expect(t, "read limit after (burst 5)", resp, body, 429, "rate_limited")
	// the edit limiter did not change: ada's bucket is still empty
	resp, body = ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"v3"}`)
	expect(t, "edit bucket kept", resp, body, 429, "rate_limited")

	// a daily cap applies at once too
	n.PostDaily = 1
	h.dsvc.SetLimits(n)
	h.clock.Advance(time.Hour)
	resp, body = ada.tryCreate(cveA, "second today", nil)
	expect(t, "lower daily cap", resp, body, 429, "daily_limit")
}

// TestSetLimitsConcurrent: SetLimits while requests run (run with -race).
func TestSetLimitsConcurrent(t *testing.T) {
	l := testLimits()
	h := newHarness(t, hopt{terms: terms, limits: l})
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n := *l
			n.ReadBurst = 1000 + i%2
			h.dsvc.SetLimits(n)
			_ = h.dsvc.Limits()
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := h.browser()
			for i := 0; i < 30; i++ {
				if resp, _ := b.do("GET", "/api/discuss/"+cveA, ""); resp.StatusCode != 200 {
					t.Errorf("read %d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-done
}
