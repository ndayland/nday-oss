package admin

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/state"
)

// stateRefreshTimeout bounds one background refresh of vuln_state_mat.
const stateRefreshTimeout = 5 * time.Minute

// stateRefresher runs at most one background refresh at a time per
// process; a request that comes while one runs makes it run once more.
type stateRefresher struct {
	mu      sync.Mutex
	running bool
	again   bool
	wg      sync.WaitGroup
}

// refreshStateSoon refreshes vuln_state_mat in the background after a
// decision that changed github PoC events (migration 0032), so the lists
// agree with the vulnerability page without the request waiting for a
// refresh of several seconds. It uses state.Refresh without waiting: when
// another process holds the refresh lock, that process takes the request
// over (state's requested/refreshed protocol). Errors are logged; the next
// collector run refreshes anyway.
func (s *Service) refreshStateSoon() {
	r := &s.refresher
	r.mu.Lock()
	if r.running {
		r.again = true
		r.mu.Unlock()
		return
	}
	r.running = true
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), stateRefreshTimeout)
			err := s.o.AuthDB.WithConn(ctx, func(c *pgx.Conn) error {
				_, err := state.Refresh(ctx, c, state.RefreshOptions{Logger: s.log})
				return err
			})
			cancel()
			if err != nil {
				s.log.Warn("admin: state refresh after a repository decision failed", "err", err)
			}
			r.mu.Lock()
			if !r.again {
				r.running = false
				r.mu.Unlock()
				return
			}
			r.again = false
			r.mu.Unlock()
		}
	}()
}

// WaitStateRefresh waits for a background refresh started by a decision
// (tests).
func (s *Service) WaitStateRefresh() { s.refresher.wg.Wait() }
