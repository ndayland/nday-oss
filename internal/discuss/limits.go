package discuss

import (
	"time"

	"nday.land/nday/internal/auth"
)

// limState is the limits in force and their token buckets. It is
// immutable once stored (SetLimits swaps the pointer); a request takes it
// once where it uses several parts of it.
type limState struct {
	lim Limits

	readRL, guestRL, addrRL, postRL, newPostRL, editRL, modRL, deleteRL, reportRL *auth.RateLimiter
}

func (s *Service) cur() *limState { return s.lims.Load() }

// newLimState builds the limiters of lim. A limiter of prev whose burst and
// interval are unchanged is kept (with every client's bucket); a changed
// one starts empty (every client gets a full burst under the new values).
func (s *Service) newLimState(lim Limits, prev *limState) *limState {
	st := &limState{lim: lim}
	mk := func(old *auth.RateLimiter, burst int, every time.Duration) *auth.RateLimiter {
		if old != nil && old.Burst == float64(burst) && old.Every == every {
			return old
		}
		l := auth.NewRateLimiter(burst, every)
		l.Now = s.now
		return l
	}
	var p limState
	if prev != nil {
		p = *prev
	}
	st.readRL = mk(p.readRL, lim.ReadBurst, lim.ReadEvery)
	st.guestRL = mk(p.guestRL, lim.GuestReadBurst, lim.GuestReadEvery)
	st.addrRL = mk(p.addrRL, lim.AddrBurst, lim.AddrEvery)
	st.postRL = mk(p.postRL, lim.PostBurst, lim.PostEvery)
	st.newPostRL = mk(p.newPostRL, lim.NewPostBurst, lim.NewPostEvery)
	st.editRL = mk(p.editRL, lim.EditBurst, lim.EditEvery)
	st.modRL = mk(p.modRL, lim.ModBurst, lim.ModEvery)
	st.deleteRL = mk(p.deleteRL, lim.DeleteBurst, lim.DeleteEvery)
	st.reportRL = mk(p.reportRL, lim.ReportBurst, lim.ReportEvery)
	return st
}

// SetLimits replaces the limits of the running service (validated values,
// e.g. LimitsFromEnv): new requests use them at once. The token buckets of
// a limiter whose burst and interval did not change are kept; the daily
// caps, the new-account rule and the duplicate window are read per request
// and apply at once. Safe for concurrent use.
func (s *Service) SetLimits(l Limits) {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	s.lims.Store(s.newLimState(l, s.lims.Load()))
}
