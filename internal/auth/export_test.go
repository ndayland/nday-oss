package auth

// Test hooks for package auth_test.

// MintAPITokenForTest returns a token this service would accept by its tag
// but that is not stored (an "unknown" token that reaches the lookup).
func (s *Service) MintAPITokenForTest() string {
	t, _, _ := s.newAPIToken()
	return t
}

// MintFeedKeyForTest returns the feed key of user with salt (tag included).
func (s *Service) MintFeedKeyForTest(user string, salt []byte) string {
	return s.keys.feedKey(user, salt)
}

// HoldAPISlotsForTest takes every API token / feed key lookup slot until
// release is called.
func (s *Service) HoldAPISlotsForTest() (release func()) {
	n := cap(s.apiSlots)
	for i := 0; i < n; i++ {
		s.apiSlots <- struct{}{}
	}
	return func() {
		for i := 0; i < n; i++ {
			<-s.apiSlots
		}
	}
}
