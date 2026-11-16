package auth_test

import (
	"testing"

	"nday.land/nday/internal/auth"
)

// "cli" is the actor name of server-side commands in the audit log; an
// account must not be able to take it.
func TestCLIHandleReserved(t *testing.T) {
	for _, h := range []string{"cli", "CLI", "Cli"} {
		if _, err := auth.CanonicalHandle(h); err != auth.ErrHandleReserved {
			t.Errorf("handle %q: %v, want reserved", h, err)
		}
	}
}
