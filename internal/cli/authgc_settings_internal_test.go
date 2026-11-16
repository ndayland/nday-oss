package cli

import (
	"context"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/testutil"
)

// TestAuthGCSessionIdle: `nday auth-gc` takes NDAY_AUTH_SESSION_IDLE from
// the database settings first; a refused database value falls back to the
// environment; sign-in off means the default.
func TestAuthGCSessionIdle(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	t.Setenv(settings.EnvKey, "")
	for _, k := range []string{auth.EnvGitHubClientID, auth.EnvGoogleClientID, auth.EnvXClientID, auth.EnvAppleServicesID,
		auth.EnvAppleKey, auth.EnvAppleKeyFile, auth.EnvSessionMax, auth.EnvSessionIdle} {
		t.Setenv(k, "")
	}
	t.Setenv(auth.EnvPasskeys, "")
	if idle, err := gcSessionIdle(ctx, d.Conn); err != nil || idle != auth.DefaultSessionIdle {
		t.Errorf("sign-in off: %v %v", idle, err)
	}
	t.Setenv(auth.EnvPasskeys, "on")
	t.Setenv(auth.EnvPublicURL, "https://www.nday.land")
	t.Setenv(auth.EnvSecret, randSecret())
	t.Setenv(auth.EnvSessionIdle, "3d")
	if idle, err := gcSessionIdle(ctx, d.Conn); err != nil || idle != 72*time.Hour {
		t.Errorf("environment: %v %v", idle, err)
	}
	if _, err := settings.Set(ctx, d.Conn, auth.EnvSessionIdle, "2d"); err != nil {
		t.Fatal(err)
	}
	if idle, err := gcSessionIdle(ctx, d.Conn); err != nil || idle != 48*time.Hour {
		t.Errorf("database: %v %v", idle, err)
	}
	// below the 10m minimum: refused, the environment applies
	if _, err := settings.Set(ctx, d.Conn, auth.EnvSessionIdle, "1m"); err != nil {
		t.Fatal(err)
	}
	if idle, err := gcSessionIdle(ctx, d.Conn); err != nil || idle != 72*time.Hour {
		t.Errorf("refused database value: %v %v", idle, err)
	}
	// a bad environment is still an error when the database does not fix it
	t.Setenv(auth.EnvSessionIdle, "soon")
	if _, err := gcSessionIdle(ctx, d.Conn); err == nil {
		t.Error("bad environment accepted")
	}
}
