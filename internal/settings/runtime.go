package settings

import "context"

// Runtime applies database settings to a running process. `nday serve`
// implements it (internal/cli) and hands it to the back office
// (admin.Options.Settings), whose settings pages use it like this:
//
//	tx: Lock; snap := LoadSnapshot(tx, rt.Key()); cand := snap.With(k, v) (or Without);
//	    rt.Validate(cand) -> refuse the change (the error names keys only);
//	    Set / SetSecret / Unset; audit row; commit
//	after the commit: rt.Apply(ctx) (it reads app_settings again itself)
//
// Settings marked Restart (Def.Restart) are stored but take effect only at
// the next start; Apply leaves them alone.
type Runtime interface {
	// Validate checks the whole configuration that candidate (not yet
	// written) would give this process: every validator of the managed
	// settings, sign-in must not be switched off entirely, and the parts
	// that are fixed while the process runs must stay as they are. When it
	// passes, Apply of the same snapshot does not fail because of the
	// configuration. Errors name keys, never values.
	Validate(candidate *Snapshot) error
	// Apply reads the stored settings again and puts the configuration
	// they give into the running process (call it after the transaction
	// committed). Calls are serialised and each one loads under the same
	// serialisation, so concurrent saves leave the process at the last
	// committed state whatever order their Apply calls run in. It is
	// idempotent: calling it with nothing changed re-applies the same
	// state (a save that changes nothing uses that as a retry). On error
	// nothing was changed; errors name keys, never values.
	Apply(ctx context.Context) error
	// Env is the process environment lookup (for Snapshot.Source:
	// db / env / default).
	Env() func(string) (string, bool)
	// Key is the master key (nil: NDAY_SETTINGS_KEY is not configured,
	// secrets cannot be stored).
	Key() *Key
}
