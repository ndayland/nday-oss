// Package settings is the database-backed configuration (table
// app_settings, migrations/0014_settings.sql): the registered NDAY_*
// settings an operator may change without editing the environment.
//
// Lookup is layered. For a key of the registry (Defs) a row in
// app_settings wins over the environment variable of the same name; no
// row means "not set in the database" and the environment (else the
// built-in default) applies exactly as before. Keys outside the registry
// are never served from the database, whatever the table holds.
//
// Secrets (Def.Secret) are stored only as AES-256-GCM ciphertext sealed
// with a key derived from the master key NDAY_SETTINGS_KEY (environment
// only; ParseKey). A secret that cannot be opened (no or wrong master key)
// is treated as absent from the database: the environment applies and
// Snapshot.Warnings says so, naming only the key.
//
// No String, error or log value of this package contains a secret, and
// errors do not echo stored values.
//
// The package deliberately imports no other nday package (auth, discuss
// and the collectors validate the values; see internal/cli/settings.go).
package settings

// Groups, in display order.
const (
	GroupDiscuss    = "discuss"
	GroupCollectors = "collectors"
	GroupAuth       = "auth"
	GroupHot        = "hot"
)

// Groups lists the group names in display order.
var Groups = []string{GroupDiscuss, GroupCollectors, GroupAuth, GroupHot}

// Def describes one registered setting. Key is the environment variable
// name, which is also the app_settings key.
type Def struct {
	Key   string
	Group string
	// Secret: stored encrypted, never shown (only a hint), never written
	// from the command line.
	Secret bool
	// Restart: a running website applies a change only after a restart.
	Restart bool
}

var defs = func() []Def {
	var d []Def
	add := func(group string, secret bool, keys ...string) {
		for _, k := range keys {
			d = append(d, Def{Key: k, Group: group, Secret: secret})
		}
	}
	// discussions (internal/discuss/config.go); NDAY_DISCUSS mounts the
	// routes at start-up, hence Restart. NDAY_DISCUSS_DB_POOL_SIZE stays in
	// the environment.
	d = append(d, Def{Key: "NDAY_DISCUSS", Group: GroupDiscuss, Restart: true})
	add(GroupDiscuss, false,
		"NDAY_DISCUSS_POST_BURST", "NDAY_DISCUSS_POST_EVERY", "NDAY_DISCUSS_POST_DAILY",
		"NDAY_DISCUSS_NEW_POST_BURST", "NDAY_DISCUSS_NEW_POST_EVERY", "NDAY_DISCUSS_NEW_POST_DAILY",
		"NDAY_DISCUSS_NEW_ACCOUNT_AGE", "NDAY_DISCUSS_NEW_ACCOUNT_COMMENTS",
		"NDAY_DISCUSS_ADDR_BURST", "NDAY_DISCUSS_ADDR_EVERY",
		"NDAY_DISCUSS_EDIT_BURST", "NDAY_DISCUSS_EDIT_EVERY",
		"NDAY_DISCUSS_REPORT_DAILY", "NDAY_DISCUSS_REPORT_BURST", "NDAY_DISCUSS_REPORT_EVERY",
		"NDAY_DISCUSS_DELETE_BURST", "NDAY_DISCUSS_DELETE_EVERY",
		"NDAY_DISCUSS_READ_BURST", "NDAY_DISCUSS_READ_EVERY",
		"NDAY_DISCUSS_MOD_BURST", "NDAY_DISCUSS_MOD_EVERY",
		"NDAY_DISCUSS_DUPLICATE_WINDOW",
		// signed-out reading of the comments (on/off) and its own per-address
		// limit; applied to the running site at once (SetLimits)
		"NDAY_DISCUSS_GUEST_READ", "NDAY_DISCUSS_GUEST_READ_BURST", "NDAY_DISCUSS_GUEST_READ_EVERY")
	// readers' corrections of vulnerability pages (internal/corrections,
	// docs/corrections.md): community limits shown with the discussion
	// ones; applied to the running site at once (SetLimits)
	add(GroupDiscuss, false,
		"NDAY_CORRECTIONS_DAILY", "NDAY_CORRECTIONS_OPEN_PER_VULN", "NDAY_CORRECTIONS_OPEN_PER_USER",
		"NDAY_CORRECTIONS_BURST", "NDAY_CORRECTIONS_EVERY")
	// collectors (cvelist, ghsa, xposts)
	add(GroupCollectors, false,
		"NDAY_CVELIST_BOOTSTRAP_DAYS", "NDAY_CVELIST_MAX_FILES", "NDAY_CVELIST_BACKFILL_RETRY_DAYS",
		"NDAY_GHSA_BOOTSTRAP_DAYS", "NDAY_GHSA_MAX_REQUESTS", "NDAY_GHSA_OVERLAP_MINUTES")
	add(GroupCollectors, true, "NDAY_GITHUB_TOKEN", "NDAY_X_BEARER_TOKEN")
	// sign-in (internal/auth/config.go)
	add(GroupAuth, false,
		"NDAY_AUTH_GITHUB_CLIENT_ID", "NDAY_AUTH_GOOGLE_CLIENT_ID", "NDAY_AUTH_X_CLIENT_ID",
		"NDAY_AUTH_APPLE_SERVICES_ID", "NDAY_AUTH_APPLE_TEAM_ID", "NDAY_AUTH_APPLE_KEY_ID",
		"NDAY_AUTH_PASSKEYS", "NDAY_AUTH_PASSKEY_SIGNUP", "NDAY_AUTH_PASSKEY_SIGNUP_DAILY",
		"NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL", "NDAY_AUTH_MAX_PASSKEYS",
		"NDAY_AUTH_SESSION_IDLE", "NDAY_AUTH_SESSION_MAX", "NDAY_AUTH_SENSITIVE_WINDOW",
		"NDAY_AUTH_HANDLE_HOLD", "NDAY_TERMS_VERSION")
	add(GroupAuth, true,
		"NDAY_AUTH_GITHUB_CLIENT_SECRET", "NDAY_AUTH_GOOGLE_CLIENT_SECRET", "NDAY_AUTH_X_CLIENT_SECRET",
		"NDAY_AUTH_APPLE_KEY")
	// hot list pinning (internal/site/pin.go); applied to the running site
	// at once
	add(GroupHot, false,
		"NDAY_HOT_PIN_MAX", "NDAY_HOT_PIN_RESEARCHERS", "NDAY_HOT_PIN_RECENT_HOURS", "NDAY_HOT_PIN_WAVE_DAYS")
	return d
}()

var byKey = func() map[string]Def {
	m := make(map[string]Def, len(defs))
	for _, d := range defs {
		if _, dup := m[d.Key]; dup {
			panic("settings: duplicate key " + d.Key)
		}
		m[d.Key] = d
	}
	return m
}()

// Defs returns every registered setting, grouped in Groups order (a copy).
func Defs() []Def { return append([]Def(nil), defs...) }

// GroupDefs returns the settings of one group in display order.
func GroupDefs(group string) []Def {
	var out []Def
	for _, d := range defs {
		if d.Group == group {
			out = append(out, d)
		}
	}
	return out
}

// Lookup returns the definition of a registered key.
func Lookup(key string) (Def, bool) {
	d, ok := byKey[key]
	return d, ok
}
