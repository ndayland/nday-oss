package admin

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/settings"
)

// The database settings of /admin/settings (internal/settings,
// docs/settings.md). Every change runs in one transaction on the auth pool:
// the actor is re-checked (writeTx), app_settings is locked, the stored
// rows are read, the candidate configuration is checked by the runtime
// (settings.Runtime.Validate) before anything is written, then the rows
// and the audit row(s) are written; after the commit the runtime re-reads
// app_settings and applies what is stored to the running process (also
// after a save that changed nothing: that makes saving again a retry of
// an Apply that failed). Nothing here returns, logs or audits a value of a
// secret; refusals name keys only.

// Errors of the settings writes.
var (
	// ErrSettingsOff: this process has no settings runtime (Options.Settings nil).
	ErrSettingsOff = errors.New("database settings are not available in this process")
	// ErrNoMasterKey: NDAY_SETTINGS_KEY is not configured, secrets cannot be stored.
	ErrNoMasterKey = errors.New(settings.EnvKey + " is not configured; secrets cannot be stored")
)

// ConfigError: the resulting configuration was refused by the runtime.
// Keys are the NDAY_* names the refusal mentions (registered or not, e.g.
// NDAY_AUTH_SECRET); SignInOff: the change would switch sign-in off. It
// never holds a value (the validators' own messages are not kept).
type ConfigError struct {
	Keys      []string
	SignInOff bool
}

func (e *ConfigError) Error() string {
	if len(e.Keys) == 0 {
		return "settings: the resulting configuration is invalid"
	}
	return "settings: the resulting configuration is invalid: " + strings.Join(e.Keys, ", ")
}

// ApplyError: the change was stored (committed) but the running process
// could not apply it; it takes effect at the next start. Keys as in
// ConfigError.
type ApplyError struct{ Keys []string }

func (e *ApplyError) Error() string {
	return "settings: stored, but the running site could not apply the change"
}

// SettingsChange is the outcome of a write.
type SettingsChange struct {
	// Changed lists the keys whose row was written or removed (sorted).
	Changed []string
	// Snapshot is the configuration now stored (as this request's
	// transaction committed it), for the answer.
	Snapshot *settings.Snapshot
}

// keyNameRe finds NDAY_* names in a refusal (the validators' messages name
// the variables; nothing else of the message is kept).
var keyNameRe = regexp.MustCompile(`\bNDAY_[A-Z0-9_]*[A-Z0-9]`)

// namedKeys returns the distinct NDAY_* names mentioned by err, sorted.
func namedKeys(err error) []string {
	if err == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, k := range keyNameRe.FindAllString(err.Error(), -1) {
		if len(k) <= 70 && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func configError(err error) *ConfigError {
	return &ConfigError{Keys: namedKeys(err),
		SignInOff: errors.Is(err, auth.ErrReconfigureDisabled) || strings.Contains(err.Error(), "turn sign-in off")}
}

// SettingsSnapshot reads the stored settings for the page (read-only pool),
// secrets opened with the runtime's master key. ErrSettingsOff without a
// runtime.
func (s *Service) SettingsSnapshot(ctx context.Context) (*settings.Snapshot, error) {
	rt := s.o.Settings
	if rt == nil {
		return nil, ErrSettingsOff
	}
	var snap *settings.Snapshot
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		snap, err = settings.LoadSnapshot(ctx, c, rt.Key())
		return err
	})
	return snap, err
}

// auditTarget is the target id of a change of keys: the key itself, else
// their common group, else "settings".
func auditTarget(keys []string) string {
	if len(keys) == 1 {
		return keys[0]
	}
	group := ""
	for _, k := range keys {
		d, _ := settings.Lookup(k)
		if group != "" && d.Group != group {
			return "settings"
		}
		group = d.Group
	}
	if group == "" {
		return "settings"
	}
	return group
}

// SaveSettings stores plain settings (set: key -> value, already checked
// with settings.CheckValue) and removes stored rows (unset: any registered
// key, secrets included: clearing carries no value) in one transaction.
// Values equal to the stored ones and unset keys without a row are no
// change; with no change nothing is written or audited, but the stored
// state is applied again (a retry after a failed Apply). Plain
// changes write one settings.update row ({"set": [...], "unset": [...]},
// key names only), each cleared secret a settings.secret_clear row.
// Errors: ErrSettingsOff, *ConfigError (nothing written), *ApplyError
// (written and committed, not applied), settings.ErrSecretKey for a secret
// in set, auth.ErrNotAdmin.
func (s *Service) SaveSettings(ctx context.Context, actor string, set map[string]string, unset []string) (SettingsChange, error) {
	rt := s.o.Settings
	if rt == nil {
		return SettingsChange{}, ErrSettingsOff
	}
	setKeys := make([]string, 0, len(set))
	for k := range set {
		if d, ok := settings.Lookup(k); ok && d.Secret {
			return SettingsChange{}, settings.ErrSecretKey
		}
		setKeys = append(setKeys, k)
	}
	sort.Strings(setKeys)
	unset = append([]string(nil), unset...)
	sort.Strings(unset)
	var res SettingsChange
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		if err := settings.Lock(ctx, tx); err != nil {
			return err
		}
		snap, err := settings.LoadSnapshot(ctx, tx, rt.Key())
		if err != nil {
			return err
		}
		cand := snap
		var toSet, toUnset []string
		for _, k := range setKeys {
			if cur, ok := snap.Value(k); ok && cur == set[k] {
				continue
			}
			cand, toSet = cand.With(k, set[k]), append(toSet, k)
		}
		for _, k := range unset {
			if !snap.Has(k) {
				continue
			}
			cand, toUnset = cand.Without(k), append(toUnset, k)
		}
		res.Snapshot = cand
		if len(toSet)+len(toUnset) == 0 {
			return nil
		}
		if err := rt.Validate(cand); err != nil {
			return configError(err)
		}
		var plainSet, plainUnset []string
		for _, k := range toSet {
			changed, err := settings.Set(ctx, tx, k, set[k])
			if err != nil {
				return err
			}
			if changed {
				plainSet = append(plainSet, k)
			}
		}
		for _, k := range toUnset {
			removed, err := settings.Unset(ctx, tx, k)
			if err != nil {
				return err
			}
			if !removed {
				continue
			}
			if d, _ := settings.Lookup(k); d.Secret {
				if err := audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: audit.SettingsSecretClear,
					TargetType: audit.TargetSetting, TargetID: k, Details: map[string]any{"keys": []string{k}}}); err != nil {
					return err
				}
				res.Changed = append(res.Changed, k)
				continue
			}
			plainUnset = append(plainUnset, k)
		}
		if n := len(plainSet) + len(plainUnset); n > 0 {
			details := map[string]any{}
			if len(plainSet) > 0 {
				details["set"] = plainSet
			}
			if len(plainUnset) > 0 {
				details["unset"] = plainUnset
			}
			if err := audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: audit.SettingsUpdate, TargetType: audit.TargetSetting,
				TargetID: auditTarget(append(append([]string(nil), plainSet...), plainUnset...)), Details: details}); err != nil {
				return err
			}
		}
		res.Changed = append(append(res.Changed, plainSet...), plainUnset...)
		sort.Strings(res.Changed)
		return nil
	})
	if err != nil {
		return SettingsChange{}, err
	}
	return s.apply(ctx, rt, res, "save")
}

// SetSecret stores one secret (sealed with the master key) after the
// runtime accepted the configuration it gives. It never compares the value
// with the stored one (that would tell an admin session whether a guess is
// the stored secret): every call seals and writes it again and writes one
// settings.secret_set row (key name only). Errors: ErrSettingsOff,
// ErrNoMasterKey, *ConfigError, *ApplyError, the settings errors of the
// key and value (they never contain the value), auth.ErrNotAdmin.
func (s *Service) SetSecret(ctx context.Context, actor, key, value string) (SettingsChange, error) {
	rt := s.o.Settings
	if rt == nil {
		return SettingsChange{}, ErrSettingsOff
	}
	if d, ok := settings.Lookup(key); !ok {
		return SettingsChange{}, settings.ErrUnknownKey
	} else if !d.Secret {
		return SettingsChange{}, settings.ErrPlainKey
	}
	k := rt.Key()
	if k == nil {
		return SettingsChange{}, ErrNoMasterKey
	}
	value = strings.TrimSpace(value)
	var res SettingsChange
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		if err := settings.Lock(ctx, tx); err != nil {
			return err
		}
		snap, err := settings.LoadSnapshot(ctx, tx, k)
		if err != nil {
			return err
		}
		cand := snap.With(key, value)
		if err := rt.Validate(cand); err != nil {
			return configError(err)
		}
		if err := settings.SetSecret(ctx, tx, key, value, k); err != nil {
			return err
		}
		res.Snapshot, res.Changed = cand, []string{key}
		return audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: audit.SettingsSecretSet, TargetType: audit.TargetSetting,
			TargetID: key, Details: map[string]any{"keys": []string{key}}})
	})
	if err != nil {
		return SettingsChange{}, err
	}
	return s.apply(ctx, rt, res, "secret")
}

// ClearSecret removes a stored secret (SaveSettings with unset = [key]).
func (s *Service) ClearSecret(ctx context.Context, actor, key string) (SettingsChange, error) {
	if d, ok := settings.Lookup(key); !ok {
		return SettingsChange{}, settings.ErrUnknownKey
	} else if !d.Secret {
		return SettingsChange{}, settings.ErrPlainKey
	}
	return s.SaveSettings(ctx, actor, nil, []string{key})
}

// applyTimeout bounds Apply after a commit (it reads app_settings again).
const applyTimeout = 10 * time.Second

// apply puts what is stored into the running process after a commit (or
// after a save that changed nothing: a retry). The request's cancellation
// does not stop it: the change is committed.
func (s *Service) apply(ctx context.Context, rt settings.Runtime, res SettingsChange, op string) (SettingsChange, error) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), applyTimeout)
	defer cancel()
	if err := rt.Apply(actx); err != nil {
		// stored but not in force: key names only (the runtime's errors
		// name keys, but nothing of their text is logged here)
		ae := &ApplyError{Keys: namedKeys(err)}
		s.log.Error("admin: settings stored but not applied to the running site", "op", op, "changed", res.Changed,
			"keys", ae.Keys)
		return res, ae
	}
	return res, nil
}
