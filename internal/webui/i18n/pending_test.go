package i18n

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func copyEmbedded(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	err := fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(embedded, p)
			m[p] = &fstest.MapFile{Data: b}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestPendingFallback: keys of a pending prefix that a locale's catalog
// leaves out render the primary locale's text (HTML marked lang="en"); the
// primary locale and zh-Hans have every key natively.
func TestPendingFallback(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	en := set.Primary()
	if len(set.Pending) == 0 {
		t.Skip("nothing pending")
	}
	for _, tag := range []string{"en", "zh-Hans"} {
		if ks := set.PendingKeys(set.ByTag(tag)); len(ks) != 0 {
			t.Errorf("%s falls back for %v; it must be complete", tag, ks)
		}
	}
	for _, e := range set.Pending {
		for _, tag := range e.Locales {
			l := set.ByTag(tag)
			if !l.Enabled() {
				t.Errorf("%s disabled: %v", tag, l.Problems())
				continue
			}
			ks := set.PendingKeys(l)
			if len(ks) == 0 {
				continue // TestPendingNotStale reports it
			}
			for _, k := range ks {
				if !pendingMatch(set, tag, k) {
					t.Errorf("%s: %s falls back but no pending entry of %s covers it", tag, k, tag)
				}
				def := set.Reference.Key(k)
				kv := def.ExampleArgs()
				if def.Select != nil {
					kv = append(kv, def.Select.Var, def.Select.Values[0])
				}
				hasHTML := false
				for _, p := range def.Placeholders {
					hasHTML = hasHTML || p.Kind == "html"
				}
				if hasHTML { // html values cannot render as plain text: compare the HTML
					got := strings.TrimSuffix(strings.TrimPrefix(string(l.HTML(k, kv...)), `<span lang="en">`), "</span>")
					if want := string(en.HTML(k, kv...)); got != want || strings.Contains(got, MissingOpen) {
						t.Errorf("%s %s: %q, want the English %q", tag, k, got, want)
					}
				} else if got, want := l.Text(k, kv...), en.Text(k, kv...); got != want || strings.Contains(got, MissingOpen) {
					t.Errorf("%s %s: %q, want the English %q", tag, k, got, want)
				}
				if h := string(l.HTML(k, kv...)); !strings.HasPrefix(h, `<span lang="en">`) || !strings.HasSuffix(h, "</span>") {
					t.Errorf("%s %s: fallback HTML not marked lang=en: %s", tag, k, h)
				}
			}
		}
	}
	// A key outside the pending entries never falls back; a single-key
	// entry covers that key only.
	if set.ByTag("ja").FallsBack("sbar.utc") || en.FallsBack("acct.slot.signin") || en.FallsBack("sbar.local_time") {
		t.Error("FallsBack outside pending")
	}
	if e := (PendingEntry{Key: "sbar.local_time"}); !e.Matches("sbar.local_time") || e.Matches("sbar.local_time_x") || e.Matches("sbar.") {
		t.Error("single-key entry matches more than its key")
	}
}

// pendingMatch reports whether a pending entry listing tag covers key.
func pendingMatch(set *Set, tag, key string) bool {
	for _, e := range set.Pending {
		if !e.Matches(key) {
			continue
		}
		for _, t := range e.Locales {
			if t == tag {
				return true
			}
		}
	}
	return false
}

// TestPendingRules: pending.json cannot excuse the primary locale, unknown
// locales or prefixes that match nothing; keys outside a pending prefix are
// still mandatory; a pending key that IS present is validated normally.
func TestPendingRules(t *testing.T) {
	bad := map[string]string{
		"primary":     `{"pending":[{"prefix":"acct.","locales":["en"],"why":"x"}]}`,
		"unknown tag": `{"pending":[{"prefix":"acct.","locales":["xx"],"why":"x"}]}`,
		"tag case":    `{"pending":[{"prefix":"acct.","locales":["JA"],"why":"x"}]}`,
		"no match":    `{"pending":[{"prefix":"nosuch.","locales":["ja"],"why":"x"}]}`,
		"no dot":      `{"pending":[{"prefix":"acct","locales":["ja"],"why":"x"}]}`,
		"both":        `{"pending":[{"prefix":"sbar.","key":"sbar.local_time","locales":["ja"],"why":"x"}]}`,
		"neither":     `{"pending":[{"locales":["ja"],"why":"x"}]}`,
		"no such key": `{"pending":[{"key":"sbar.nosuch","locales":["ja"],"why":"x"}]}`,
		"key as pfx":  `{"pending":[{"key":"sbar.","locales":["ja"],"why":"x"}]}`,
		"no reason":   `{"pending":[{"prefix":"acct.","locales":["ja"]}]}`,
		"no locales":  `{"pending":[{"prefix":"acct.","locales":[],"why":"x"}]}`,
		"unknown fld": `{"pending":[{"prefix":"acct.","locales":["ja"],"why":"x","all":true}]}`,
	}
	for name, src := range bad {
		m := copyEmbedded(t)
		m["pending.json"] = &fstest.MapFile{Data: []byte(src)}
		if _, err := Load(m); err == nil {
			t.Errorf("%s: pending.json accepted: %s", name, src)
		}
	}
	// No pending.json: nothing is pending, and a catalog without the acct.
	// keys is incomplete.
	m := copyEmbedded(t)
	delete(m, "pending.json")
	set, err := Load(m)
	if err != nil {
		t.Fatal(err)
	}
	if ja := set.ByTag("ja"); !ja.Has("acct.slot.signin") && ja.Enabled() {
		t.Error("ja without acct. keys enabled although nothing is pending")
	}
	// A missing key outside the prefix still disables the locale.
	m = copyEmbedded(t)
	b, _ := fs.ReadFile(embedded, "catalogs/ja.json")
	m["catalogs/ja.json"] = &fstest.MapFile{Data: []byte(strings.Replace(string(b), `"sbar.utc"`, `"sbar.utc.gone"`, 1))}
	set, err = Load(m)
	if err != nil {
		t.Fatal(err)
	}
	if set.ByTag("ja").Enabled() {
		t.Error("ja enabled with a missing non-pending key")
	}
	// A present pending key is validated (here: HTML in a message).
	m = copyEmbedded(t)
	b, _ = fs.ReadFile(embedded, "catalogs/ja.json")
	m["catalogs/ja.json"] = &fstest.MapFile{Data: []byte(strings.Replace(string(b), `"messages": {`,
		`"messages": {"acct.slot.signin": "<b>x</b>",`, 1))}
	set, err = Load(m)
	if err != nil {
		t.Fatal(err)
	}
	ja := set.ByTag("ja")
	if ja.Enabled() || !strings.Contains(strings.Join(ja.Problems(), "\n"), "acct.slot.signin: contains an HTML tag") {
		t.Errorf("present pending key not validated: %v", ja.Problems())
	}
}

// TestPendingNotStale: every pending entry still excuses at least one key
// in each listed locale (remove the locale from the entry once its catalog
// is complete for the prefix).
func TestPendingNotStale(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range set.Pending {
		for _, tag := range e.Locales {
			n := 0
			for _, k := range set.PendingKeys(set.ByTag(tag)) {
				if e.Matches(k) {
					n++
				}
			}
			if n == 0 {
				t.Errorf("pending.json: %s has every %s key now; remove it from the entry", tag, e.name())
			}
		}
	}
}

// TestPendingDocumented: docs/i18n/README.md lists every pending key once,
// so writers see what is still English in their locale.
func TestPendingDocumented(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../docs/i18n/README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	seen := map[string]bool{}
	for _, l := range set.All {
		for _, k := range set.PendingKeys(l) {
			seen[k] = true
		}
	}
	for k := range seen {
		if c := strings.Count(doc, "`"+k+"`"); c != 1 {
			t.Errorf("docs/i18n/README.md mentions pending key `%s` %d times, want once", k, c)
		}
	}
}
