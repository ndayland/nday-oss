package i18n

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// PendingEntry is one entry of pending.json: keys starting with Prefix, or
// the single key Key (exactly one of the two is set), may be missing from
// the catalogs of Locales for now; those locales render the primary
// locale's (English) text for them, marked lang="en" in HTML.
//
// It exists for features whose copy is written in the primary locale and
// zh-Hans first while translation of the other locales is on hold. It is
// deliberately narrow: only listed prefixes, only listed locales, never the
// primary locale; every other key stays mandatory, and a key that IS present
// is validated like any other. An entry whose prefix is fully translated in
// a locale must be removed (TestPendingNotStale).
type PendingEntry struct {
	Prefix  string   `json:"prefix,omitempty"`
	Key     string   `json:"key,omitempty"`
	Locales []string `json:"locales"`
	Why     string   `json:"why"`
	Since   string   `json:"since"`
}

// Matches reports whether key is covered by the entry.
func (e PendingEntry) Matches(key string) bool {
	if e.Key != "" {
		return key == e.Key
	}
	return e.Prefix != "" && strings.HasPrefix(key, e.Prefix)
}

// name is the entry's prefix or key (messages).
func (e PendingEntry) name() string {
	if e.Key != "" {
		return e.Key
	}
	return e.Prefix
}

// LoadPending reads pending.json (optional: a missing file means nothing is
// pending) and attaches the entries to the locales of s. Entries must name
// registered, non-primary locales and either a prefix ending in "." that
// matches at least one key of the reference or one key of the reference.
func LoadPending(fsys fs.FS, s *Set) ([]PendingEntry, error) {
	b, err := fs.ReadFile(fsys, "pending.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f struct {
		Comment string         `json:"comment"`
		Pending []PendingEntry `json:"pending"`
	}
	if err := strictUnmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("pending.json: %w", err)
	}
	for _, e := range f.Pending {
		switch {
		case (e.Prefix == "") == (e.Key == ""):
			return nil, fmt.Errorf("pending.json: entry %q needs exactly one of prefix and key", e.name())
		case e.Prefix != "" && !strings.HasSuffix(e.Prefix, "."):
			return nil, fmt.Errorf("pending.json: prefix %q must end in \".\"", e.Prefix)
		case e.Why == "":
			return nil, fmt.Errorf("pending.json: entry %q needs a reason", e.name())
		}
		n := 0
		for _, k := range s.Reference.Keys() {
			if e.Matches(k) {
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("pending.json: %q matches no key of keys.json", e.name())
		}
		if len(e.Locales) == 0 {
			return nil, fmt.Errorf("pending.json: %q lists no locale", e.name())
		}
		for _, tag := range e.Locales {
			l := s.byTag[strings.ToLower(tag)]
			switch {
			case l == nil || l.Tag != tag:
				return nil, fmt.Errorf("pending.json: %q is not a locale tag of locales.json", tag)
			case l.IsPrimary():
				return nil, fmt.Errorf("pending.json: the primary locale %s can never be pending", tag)
			}
			l.pending = append(l.pending, e)
		}
	}
	return f.Pending, nil
}

// PendingKeys lists the keys of l that currently render the primary
// locale's text (pending and missing from l's catalog), sorted.
func (s *Set) PendingKeys(l *Locale) []string {
	var out []string
	for _, k := range s.Reference.Keys() {
		if l.FallsBack(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
