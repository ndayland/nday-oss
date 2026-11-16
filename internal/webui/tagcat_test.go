package webui

import (
	"strings"
	"testing"

	"nday.land/nday/internal/tags"
)

// Every slug of the colour categories is a weakness-type tag of the vocabulary.
func TestTypeCategoryInVocabulary(t *testing.T) {
	for slug, cat := range typeCategory {
		tg, ok := tags.Lookup(slug)
		if !ok || tg.Dim != tags.DimType {
			t.Errorf("%s (%s): not a type tag of the vocabulary", slug, cat)
		}
		switch cat {
		case "exec", "mem", "authz", "web":
		default:
			t.Errorf("%s: unknown category %q", slug, cat)
		}
	}
}

// A chip carries tg-c-<category> for a categorised type tag and no category
// class otherwise (an uncategorised type tag, another dimension).
func TestChipCategoryClass(t *testing.T) {
	for slug, want := range map[string]string{
		"command-injection": "tg tg-c-exec",
		"use-after-free":    "tg tg-c-mem",
		"auth-bypass":       "tg tg-c-authz",
		"sql-injection":     "tg tg-c-web",
		"race-condition":    "tg",            // a type tag without a category
		"network":           "tg",            // another dimension
		"remote-unauth":     "tg tg-s",       // strong, unchanged
		"ransomware":        "tg tg-s tg-rw", // keeps its own look
	} {
		if got := chip(slug, "/tag/"+slug).Class; got != want {
			t.Errorf("%s: class %q, want %q", slug, got, want)
		}
	}
	for _, tg := range tags.Vocabulary {
		if tg.Dim != tags.DimType && strings.Contains(chip(tg.Slug, "").Class, "tg-c-") {
			t.Errorf("%s (%s): category class outside the type dimension", tg.Slug, tg.Dim)
		}
	}
}
