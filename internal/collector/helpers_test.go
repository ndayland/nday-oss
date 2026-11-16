package collector_test

import (
	"encoding/json"
	"os"
	"testing"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/pystr"
)

type ref struct {
	Strip []struct {
		S       string `json:"s"`
		Strip   string `json:"strip"`
		IsSpace bool   `json:"isspace"`
	} `json:"strip"`
	FromISO []struct {
		S    string  `json:"s"`
		OK   bool    `json:"ok"`
		Date *string `json:"date"`
	} `json:"fromisoformat"`
}

func loadRef(t *testing.T) ref {
	b, err := os.ReadFile("../pyjson/testdata/pyref.json")
	if err != nil {
		t.Fatal(err)
	}
	var r ref
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStripMatchesPython(t *testing.T) {
	r := loadRef(t)
	for _, c := range r.Strip {
		if got := pystr.Strip(c.S); got != c.Strip {
			t.Errorf("strip(%q) = %q want %q", c.S, got, c.Strip)
		}
	}
	// Exhaustive over the BMP prefix covered by the reference: the reference
	// lists every code point < U+3001 for which Python's isspace() is true.
	py := map[rune]bool{}
	for _, c := range r.Strip {
		if c.IsSpace {
			py[[]rune(c.S)[0]] = true
		}
	}
	for cp := rune(0); cp <= 0x3000; cp++ {
		if pystr.IsSpace(cp) != py[cp] {
			t.Errorf("IsSpace(%U) = %v, Python %v", cp, pystr.IsSpace(cp), py[cp])
		}
	}
}

func TestParseISODateMatchesPython(t *testing.T) {
	for _, c := range loadRef(t).FromISO {
		got, ok := collector.ParseISODate(c.S)
		if ok != c.OK {
			t.Errorf("fromisoformat(%q): ok=%v want %v", c.S, ok, c.OK)
			continue
		}
		if ok && got.Format("2006-01-02") != *c.Date {
			t.Errorf("fromisoformat(%q) = %s want %s", c.S, got.Format("2006-01-02"), *c.Date)
		}
	}
}

func TestText(t *testing.T) {
	if collector.Text(" \x1f x 　") == nil || *collector.Text(" \x1f x 　") != "x" {
		t.Error("strip")
	}
	for _, v := range []any{nil, 5, "", " \x1c\x1d\x1e\x1f "} {
		if collector.Text(v) != nil {
			t.Errorf("Text(%q) should be nil", v)
		}
	}
}
