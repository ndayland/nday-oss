package site_test

import (
	"errors"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
)

func TestParseCVSSScore(t *testing.T) {
	for in, want := range map[string]int{
		"0": 0, "0.0": 0, "0.1": 1, "3.9": 39, "4": 40, "9": 90, "9.0": 90, "9.8": 98, "10": 100, "10.0": 100,
	} {
		if got, ok := site.ParseCVSSScore(in); !ok || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", "-1", "-0", "-0.1", "10.1", "11", "100", "NaN", "nan", "Inf", "+Inf", "1e1", "9e0", "9E0", "9,8", "9.85",
		"9.80", "+9", " 9", "9 ", "09", ".5", "5.", "0x9", "９", "9.8\x00", "9..8", "9.8.1", "ten", "7-8.9", ">=9",
		strings.Repeat("9", 1000), "1" + strings.Repeat("0", 400),
	} {
		if got, ok := site.ParseCVSSScore(in); ok {
			t.Errorf("%q accepted as %d", in, got)
		}
	}
}

func TestNormalizeCVSS(t *testing.T) {
	for _, c := range []struct{ min, max, wantMin, wantMax string }{
		{"", "", "", ""},
		{"9", "", "9", ""},
		{"9.0", "10.0", "9", "10"},
		{"", "3.9", "", "3.9"},
		{"9.8", "9.8", "9.8", "9.8"}, // exact
		{"0", "0", "0", "0"},
		{"0.0", "10", "0", "10"},
	} {
		lo, hi, err := site.NormalizeCVSS(c.min, c.max)
		if err != nil || lo != c.wantMin || hi != c.wantMax {
			t.Errorf("%q..%q: %q..%q %v", c.min, c.max, lo, hi, err)
		}
	}
	for _, c := range []struct{ min, max, param string }{
		{"-1", "", "cvss_min"},
		{"", "10.5", "cvss_max"},
		{"NaN", "9", "cvss_min"},
		{"9", "1e1", "cvss_max"},
		{"7,5", "", "cvss_min"},
		{strings.Repeat("1", 200), "", "cvss_min"},
		{"9", "7", "cvss_max"}, // min above max
		{"9.1", "9", "cvss_max"},
	} {
		var ie *site.InputError
		if _, _, err := site.NormalizeCVSS(c.min, c.max); !errors.As(err, &ie) || ie.Param != c.param {
			t.Errorf("%q..%q: %v, want a %s error", c.min, c.max, err, c.param)
		} else if strings.Contains(ie.Msg, c.min) && len(c.min) > 3 {
			t.Errorf("%q..%q: the message echoes the input: %q", c.min, c.max, ie.Msg)
		}
	}
}

// The severity bands cover 0.1..10 without gaps or overlaps (one decimal).
func TestCVSSBands(t *testing.T) {
	seen := make([]int, 101)
	for _, b := range site.CVSSBands {
		lo, ok1 := site.ParseCVSSScore(b.Min)
		hi, ok2 := site.ParseCVSSScore(b.Max)
		if !ok1 || !ok2 || lo > hi {
			t.Fatalf("%+v", b)
		}
		for s := lo; s <= hi; s++ {
			seen[s]++
		}
	}
	for s, n := range seen {
		if want := map[bool]int{true: 0, false: 1}[s == 0]; n != want {
			t.Errorf("score %d/10 in %d bands", s, n)
		}
	}
}
