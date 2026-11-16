package ghsa

import (
	"os"
	"strconv"
	"testing"
	"time"

	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// TestFromISOFormatMatchesCPython compares fromISOFormat and parseTS with
// vectors produced by CPython 3.13 (testdata/gen_pyref.py iso ...):
// {"s", "fromisoformat": micros since epoch | null, "parse_ts": ... | null}.
// GHSA_ISO_VECTORS=<path> runs a bigger generated file instead.
func TestFromISOFormatMatchesCPython(t *testing.T) {
	var raw []byte
	if p := os.Getenv("GHSA_ISO_VECTORS"); p != "" {
		var err error
		if raw, err = os.ReadFile(p); err != nil {
			t.Fatal(err)
		}
	} else {
		raw = testutil.ReadFile(t, "internal/collector/ghsa/testdata/fromisoformat.json")
	}
	v, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, s string, want any, got time.Time, ok bool) {
		t.Helper()
		if want == nil {
			if ok {
				t.Errorf("%s(%q) = %v, Python: invalid", name, s, got)
			}
			return
		}
		w, _ := strconv.ParseInt(string(want.(pyjson.Int)), 10, 64)
		if !ok || got.UnixMicro() != w {
			t.Errorf("%s(%q) = %v ok=%v, Python: %v", name, s, got, ok, time.UnixMicro(w).UTC())
		}
	}
	n := 0
	for _, it := range v.([]any) {
		o := it.(*pyjson.Object)
		s := o.Get("s").(string)
		got, ok := fromISOFormat(s)
		check("fromisoformat", s, o.Get("fromisoformat"), got, ok)
		got, ok = parseTS(s)
		check("parse_ts", s, o.Get("parse_ts"), got, ok)
		n++
	}
	t.Logf("%d vectors", n)
}

func TestIsoZ(t *testing.T) {
	s, err := isoZ(time.Date(2026, 11, 12, 14, 57, 39, 999999000, time.FixedZone("x", 3600)))
	if err != nil || s != "2026-11-12T13:57:39Z" {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := isoZ(time.Date(0, 12, 31, 23, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("year 0 must overflow")
	}
}
