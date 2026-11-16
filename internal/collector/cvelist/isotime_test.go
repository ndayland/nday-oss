package cvelist

import (
	"testing"

	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// TestFromISOFormatMatchesPython compares parseTS with the real CPython
// parse_ts on 6000 handwritten and mutated inputs (testdata/gen_isoref.py).
func TestFromISOFormatMatchesPython(t *testing.T) {
	v, err := pyjson.Decode(testutil.ReadFile(t, "internal/collector/cvelist/testdata/fromisoformat_ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, it := range v.([]any) {
		row := it.([]any)
		in := row[0].(string)
		got, ok := parseTS(in)
		switch {
		case row[1] == nil && ok:
			t.Errorf("%q: Go parsed %s, Python None", in, got.isoformat())
			bad++
		case row[1] != nil && !ok:
			t.Errorf("%q: Go None, Python %v", in, row[1])
			bad++
		case ok && (got.isoformat() != row[1] || pyjson.IntOf(got.micro()) != row[2]):
			t.Errorf("%q: Go %s/%d, Python %v/%v", in, got.isoformat(), got.micro(), row[1], row[2])
			bad++
		}
		if bad > 30 {
			t.Fatal("too many differences")
		}
	}
}
