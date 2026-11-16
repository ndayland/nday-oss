package pyjson_test

import (
	"encoding/json"
	"math"
	"os"
	"testing"

	"nday.land/nday/internal/pyjson"
)

// pyref.json is produced by tools/dump_pyref.py from the real Python code.
type pyref struct {
	FloatRepr []struct {
		Bits uint64 `json:"bits"`
		Repr string `json:"repr"`
		JSON string `json:"json"`
	} `json:"float_repr"`
	Canonical []struct {
		Text      string `json:"text"`
		Canonical string `json:"canonical"`
		Hash      string `json:"hash"`
		Error     string `json:"error"`
	} `json:"canonical"`
	Repr []struct {
		JSON string `json:"json"`
		Repr string `json:"repr"`
	} `json:"repr"`
}

func loadRef(t *testing.T) pyref {
	t.Helper()
	b, err := os.ReadFile("testdata/pyref.json")
	if err != nil {
		t.Fatal(err)
	}
	var r pyref
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFloatReprMatchesPython(t *testing.T) {
	r := loadRef(t)
	if len(r.FloatRepr) < 8000 {
		t.Fatalf("only %d reference floats", len(r.FloatRepr))
	}
	for _, f := range r.FloatRepr {
		x := math.Float64frombits(f.Bits)
		if got := pyjson.FloatRepr(x); got != f.Repr {
			t.Errorf("repr(%v): got %q want %q", x, got, f.Repr)
		}
		got, err := pyjson.Canonical(x)
		if err != nil || got != f.JSON {
			t.Errorf("json.dumps(%v): got %q (%v) want %q", x, got, err, f.JSON)
		}
	}
}

func TestCanonicalAndHashMatchPython(t *testing.T) {
	for _, c := range loadRef(t).Canonical {
		v, err := pyjson.Decode([]byte(c.Text))
		if c.Error != "" {
			// JSONDecodeError / ValueError (int digits) at loads time, or
			// UnicodeEncodeError (lone surrogate) at hash time: Go rejects
			// both at decode time; either way the record cannot be stored.
			if err == nil {
				t.Errorf("%q: Python %s, Go decoded OK", c.Text, c.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: Go decode error %v", c.Text, err)
			continue
		}
		got, err := pyjson.Canonical(v)
		if err != nil || got != c.Canonical {
			t.Errorf("%q:\n got  %s (%v)\n want %s", c.Text, got, err, c.Canonical)
		}
		if h, _ := pyjson.ContentHash(v); h != c.Hash {
			t.Errorf("%q: hash %s want %s", c.Text, h, c.Hash)
		}
	}
}

func TestReprMatchesPython(t *testing.T) {
	for _, c := range loadRef(t).Repr {
		v, err := pyjson.DecodeString(c.JSON)
		if err != nil {
			t.Fatal(err)
		}
		if got := pyjson.Repr(v); got != c.Repr {
			t.Errorf("repr(%s): got %s want %s", c.JSON, got, c.Repr)
		}
	}
}

func TestObjectDuplicateKeyKeepsFirstPosition(t *testing.T) {
	v, err := pyjson.DecodeString(`{"b":1,"a":2,"b":3}`)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := pyjson.Encode(v, pyjson.Options{})
	if got != `{"b": 3, "a": 2}` { // Python: json.dumps(json.loads(...))
		t.Fatalf("got %s", got)
	}
}

func TestEncodeDefaultAndIndent(t *testing.T) {
	o := pyjson.NewObject()
	o.Set("source", "kev")
	o.Set("ok", true)
	o.Set("n", pyjson.IntOf(-3))
	o.Set("l", []any{})
	o.Set("é", "é")
	got, _ := pyjson.Encode(o, pyjson.Options{Indent: 2, EnsureASCII: true})
	want := "{\n  \"source\": \"kev\",\n  \"ok\": true,\n  \"n\": -3,\n  \"l\": [],\n  \"\\u00e9\": \"\\u00e9\"\n}"
	if got != want {
		t.Fatalf("got %q", got)
	}
	got, _ = pyjson.Encode(o, pyjson.Options{})
	if got != `{"source": "kev", "ok": true, "n": -3, "l": [], "é": "é"}` {
		t.Fatalf("got %q", got)
	}
}

// jsonb::text renders Python floats without exponent and keeps their scale;
// decoding that text must still give Python's canonical form.
func TestJSONBTextRoundTrip(t *testing.T) {
	cases := map[string]string{
		`[100.0, 0.00001, 6.30, 0.0, 10000000000000000, 0.0001]`: `[100.0,1e-05,6.3,0.0,10000000000000000,0.0001]`,
	}
	for in, want := range cases {
		v, err := pyjson.DecodeString(in)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := pyjson.Canonical(v); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}
