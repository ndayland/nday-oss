package ghsa

import (
	"net/http"
	"os"
	"regexp"
	"strconv"
	"testing"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/testutil"
)

func decodeFile(t *testing.T, rel string) any {
	t.Helper()
	v, err := pyjson.Decode(testutil.ReadFile(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func asInt(v any) rune {
	n, _ := strconv.ParseInt(string(v.(pyjson.Int)), 10, 32)
	return rune(n)
}

func pyRanges(v any) []cpRange {
	var out []cpRange
	for _, r := range v.([]any) {
		p := r.([]any)
		out = append(out, cpRange{asInt(p[0]), asInt(p[1])})
	}
	return out
}

func eachCodePoint(f func(r rune)) {
	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		f(r)
	}
}

// TestCharacterClassesMatchPython checks every code point: the \d and \s
// classes used in the Go regexps, isdigit/isdecimal tables, pystr.IsSpace and
// the IGNORECASE letter classes against CPython 3.13 (testdata/python_classes.json).
func TestCharacterClassesMatchPython(t *testing.T) {
	doc := decodeFile(t, "internal/collector/ghsa/testdata/python_classes.json").(*pyjson.Object)
	reD := regexp.MustCompile(`^[` + reDecimal + `]$`)
	reS := regexp.MustCompile(`^[` + reSpace + `]$`)
	pyD, pyDec, pyDig := pyRanges(doc.Get("re_d")), pyRanges(doc.Get("isdecimal")), pyRanges(doc.Get("isdigit"))
	pyS, pySp, pyPr := pyRanges(doc.Get("re_s")), pyRanges(doc.Get("isspace")), pyRanges(doc.Get("isprintable"))
	bad := 0
	eachCodePoint(func(r rune) {
		in := func(rs []cpRange) bool { _, ok := inRanges(r, rs); return ok }
		s := string(r)
		if reD.MatchString(s) != in(pyD) || in(pyDecimal) != in(pyDec) || in(pyDigit) != in(pyDig) ||
			reS.MatchString(s) != in(pyS) || pystr.IsSpace(r) != in(pySp) ||
			(r >= 0x7F && pyPrintable(r) != in(pyPr)) {
			if bad++; bad < 10 {
				t.Errorf("U+%04X: class mismatch", r)
			}
		}
	})
	ic := doc.Get("ignorecase").(*pyjson.Object)
	for _, letter := range ic.Keys() {
		want := map[rune]bool{}
		for _, cp := range ic.Get(letter).([]any) {
			want[asInt(cp)] = true
		}
		re := regexp.MustCompile(`^` + foldPy(letter) + `$`)
		eachCodePoint(func(r rune) {
			if re.MatchString(string(r)) != want[r] {
				t.Errorf("IGNORECASE %q vs U+%04X: Go %v, Python %v", letter, r, !want[r], want[r])
			}
		})
	}
	// Go's own \d / (?i) are NOT equivalent (why the classes are explicit).
	if regexp.MustCompile(`^\d$`).MatchString("٣") || !regexp.MustCompile(`^\p{Nd}$`).MatchString("\U00010D40") ||
		regexp.MustCompile(`(?i)^i$`).MatchString("ı") {
		t.Error("assumption about Go regexp semantics changed")
	}
}

// TestFixCommitURLsMatchPython: random reference lists, Python's
// fix_commit_urls output and NOT_FIX_RE.match per element
// (testdata/fix_urls.json; GHSA_FIXURL_VECTORS=<file> for a bigger run).
func TestFixCommitURLsMatchPython(t *testing.T) {
	var v any
	if p := os.Getenv("GHSA_FIXURL_VECTORS"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if v, err = pyjson.Decode(b); err != nil {
			t.Fatal(err)
		}
	} else {
		v = decodeFile(t, "internal/collector/ghsa/testdata/fix_urls.json")
	}
	n := 0
	for _, it := range v.([]any) {
		o := it.(*pyjson.Object)
		got, _ := pyjson.Canonical(FixCommitURLs(o.Get("refs")))
		want, _ := pyjson.Canonical(o.Get("want"))
		if got != want {
			t.Errorf("refs %s:\n got  %s\n want %s", pyjson.Repr(o.Get("refs")), got, want)
		}
		for i, ref := range o.Get("refs").([]any) {
			s, ok := ref.(string)
			if !ok {
				continue
			}
			if nf := o.Get("not_fix").([]any)[i]; notFixRe.MatchString(s) != nf {
				t.Errorf("NOT_FIX_RE.match(%q): Go %v, Python %v", s, !nf.(bool), nf)
			}
			n++
		}
	}
	t.Logf("%d references checked", n)
}

func TestPyRepr(t *testing.T) {
	o := pyjson.NewObject()
	o.Set("a", []any{nil, true, pyjson.IntOf(3), 1.5, "x'y", "\U00010D41\u00e9\x00"})
	if got := pyRepr(o); got != `{'a': [None, True, 3, 1.5, "x'y", '\U00010d41é\x00']}` {
		t.Error(got)
	}
}

func TestPyIntAndDigits(t *testing.T) {
	for s, want := range map[string]string{
		"7": "7", " 7 ": "7", "+7": "7", "-7": "-7", "0_1": "1", "007": "7", "٣": "3", "\u3000 12\x1f": "12",
	} {
		n, err := pyInt(s)
		if err != nil || n.String() != want {
			t.Errorf("pyInt(%q) = %v, %v", s, n, err)
		}
	}
	for _, s := range []string{"", " ", "1_", "_1", "1__0", "1 0", "²", "0x10", "1.0", "+-1", "- 1"} {
		if _, err := pyInt(s); err == nil {
			t.Errorf("pyInt(%q) accepted", s)
		}
	}
	if !isDigitStr("²") || isDigitStr("") || isDigitStr("1a") {
		t.Error("isDigitStr")
	}
	if _, err := pyFloatDigits("²"); err == nil {
		t.Error("float('²') must fail")
	}
}

func TestLinkHeaderAndURLSplit(t *testing.T) {
	real := string(testutil.ReadFile(t, "tests/fixtures/ghsa/link_header.txt"))
	h := http.Header{"Link": {pystr.Strip(real)}}
	nxt, err := nextURL(h)
	if err != nil || nxt != "https://api.github.com/advisories?type=reviewed&sort=updated&direction=asc&per_page=100&updated=%3E%3D2026-11-05T14%3A58%3A47Z&after=Y3Vyc29yOnYyOpK0MjAyNi0xMS0wOVQyMToxODozMFrOAAgSnA%3D%3D" {
		t.Fatalf("%q %v", nxt, err)
	}
	for _, c := range []struct {
		link, want string
		bad        bool
	}{
		{`<https://evil.example/advisories?after=x>; rel="next"`, "", true},
		{`<https://api.github.com/advisories/x?after=x>; rel="next"`, "", true},
		{`<https://api.github.com:443/advisories?after=x>; rel="next"`, "", true},
		{`<HTTPS://api.github.com/advisories?after=x>; rel="next"`, "HTTPS://api.github.com/advisories?after=x", false},
		{`<https://api.github.com/advisories?after=x>; rel="prev"`, "", false},
		{`<https://api.github.com/advisories?a=1>; rel="prev", <https://api.github.com/advisories?a=2>; rel="next"`, "https://api.github.com/advisories?a=2", false},
		{`<https://api.github.com/advisories?a=1>; rel=next; x="1=2"`, "https://api.github.com/advisories?a=1", false},
		{` '<https://api.github.com/advisories#f>' ; rel="next"`, "https://api.github.com/advisories#f", false},
		{`<https://[api.github.com/advisories?a=1>; rel="next"`, "", true},
		{``, "", false},
	} {
		got, err := nextURL(http.Header{"Link": {c.link}})
		if got != c.want || (err != nil) != c.bad {
			t.Errorf("%s: %q %v", c.link, got, err)
		}
	}
	// Two Link fields are joined with ", " like httpx.Headers.get.
	got, _ := nextURL(http.Header{"Link": {`<https://api.github.com/advisories?a=1>; rel="prev"`, `<https://api.github.com/advisories?a=2>; rel="next"`}})
	if got != "https://api.github.com/advisories?a=2" {
		t.Errorf("multi Link: %q", got)
	}
}

// TestNormalizeParityFile compares Normalize with Python's output for an
// arbitrary record dump (ad hoc, e.g. every ghsa raw_record of a DB snapshot):
// GHSA_PY_NORMALIZED=<json from a Python run of tools/dump_golden._normalize,
// with "payload" added to each record>. Skipped when unset.
func TestNormalizeParityFile(t *testing.T) {
	p := os.Getenv("GHSA_PY_NORMALIZED")
	if p == "" {
		t.Skip("GHSA_PY_NORMALIZED not set")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyjson.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{Token: new(string)})
	same := 0
	for _, it := range v.([]any) {
		o := it.(*pyjson.Object)
		rec := model.RawRecord{Source: Name, SourceKey: o.Get("source_key").(string), Payload: o.Get("payload")}
		if h, _ := rec.ContentHash(); h != o.Get("content_hash") {
			t.Errorf("%s: hash %s vs %v", rec.SourceKey, h, o.Get("content_hash"))
		}
		n, err := c.Normalize(rec)
		if err == nil {
			err = n.Validate()
		}
		if e, ok := o.Lookup("error"); ok {
			if err == nil {
				t.Errorf("%s: Go ok, Python %s", rec.SourceKey, pyjson.Repr(e))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Go %v", rec.SourceKey, err)
			continue
		}
		got, _ := pyjson.Canonical(testutil.NormalizedValue(n))
		want, _ := pyjson.Canonical(o.Get("normalized"))
		if got != want {
			t.Errorf("%s:\n got  %s\n want %s", rec.SourceKey, got, want)
			continue
		}
		same++
	}
	t.Logf("%d records identical", same)
}
