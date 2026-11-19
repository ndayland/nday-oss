package md

import (
	"strings"
	"testing"
	"time"
)

var fuzzSeeds = []string{
	"", "a", "*a* **b** `c` [d](https://e.com) https://f.com CVE-2024-1234 GHSA-gpwc-27cw-rh9r",
	"```\ncode\n```", "> q\n> r", "- a\n- b\n1. c", "[x](javascript:alert(1))", "[x](JAVASCRIPT:alert(1))",
	"[x](java\tscript:x)", "[x](https://a@b)", "<script>", "\x00\u202e\xff", strings.Repeat("`", 300),
	strings.Repeat("[", 300), strings.Repeat("*", 300), "http://a)))", "[a](http://b) [c](d)",
	"&#106;avascript:x", "[x](&#106;avascript:alert(1))", "[x](%6Aavascript:x)", "[x](data:text/html;base64,PHM+)",
}

// checkOutput asserts the properties every rendering must have.
func checkOutput(t *testing.T, in string, opt Options) {
	start := time.Now()
	out := Render(in, opt)
	d := time.Since(start)
	if err := Validate(out); err != nil {
		t.Fatalf("Render(%q) = %q: %v", in, out, err)
	}
	// the node tree of the output (body_nodes) always exists and says the same
	nodes, err := Nodes(out)
	if err != nil {
		t.Fatalf("Nodes(Render(%q) = %q): %v", in, out, err)
	}
	if back := serialize(nodes); back != out {
		t.Fatalf("Nodes(%q) serializes back to %q", out, back)
	}
	if len(out) > MaxExpansion*len(in)+64 {
		t.Fatalf("Render(%q): %d output bytes for %d input bytes", in, len(out), len(in))
	}
	if strings.Contains(out, "<br>\n<br>\n<br>") {
		t.Fatalf("Render(%q) has 3 consecutive <br>: %q", in, out)
	}
	if c := Clean(in); Clean(c) != c {
		t.Fatalf("Clean not idempotent on %q: %q -> %q", in, c, Clean(c))
	}
	if n := strings.Count(out, `href="/`); n > MaxCVELinks {
		t.Fatalf("Render(%q): %d CVE links", in, n)
	}
	low := strings.ToLower(out)
	for _, bad := range []string{"<script", "<img", "<iframe", "<svg", "<style", "style=", "onerror=", "src="} {
		if strings.Contains(low, bad) {
			t.Fatalf("Render(%q) contains %q: %s", in, bad, out)
		}
	}
	// every href, decoded, in any case and without whitespace/controls
	for rest := out; ; {
		k := strings.Index(rest, `href="`)
		if k < 0 {
			break
		}
		rest = rest[k+len(`href="`):]
		e := strings.IndexByte(rest, '"')
		href := strings.ToLower(strings.Map(func(r rune) rune {
			if r <= ' ' || r == 0x7f {
				return -1
			}
			return r
		}, unescape(rest[:e])))
		for _, bad := range []string{"javascript:", "data:", "vbscript:", "&#", "%6a", "\\"} {
			if strings.Contains(href, bad) && !strings.HasPrefix(href, "http") {
				t.Fatalf("Render(%q): href %q", in, href)
			}
		}
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") && !(strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//")) {
			t.Fatalf("Render(%q): href %q is neither http(s) nor a site path", in, href)
		}
	}
	// time bound: generous fixed part (scheduler noise) + 2 µs per byte
	if limit := 100*time.Millisecond + time.Duration(len(in))*2*time.Microsecond; d > limit {
		t.Fatalf("Render took %v for %d bytes (limit %v)", d, len(in), limit)
	}
}

func FuzzRender(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		checkOutput(t, in, on)
		checkOutput(t, in, off)
		checkOutput(t, in, Options{Links: true})
	})
}

// FuzzRenderBlocks builds inputs out of Markdown-significant fragments, so
// the fuzzer reaches deep structure quickly.
func FuzzRenderBlocks(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, "x")
	frags := []string{"\n", "\n\n", "```", "`", "> ", "- ", "* ", "1. ", "*", "**", "[", "]", "(", ")", "](",
		"https://", "http://e.com", "CVE-2024-1234", "\\", "<", "&", "\"", "  ", "\t", "javascript:", "data:",
		"\u202e", "\x00", "\r", "e.com/", "@", "a", "中", "\u200d", "\u200b", "\u0301", "\U000E0041", "\n \n",
		"GHSA-gpwc-27cw-rh9r", "ghsa-"}
	f.Fuzz(func(t *testing.T, picks []byte, filler string) {
		var b strings.Builder
		for _, p := range picks {
			if int(p) < len(frags) {
				b.WriteString(frags[p])
			} else {
				b.WriteString(filler)
			}
		}
		in := b.String()
		checkOutput(t, in, on)
		checkOutput(t, in, off)
	})
}

func FuzzSafeURL(f *testing.F) {
	for _, s := range []string{"https://e.com", "javascript:x", "http://a@b", "HTTPS://X", "http://\\x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, ok := SafeURL(raw)
		if !ok {
			return
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			t.Fatalf("SafeURL(%q) = %q", raw, u)
		}
		for i := 0; i < len(u); i++ {
			if c := u[i]; c <= ' ' || c >= 0x7f || strings.IndexByte("\"<>\\`", c) >= 0 {
				t.Fatalf("SafeURL(%q) = %q contains %q", raw, u, c)
			}
		}
	})
}

// serialize writes a node tree back in Render's form.
func serialize(nodes []any) string {
	var b strings.Builder
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	var walk func([]any)
	walk = func(ns []any) {
		for _, n := range ns {
			switch v := n.(type) {
			case string:
				b.WriteString(esc.Replace(v))
			case *Elem:
				if v.E == "a" {
					b.WriteString(`<a href="` + esc.Replace(v.Href) + `" rel="` + Rel + `">`)
				} else {
					b.WriteString("<" + v.E + ">")
				}
				if v.E == "br" {
					continue
				}
				walk(v.C)
				b.WriteString("</" + v.E + ">")
			}
		}
	}
	walk(nodes)
	return b.String()
}

func TestNodesRejects(t *testing.T) {
	for _, h := range []string{"<p>", "</p>", "<div>x</div>", `<p class="x">x</p>`, `<a href="javascript:x" rel="` + Rel + `">x</a>`,
		`<a href="https://e.com">x</a>`, "a & b", "&nbsp;", `say "x"`, "<p><em></p></em>"} {
		if _, err := Nodes(h); err == nil {
			t.Errorf("Nodes(%q) accepted", h)
		}
	}
}
