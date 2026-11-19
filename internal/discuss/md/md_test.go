package md

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func cveLink(id string) string { return "/zh-hans/vuln/" + id }

var on = Options{Links: true, CVELink: cveLink}
var off = Options{Links: false, CVELink: cveLink}

const rel = ` rel="nofollow ugc noopener noreferrer"`

func TestRenderCases(t *testing.T) {
	cases := []struct {
		name, in, want string
		opt            *Options
	}{
		{"empty", "", "", nil},
		{"blank", " \n\t\n", "", nil},
		{"para", "hello", "<p>hello</p>\n", nil},
		{"two paras", "a\n\nb", "<p>a</p>\n<p>b</p>\n", nil},
		{"hard breaks", "a\nb  \n  c", "<p>a<br>\nb<br>\nc</p>\n", nil},
		{"crlf", "a\r\nb\rc", "<p>a<br>\nb<br>\nc</p>\n", nil},
		{"escape", `<script>alert("x")</script> & 'q'`, "<p>&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; &#39;q&#39;</p>\n", nil},
		{"html attr", `<img src=x onerror=alert(1)>`, "<p>&lt;img src=x onerror=alert(1)&gt;</p>\n", nil},
		{"em", "*a*", "<p><em>a</em></p>\n", nil},
		{"strong", "**a**", "<p><strong>a</strong></p>\n", nil},
		{"nested", "**a *b* c**", "<p><strong>a <em>b</em> c</strong></p>\n", nil},
		{"intraword", "2*3*4", "<p>2<em>3</em>4</p>\n", nil},
		{"spaced star", "a * b * c", "<p>a * b * c</p>\n", nil},
		{"unclosed em", "*a", "<p>*a</p>\n", nil},
		{"triple star literal", "***a***", "<p>***a***</p>\n", nil},
		{"mismatch", "*a **b* c**", "<p><em>a **b</em> c**</p>\n", nil},
		{"underscore", "_a_ snake_case", "<p>_a_ snake_case</p>\n", nil},
		{"code", "`a<b>`", "<p><code>a&lt;b&gt;</code></p>\n", nil},
		{"code double", "`` a`b ``", "<p><code>a`b</code></p>\n", nil},
		{"code no parse", "`*a* [x](http://e.com) CVE-2024-1234`", "<p><code>*a* [x](http://e.com) CVE-2024-1234</code></p>\n", nil},
		{"unmatched backticks", "``a`", "<p>``a`</p>\n", nil},
		{"backslash", `\*a\* \[x\] \\ \q`, `<p>*a* [x] \ \q</p>` + "\n", nil},
		{"fence", "```go\nif a < b {\n}\n```\nafter", "<pre><code>if a &lt; b {\n}\n</code></pre>\n<p>after</p>\n", nil},
		{"fence info ignored", "```\" onclick=x\nz\n```", "<pre><code>z\n</code></pre>\n", nil},
		{"fence unclosed", "```\na\n\nb", "<pre><code>a\n\nb\n</code></pre>\n", nil},
		{"fence longer close", "````\n```\n````", "<pre><code>```\n</code></pre>\n", nil},
		{"fence with backtick info", "``` a`b\nc", "<p>``` a`b<br>\nc</p>\n", nil},
		{"tilde not fence", "~~~\nx\n~~~", "<p>~~~<br>\nx<br>\n~~~</p>\n", nil},
		{"quote", "> a\n> b\n>\n> c", "<blockquote>\n<p>a<br>\nb</p>\n<p>c</p>\n</blockquote>\n", nil},
		{"quote nested is text", ">> a", "<blockquote>\n<p>&gt; a</p>\n</blockquote>\n", nil},
		{"quote empty", ">\n>", "", nil},
		{"ul", "- a\n- b\n* c", "<ul>\n<li>a</li>\n<li>b</li>\n<li>c</li>\n</ul>\n", nil},
		{"ul then ol", "- a\n1. b", "<ul>\n<li>a</li>\n</ul>\n<ol>\n<li>b</li>\n</ol>\n", nil},
		{"ol", "1. a\n2. b", "<ol>\n<li>a</li>\n<li>b</li>\n</ol>\n", nil},
		{"ol paren not list", "1) a", "<p>1) a</p>\n", nil},
		{"item continuation", "- a\n  more\n- b", "<ul>\n<li>a<br>\nmore</li>\n<li>b</li>\n</ul>\n", nil},
		{"nested list is text", "- a\n  - b", "<ul>\n<li>a<br>\n- b</li>\n</ul>\n", nil},
		{"list then para", "- a\nb", "<ul>\n<li>a</li>\n</ul>\n<p>b</p>\n", nil},
		{"para interrupted", "a\n- b", "<p>a</p>\n<ul>\n<li>b</li>\n</ul>\n", nil},
		{"year not list", "In\n2024. it was", "<p>In<br>\n2024. it was</p>\n", nil},
		{"empty item not list", "-\n- ", "<p>-<br>\n-</p>\n", nil},
		{"heading text", "# Title", "<p># Title</p>\n", nil},
		{"table text", "| a | b |\n|---|---|", "<p>| a | b |<br>\n|---|---|</p>\n", nil},
		{"image text", "![x](http://e.com/a.png)", `<p>!<a href="http://e.com/a.png"` + rel + `>x</a></p>` + "\n", nil},
		{"link", "[site](https://example.com/a?b=1&c=2)", `<p><a href="https://example.com/a?b=1&amp;c=2"` + rel + `>site</a></p>` + "\n", nil},
		{"link emphasis text", "[*a* `c`](http://e.com)", `<p><a href="http://e.com"` + rel + `><em>a</em> <code>c</code></a></p>` + "\n", nil},
		{"link text no cve", "[CVE-2024-1234](http://e.com)", `<p><a href="http://e.com"` + rel + `>CVE-2024-1234</a></p>` + "\n", nil},
		{"link empty text", "[](http://e.com)", `<p><a href="http://e.com"` + rel + `>http://e.com</a></p>` + "\n", nil},
		{"link upper scheme", "[x](HTTPS://E.com)", `<p><a href="https://E.com"` + rel + `>x</a></p>` + "\n", nil},
		{"link js", "[x](javascript:alert(1))", "<p>[x](javascript:alert(1))</p>\n", nil},
		{"link data", "[x](data:text/html,hi)", "<p>[x](data:text/html,hi)</p>\n", nil},
		{"link relative", "[x](/account)", "<p>[x](/account)</p>\n", nil},
		{"link protocol relative", "[x](//evil.com)", "<p>[x](//evil.com)</p>\n", nil},
		{"link credentials", "[x](https://user:pw@e.com)", "<p>[x](https://user:pw@e.com)</p>\n", nil},
		{"link no host", "[x](https:///p)", "<p>[x](https:///p)</p>\n", nil},
		{"link backslash", `[x](https:\\evil.com)`, `<p>[x](https:\evil.com)</p>` + "\n", nil},
		{"link non-ascii", "[x](https://例子.com)", "<p>[x](https://例子.com)</p>\n", nil},
		{"link quote", `[x](https://e.com/"onmouseover=x)`, `<p>[x](<a href="https://e.com/"` + rel + `>https://e.com/</a>&#34;onmouseover=x)</p>` + "\n", nil},
		{"link with space", "[x](https://e.com a)", `<p>[x](<a href="https://e.com"` + rel + `>https://e.com</a> a)</p>` + "\n", nil},
		{"autolink", "see https://e.com/x.", `<p>see <a href="https://e.com/x"` + rel + `>https://e.com/x</a>.</p>` + "\n", nil},
		{"autolink paren", "(https://en.wikipedia.org/wiki/A_(b))", `<p>(<a href="https://en.wikipedia.org/wiki/A_(b)"` + rel + `>https://en.wikipedia.org/wiki/A_(b)</a>)</p>` + "\n", nil},
		{"autolink cjk stop", "链接https://e.com，后面", `<p>链接<a href="https://e.com"` + rel + `>https://e.com</a>，后面</p>` + "\n", nil},
		{"autolink angle", "<https://e.com>", `<p>&lt;<a href="https://e.com"` + rel + `>https://e.com</a>&gt;</p>` + "\n", nil},
		{"autolink glued", "xhttps://e.com", "<p>xhttps://e.com</p>\n", nil},
		{"autolink star", "*https://e.com*", `<p><em><a href="https://e.com"` + rel + `>https://e.com</a></em></p>` + "\n", nil},
		{"not autolink scheme", "javascript:alert(1) ftp://x", "<p>javascript:alert(1) ftp://x</p>\n", nil},
		{"cve", "see cve-2024-12345, CVE-2024-1", `<p>see <a href="/zh-hans/vuln/CVE-2024-12345"` + rel + `>cve-2024-12345</a>, CVE-2024-1</p>` + "\n", nil},
		{"cve glued", "xCVE-2024-1234 CVE-2024-1234x /CVE-2024-1234 CVE-2024-1234_", "<p>xCVE-2024-1234 CVE-2024-1234x /CVE-2024-1234 CVE-2024-1234_</p>\n", nil},
		{"cve in url", "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", `<p><a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1234"` + rel + `>https://nvd.nist.gov/vuln/detail/CVE-2024-1234</a></p>` + "\n", nil},
		{"ghsa", "see ghsa-GPWC-27cw-rh9r, GHSA-gpwc-27cw-rh9", `<p>see <a href="/zh-hans/vuln/GHSA-gpwc-27cw-rh9r"` + rel + `>ghsa-GPWC-27cw-rh9r</a>, GHSA-gpwc-27cw-rh9</p>` + "\n", nil},
		{"ghsa glued", "xGHSA-gpwc-27cw-rh9r GHSA-gpwc-27cw-rh9rx /GHSA-gpwc-27cw-rh9r GHSA-gpwc-27cw-rh9r_ GHSA-aaaa-27cw-rh9r GHSAgpwc-27cw-rh9r", "<p>xGHSA-gpwc-27cw-rh9r GHSA-gpwc-27cw-rh9rx /GHSA-gpwc-27cw-rh9r GHSA-gpwc-27cw-rh9r_ GHSA-aaaa-27cw-rh9r GHSAgpwc-27cw-rh9r</p>\n", nil},
		{"ghsa in url", "https://github.com/advisories/GHSA-gpwc-27cw-rh9r", `<p><a href="https://github.com/advisories/GHSA-gpwc-27cw-rh9r"` + rel + `>https://github.com/advisories/GHSA-gpwc-27cw-rh9r</a></p>` + "\n", nil},
		{"ghsa cjk links off", "参见GHSA-gpwc-27cw-rh9r。", `<p>参见<a href="/zh-hans/vuln/GHSA-gpwc-27cw-rh9r"` + rel + `>GHSA-gpwc-27cw-rh9r</a>。</p>` + "\n", &off},
		{"ghsa end of text", "GHSA-gpwc-27cw-rh9", "<p>GHSA-gpwc-27cw-rh9</p>\n", nil},
		{"cve cjk", "参见CVE-2024-1234。", `<p>参见<a href="/zh-hans/vuln/CVE-2024-1234"` + rel + `>CVE-2024-1234</a>。</p>` + "\n", nil},
		{"links off link", "[x](https://e.com) https://e.com/y CVE-2024-1234", `<p>[x](https://e.com) https://e.com/y <a href="/zh-hans/vuln/CVE-2024-1234"` + rel + `>CVE-2024-1234</a></p>` + "\n", &off},
		{"links off emphasis kept", "*a* [**b**](http://e.com)", "<p><em>a</em> [<strong>b</strong>](http://e.com)</p>\n", &off},
		{"no cve link func", "CVE-2024-1234", "<p>CVE-2024-1234</p>\n", &Options{Links: true}},
		{"bad cve link func", "CVE-2024-1234", "<p>CVE-2024-1234</p>\n", &Options{Links: true, CVELink: func(string) string { return "javascript:x" }}},
		{"controls stripped", "a\x00b\x07c\x7f\u0085d", "<p>abcd</p>\n", nil},
		{"bidi stripped", "a‮b⁦c⁩d‏e", "<p>abcd‏e</p>\n", nil},
		{"invalid utf8", "a\xffb", "<p>a�b</p>\n", nil},
	}
	for _, c := range cases {
		opt := on
		if c.opt != nil {
			opt = *c.opt
		}
		got := Render(c.in, opt)
		if got != c.want {
			t.Errorf("%s: Render(%q)\n got  %q\n want %q", c.name, c.in, got, c.want)
		}
		if err := Validate(got); err != nil {
			t.Errorf("%s: output fails the allowlist: %v\n%s", c.name, err, got)
		}
	}
}

// Validate tokenises rendered HTML and fails on anything outside the
// allowlist: unknown tags or attributes, unbalanced or misnested tags, an
// href that is not http(s) or a generated site path, a rel other than Rel,
// raw "<", ">" or '"' in text, unknown entities, control or bidi characters.
func Validate(h string) error {
	allowed := map[string]bool{"p": true, "br": true, "pre": true, "code": true, "blockquote": true, "ul": true,
		"ol": true, "li": true, "em": true, "strong": true, "a": true}
	var stack []string
	for i := 0; i < len(h); {
		c := h[i]
		switch {
		case c == '<':
			j := strings.IndexByte(h[i:], '>')
			if j < 0 {
				return fmt.Errorf("unterminated tag at %d", i)
			}
			tag := h[i+1 : i+j]
			i += j + 1
			if strings.HasPrefix(tag, "/") {
				name := tag[1:]
				if !allowed[name] || name == "br" {
					return fmt.Errorf("closing tag %q", name)
				}
				if len(stack) == 0 || stack[len(stack)-1] != name {
					return fmt.Errorf("misnested </%s> (open: %v)", name, stack)
				}
				stack = stack[:len(stack)-1]
				continue
			}
			name, attrs, _ := strings.Cut(tag, " ")
			if !allowed[name] {
				return fmt.Errorf("tag %q not allowed", name)
			}
			if name == "a" {
				if err := checkAnchor(attrs); err != nil {
					return err
				}
				for _, o := range stack {
					if o == "a" {
						return errors.New("nested <a>")
					}
				}
			} else if attrs != "" || strings.ContainsAny(tag, "\"'=/") {
				return fmt.Errorf("attributes on <%s>: %q", name, tag)
			}
			if name != "br" {
				stack = append(stack, name)
			}
		case c == '>' || c == '"':
			return fmt.Errorf("raw %q in text at %d", c, i)
		case c == '&':
			j := strings.IndexByte(h[i:], ';')
			if j < 0 {
				return fmt.Errorf("bare & at %d", i)
			}
			switch h[i : i+j+1] {
			case "&amp;", "&lt;", "&gt;", "&#34;", "&#39;":
			default:
				return fmt.Errorf("entity %q", h[i:i+j+1])
			}
			i += j + 1
		default:
			r, n := utf8.DecodeRuneInString(h[i:])
			if r == utf8.RuneError && n == 1 {
				return fmt.Errorf("invalid UTF-8 at %d", i)
			}
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
				(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				return fmt.Errorf("control or bidi character %U at %d", r, i)
			}
			i += n
		}
	}
	if len(stack) > 0 {
		return fmt.Errorf("unclosed %v", stack)
	}
	return nil
}

func unescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'").Replace(s)
}

func checkAnchor(attrs string) error {
	const prefix = `href="`
	if !strings.HasPrefix(attrs, prefix) {
		return fmt.Errorf("<a %s>: href must come first", attrs)
	}
	rest := attrs[len(prefix):]
	q := strings.IndexByte(rest, '"')
	if q < 0 {
		return fmt.Errorf("<a %s>: unterminated href", attrs)
	}
	href, tail := unescape(rest[:q]), rest[q+1:]
	if tail != ` rel="`+Rel+`"` {
		return fmt.Errorf("<a %s>: attributes after href must be exactly rel", attrs)
	}
	low := strings.ToLower(href)
	for _, bad := range []string{"javascript:", "data:", "vbscript:"} {
		if strings.Contains(strings.Map(func(r rune) rune {
			if r <= ' ' {
				return -1
			}
			return r
		}, low), bad) && !strings.HasPrefix(low, "http") {
			return fmt.Errorf("dangerous href %q", href)
		}
	}
	switch {
	case strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://"):
		if _, ok := SafeURL(href); !ok {
			return fmt.Errorf("href %q does not pass SafeURL", href)
		}
	case SafePath(href):
	default:
		return fmt.Errorf("href %q is neither http(s) nor a generated path", href)
	}
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "vbscript:") {
		return fmt.Errorf("dangerous href %q", href)
	}
	return nil
}

func TestValidatorRejects(t *testing.T) {
	for _, h := range []string{
		"<p>", "</p>", "<p><em></p></em>", "<div>x</div>", "<p class=\"x\">x</p>", "<img src=x>",
		`<a href="javascript:alert(1)" rel="` + Rel + `">x</a>`,
		`<a href="data:text/html,x" rel="` + Rel + `">x</a>`,
		`<a href="//evil.com" rel="` + Rel + `">x</a>`,
		`<a href="https://e.com" rel="noopener">x</a>`,
		`<a href="https://e.com" rel="` + Rel + `" onclick="x">x</a>`,
		`<a href="https://e.com" rel="` + Rel + `"><a href="https://e.com" rel="` + Rel + `">x</a></a>`,
		"a > b", `a " b`, "&nbsp;", "a‮b", "a\x00b", "<br/>",
	} {
		if Validate(h) == nil {
			t.Errorf("Validate accepted %q", h)
		}
	}
}

func TestSafeURL(t *testing.T) {
	good := []string{"http://a", "https://example.com/p?q=1#f", "HTTP://X.ORG", "https://e.com:8443/"}
	bad := []string{"", "javascript:alert(1)", "JaVaScRiPt:x", "data:x", "vbscript:x", "ftp://x", "http:x",
		"http://", "https://user@x", "https://u:p@x", "https://x y", "https://x\ty", "https://x\n", "http://x\\y",
		"//x", "/x", "https://例子.com", "https://x/\"", "https://x/<", "https://x/`", "http://[::1", "https:///x",
		"https://" + strings.Repeat("a", MaxURLLen)}
	for _, u := range good {
		if _, ok := SafeURL(u); !ok {
			t.Errorf("SafeURL(%q) refused", u)
		}
	}
	for _, u := range bad {
		if got, ok := SafeURL(u); ok {
			t.Errorf("SafeURL(%q) accepted: %q", u, got)
		}
	}
}

func TestSafePath(t *testing.T) {
	for _, p := range []string{"/vuln/CVE-2024-1", "/zh-hans/vuln/CVE-2024-1"} {
		if !SafePath(p) {
			t.Errorf("SafePath(%q) = false", p)
		}
	}
	for _, p := range []string{"", "/", "//e.com", "vuln/x", "/a/../b", "/a/./b", "/a?b", "/a#b", "/a b", "/a\"b",
		"javascript:x", "/" + strings.Repeat("a", MaxPathLen)} {
		if SafePath(p) {
			t.Errorf("SafePath(%q) = true", p)
		}
	}
}

func TestClean(t *testing.T) {
	in := "a\r\nb\rc\x00\x01\x1b\x7f\u0080\u009f‪‫‬‭‮⁦⁧⁨⁩￾￿‎‏؜\t\xc3"
	want := "a\nb\nc‎‏؜\t�"
	if got := Clean(in); got != want {
		t.Errorf("Clean = %q, want %q", got, want)
	}
}

// pathological inputs: each must render in linear time and validate.
func pathological(n int) map[string]string {
	return map[string]string{
		"backticks":       strings.Repeat("`", n),
		"backtick runs":   strings.Repeat("` ``", n/4),
		"backtick lines":  strings.Repeat("```\n", n/4),
		"brackets":        strings.Repeat("[", n),
		"bracket pairs":   strings.Repeat("[a](", n/4),
		"link no close":   strings.Repeat("[a](http://e.com/", n/17),
		"stars":           strings.Repeat("*", n),
		"star words":      strings.Repeat("*a ", n/3),
		"strong openers":  strings.Repeat("**a ", n/8) + strings.Repeat("a* ", n/6),
		"alternate":       strings.Repeat("*a**b", n/5),
		"long line":       strings.Repeat("a", n),
		"parens url":      "http://e.com/" + strings.Repeat(")", n),
		"long url":        "https://e.com/" + strings.Repeat("a", n),
		"urls":            strings.Repeat("http://a ", n/9),
		"cves":            strings.Repeat("CVE-2024-1234 ", n/14),
		"cve digits":      "CVE-2024-" + strings.Repeat("1", n),
		"ghsas":           strings.Repeat("GHSA-gpwc-27cw-rh9r ", n/20),
		"ghsa prefixes":   strings.Repeat("GHSA-gpwc-27cw-", n/15),
		"quotes":          strings.Repeat("> a\n", n/4),
		"nested quotes":   strings.Repeat(">", n),
		"lists":           strings.Repeat("- a\n", n/4),
		"nested lists":    strings.Repeat("  - a\n", n/6),
		"blank lines":     strings.Repeat("\n", n),
		"nul":             strings.Repeat("\x00", n),
		"bidi":            strings.Repeat("‮", n/3),
		"invalid utf8":    strings.Repeat("\xff", n),
		"escapes":         strings.Repeat(`\`, n),
		"amp":             strings.Repeat("&", n),
		"mixed":           strings.Repeat("*[`>-1. h C\\", n/12),
		"unclosed fences": strings.Repeat("````\n```\n", n/9),
	}
}

func TestPathologicalLinear(t *testing.T) {
	const small, big = 10000, 100000
	for name, in := range pathological(small) {
		out := Render(in, on)
		if err := Validate(out); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(out) > MaxExpansion*len(in)+64 {
			t.Errorf("%s: output %d bytes for %d input bytes", name, len(out), len(in))
		}
	}
	bigIn := pathological(big)
	for name, in := range pathological(small) {
		d1 := timeRender(in)
		d2 := timeRender(bigIn[name])
		// 10x the input: a linear renderer takes ~10x; allow 40x for noise
		if d2 > 40*d1+20*time.Millisecond {
			t.Errorf("%s: %v for %d bytes, %v for %d bytes (not linear)", name, d1, len(in), d2, len(bigIn[name]))
		}
	}
}

func timeRender(in string) time.Duration {
	best := time.Hour
	for k := 0; k < 3; k++ {
		start := time.Now()
		Render(in, on)
		Render(in, off)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}

func BenchmarkRender10k(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 10000 {
		sb.WriteString("Patch for CVE-2024-3094 is out, see https://example.com/advisory?id=1&x=2 and [the diff](https://github.com/x/y/commit/abc).\n" +
			"- *first* item with `code`\n- **second** item\n\n> quoted line\n> another\n\n```\nfn main() { println!(\"<hi>\"); }\n```\n\n")
	}
	in := sb.String()[:10000]
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Render(in, on)
	}
}

func BenchmarkRender10kPathological(b *testing.B) {
	in := strings.Repeat("*[`a](h", 10000/7)
	b.SetBytes(int64(len(in)))
	for i := 0; i < b.N; i++ {
		Render(in, on)
	}
}

// The number of CVE links per document is capped.
// TestNewTab: Options.NewTab adds target="_blank" to the absolute links it
// accepts, never to site paths; without it there is no target.
func TestNewTab(t *testing.T) {
	o := on
	o.NewTab = func(href string) bool { return !strings.HasPrefix(href, "https://www.nday.land/") }
	in := "[a](https://e.com/x) https://f.com/y https://www.nday.land/about CVE-2026-1234"
	want := `<p><a href="https://e.com/x"` + rel + ` target="_blank">a</a> <a href="https://f.com/y"` + rel +
		` target="_blank">https://f.com/y</a> <a href="https://www.nday.land/about"` + rel + `>https://www.nday.land/about</a> <a href="/zh-hans/vuln/CVE-2026-1234"` +
		rel + `>CVE-2026-1234</a></p>` + "\n"
	if got := Render(in, o); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got := Render(in, on); strings.Contains(got, "target") {
		t.Errorf("target without NewTab: %q", got)
	}
}

func TestCVELinkCap(t *testing.T) {
	in := strings.Repeat("CVE-0000-0000 ", 714)
	out := Render(in, on)
	if n := strings.Count(out, "<a "); n != MaxCVELinks {
		t.Errorf("%d CVE links, want %d", n, MaxCVELinks)
	}
	// CVE and GHSA ids share the cap
	mixed := Render(strings.Repeat("CVE-0000-0000 GHSA-gpwc-27cw-rh9r ", 40), on)
	if n := strings.Count(mixed, "<a "); n != MaxCVELinks || !strings.Contains(mixed, "/vuln/GHSA-gpwc-27cw-rh9r") {
		t.Errorf("mixed: %d links, want %d", n, MaxCVELinks)
	}
	if len(out) > 20000 {
		t.Errorf("%d bytes for %d", len(out), len(in))
	}
}

func TestCleanInvisible(t *testing.T) {
	cases := map[string]string{
		"a\u200bb\u2060c\ufeffd\u00ade\u3164f\u115fg\u1160h\u180ei\U000E0041j\U000E007Fk": "abcdefghijk",
		"zwj\u200d\u200ckept":                    "zwj\u200d\u200ckept",
		"a\n\u200d \u200c\n\n\n\n\nb":            "a\n\n\nb",
		"e\u0301\u0302\u0303\u0304\u0305\u0306x": "e\u0301\u0302\u0303\u0304x",
		"a\n \t\n":                               "a\n\n",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
		if again := Clean(Clean(in)); again != Clean(in) {
			t.Errorf("Clean not idempotent on %q", in)
		}
	}
	for _, in := range []string{"a\n\u200d\nb\n\u200c\nc", "x\n\n\n\n\n\ny", "a\nb\nc\nd"} {
		if out := Render(in, on); strings.Contains(out, "<br>\n<br>\n<br>") {
			t.Errorf("Render(%q) = %q has 3 consecutive <br>", in, out)
		}
	}
}
