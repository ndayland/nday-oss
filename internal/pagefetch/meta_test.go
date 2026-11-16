package pagefetch

import (
	"strings"
	"testing"
)

func html200(body, charset string) *Page {
	return &Page{Status: 200, ContentType: "text/html", Charset: charset, Body: []byte(body)}
}

func TestExtractMeta(t *testing.T) {
	sl7 := `<html><head><meta charset="utf-8"><title>CVE-2026-20131: Cisco FMC RCE Vulnerability Exploited by Interlock - SecureLayer7 - Offensive Security, API Scanner &amp; Attack Surface Management</title>
<meta property="og:title" content="CVE-2026-20131: Cisco FMC RCE Vulnerability Exploited by Interlock - SecureLayer7 - Offensive Security, API Scanner &amp; Attack Surface Management" />
<meta property="og:site_name" content="SecureLayer7 - Offensive Security, API Scanner &amp; Attack Surface Management" /></head><body></body></html>`
	cases := []struct {
		name, body, charset, title, site string
	}{
		{"site name suffix (real page)", sl7, "", "CVE-2026-20131: Cisco FMC RCE Vulnerability Exploited by Interlock",
			"SecureLayer7 - Offensive Security, API Scanner & Attack Surface Management"},
		{"site name prefix", `<head><meta property="og:site_name" content="Example Blog"><title>example blog | Exploiting CVE-2026-1</title>`, "",
			"Exploiting CVE-2026-1", "Example Blog"},
		{"other separators", `<head><title>A deep dive  —   Example</title><meta name="og:site_name" content="Example">`, "", "A deep dive", "Example"},
		{"no og:site_name: unchanged", `<head><title>Exploiting CVE-2026-1 - Example Blog</title>`, "", "Exploiting CVE-2026-1 - Example Blog", ""},
		{"site name is the whole title: unchanged", `<head><title>Example Blog</title><meta property="og:site_name" content="Example Blog">`, "",
			"Example Blog", "Example Blog"},
		{"hyphen without spaces is not a separator", `<head><title>Pre-Example</title><meta property="og:site_name" content="Example">`, "",
			"Pre-Example", "Example"},
		{"og:title fallback", `<html><head><meta property="og:title" content="From OG &quot;quoted&quot;"></head><body><title>body title</title>`, "",
			`From OG "quoted"`, ""},
		{"first title, comments and scripts skipped",
			`<head><!-- <title>commented</title> --><script>var s = "<title>in script</title>";</script><title>Real</title><title>Second</title>`, "", "Real", ""},
		{"svg title in body ignored", `<head></head><body><svg><title>icon</title></svg>`, "", "", ""},
		{"charset from header (windows-1252)", "<head><title>Caf\xe9 \x93quoted\x94</title>", "windows-1252", "Café “quoted”", ""},
		{"charset from meta (shift_jis)", "<head><meta charset=\"Shift_JIS\"><title>\x83e\x83X\x83g</title>", "", "テスト", ""},
		{"utf-16 refused", "<head><title>x</title>", "utf-16le", "", ""},
		{"invalid utf-8 refused", "<head><title>bad \xff here</title>", "", "", ""},
		{"bot wall", `<head><title>Just a moment...</title>`, "", "", ""},
		{"bot wall falls back to og", `<head><title>Attention Required! | Cloudflare</title><meta property="og:title" content="Real one">`, "", "Real one", ""},
		{"error pages", `<head><title>404 Not Found</title>`, "", "", ""},
		{"sign in", `<head><title>Sign in - Google Accounts</title>`, "", "", ""},
		{"error word inside a real title", `<head><title>Error handling in the patch</title>`, "", "Error handling in the patch", ""},
		{"cleaning", "<head><title>\n  A\u202e\u200bB\u2066 \t C\u00ad\U000E0041 &amp;amp; D\u0007  </title>", "", "AB C &amp; D", ""},
		{"empty", `<head><title>  </title>`, "", "", ""},
	}
	for _, c := range cases {
		m := ExtractMeta(html200(c.body, c.charset))
		if m.Title != c.title || m.SiteName != c.site {
			t.Errorf("%s: got %q / %q, want %q / %q", c.name, m.Title, m.SiteName, c.title, c.site)
		}
	}
	long := strings.Repeat("word ", 40)
	m := ExtractMeta(html200("<title>"+long+"</title>", ""))
	if r := []rune(m.Title); len(r) != MaxTitle || r[len(r)-1] != '…' {
		t.Errorf("cut: %d runes %q", len(r), m.Title)
	}
	// site name stripped before the cut
	m = ExtractMeta(html200(`<meta property="og:site_name" content="Site"><title>`+strings.Repeat("a", 118)+` | Site</title>`, ""))
	if m.Title != strings.Repeat("a", 118) {
		t.Errorf("strip before cut: %q", m.Title)
	}
	for _, p := range []*Page{nil, {Status: 404, ContentType: "text/html", Body: []byte("<title>x</title>")},
		{Status: 200, ContentType: "application/json", Body: []byte("<title>x</title>")}} {
		if m := ExtractMeta(p); m != (Meta{}) {
			t.Errorf("non-HTML page: %+v", m)
		}
	}
}

func TestCleanTitle(t *testing.T) {
	for in, want := range map[string]string{
		"  plain  ":             "plain",
		"a\u200d\u200cb\ufeffc": "abc",
		"x\u2028y\u00a0z":       "x y z",
		"&lt;b&gt;":             "<b>",
		"CAPTCHA":               "",
		"Log in | Example":      "",
		"Are you a robot?":      "",
		"403 Forbidden":         "",
		"Access denied":         "",
		"Page not found – Blog": "",
	} {
		if got := CleanTitle(in, ""); got != want {
			t.Errorf("CleanTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExtractMetaHostile: no input panics; case-changing multi-byte runes
// (U+212A, U+0130) and invalid bytes before tags do not shift offsets.
func TestExtractMetaHostile(t *testing.T) {
	if m := ExtractMeta(html200(strings.Repeat("\u212a", 50)+"<meta property=og:title content=x><title>hello</title>", "")); m.Title != "hello" {
		t.Errorf("kelvin: %q", m.Title)
	}
	if m := ExtractMeta(html200(strings.Repeat("\u0130", 20)+"<title>Real</title><p>   <title>Fake</title>", "")); m.Title != "Real" {
		t.Errorf("dotted I: %q", m.Title)
	}
	if m := ExtractMeta(html200("\xff\xfe\xff<TITLE>Ok</TITLE>", "")); m.Title != "Ok" {
		t.Errorf("invalid bytes before the tag: %q", m.Title)
	}
	pieces := []string{"<", "<!--", "-->", "<title>", "</title>", "<title", "<meta property=\"og:title\" content=\"", "<meta ", "content='",
		"<script>", "</script", "<head>", "</head>", "<body>", "\u212a", "\u0130", "\xff", "\xc3", "\"", "'", ">", "=", "/", " ", "x", "\u212aTITLE", "<!", "</"}
	var inputs []string
	inputs = append(inputs, "", "<", "<<<<", "<title", "<title>", "<title>unclosed", "<!--", "<!-- <title>x</title>", "<meta content=\"x",
		"<meta property=og:title content='x", "<script>", "<script><title>x</title>", "<title>x</title", "\xff\xfe", "<\u212a>", "</")
	for i := range pieces {
		for j := range pieces {
			for k := range pieces {
				inputs = append(inputs, pieces[i]+pieces[j]+pieces[k], "\u0130"+pieces[i]+"\u212a"+pieces[j]+pieces[k]+"<title>t</title>")
			}
		}
	}
	for _, in := range inputs {
		for _, cs := range []string{"", "windows-1252", "shift_jis"} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on %q (%s): %v", in, cs, r)
					}
				}()
				ExtractMeta(html200(in, cs))
			}()
		}
	}
}

func TestInvisibleTitles(t *testing.T) {
	for _, in := range []string{"\u3164", "\u115f\u1160", "\uffa0 \u034f", "\u2800\u2800", "\u180e\u2060\u2061\u2062\u2063\u2064\ufeff", "...", "\u2013 | \u2013", "\u3164!\u3164"} {
		if got := CleanTitle(in, ""); got != "" {
			t.Errorf("CleanTitle(%q) = %q", in, got)
		}
	}
	if got := CleanTitle("A\u3164B\u2800C\u034fD\u2060E", ""); got != "ABCDE" {
		t.Errorf("stripped: %q", got)
	}
}
