package xdraft

import (
	"net/url"
	"strings"
	"testing"
	"unicode"
)

func ip(n int) *int { return &n }

func TestWeightedLength(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"", 0},
		{"hello world", 11},
		{strings.Repeat("a", 280), 280},
		{"漏洞", 4}, // CJK: 2 each
		{"日本語のテキスト", 16},
		{"한국어", 6},
		{"e\u0301", 1},      // NFC: é, one light code point
		{"\u2014\u2019", 2}, // em dash, right quote: light ranges 8208-8223
		{"\u2026", 2},       // … (8230) is outside the light ranges
		{"©", 2},            // an emoji in the light range
		{"😀", 2},
		{"👍🏽", 4},  // X: 2 (one sequence); counted per code point: never less
		{"👩‍💻", 5}, // 2 + ZWJ 1 + 2
		{"🇯🇵", 4},  // X: 2
		{"1️⃣", 5}, // 1 + 2 + 2; X: 2
		{"https://example.com/a/very/long/path/that/is/longer/than/23", 23}, // a sure link
		{"see https://nday.land/vuln/CVE-2026-1234 now", 4 + 23 + 4},
		{"https://x.co", 23},
		{"example.com", 11 + 19}, // a bare host: literal + the surcharge of its dot
		{"a-very-long-subdomain-name.example.org", 38 + 2*19},
		{"Node.js", 7 + 19},
		{"v1.2.3", 6}, // dots before digits never end a domain name
		{"Apache 2.4.1", 12},
		{"\xff", 2},
	} {
		if got := WeightedLength(c.in); got != c.want {
			t.Errorf("WeightedLength(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	if !FitsWithLink(strings.Repeat("a", BodyBudget)) || FitsWithLink(strings.Repeat("a", BodyBudget+1)) {
		t.Error("FitsWithLink boundary")
	}
	if BodyBudget != 256 {
		t.Errorf("BodyBudget %d", BodyBudget)
	}
}

// TestWeightedLengthNeverUnder: inputs that an emoji-grouping or URL-greedy
// count got below twitter-text v3. got must be >= the value X gives (worked
// out from the v3 rules: x), and is pinned to this package's exact count.
func TestWeightedLengthNeverUnder(t *testing.T) {
	smile := "😀"
	for _, c := range []struct {
		name    string
		in      string
		x, want int
	}{
		// X: "😀\uFE0F" is one emoji (2), every further selector 2
		{"200 variation selectors", smile + strings.Repeat("\uFE0F", 200), 2 + 199*2, 2 + 200*2},
		// X: "😀🏻" one emoji (2), every further modifier an emoji (2)
		{"150 skin tones", smile + strings.Repeat("\U0001F3FB", 150), 2 + 149*2, 2 + 150*2},
		// X: at most 2 per tag character after the emoji
		{"200 tag characters", smile + strings.Repeat("\U000E0061", 200), 2 + 200*2, 2 + 200*2},
		// X: one ZWJ sequence counts 2 (at most 2 per emoji + 1 per joiner)
		{"100 joined emoji", strings.Repeat(smile+"\u200D", 100) + smile, 101*2 + 100, 101*2 + 100},
		// X: "#" before the scheme: no link, all literal (1 + 20 + 300)
		{"hash before a URL", "#https://example.com/" + strings.Repeat("a", 300), 321, 321 + 19},
		// X: the link stops before the CJK text: 23 + 130*2
		{"CJK after a URL", "https://example.com/" + strings.Repeat("中", 130), 23 + 260, 23 + 260},
		// X: the link stops at the quote: 23 + 1 + 300
		{"quote in a URL", "https://example.com/a\"" + strings.Repeat("b", 300), 23 + 301, 23 + 301},
		// X: the link stops at "(": "(https://a.co)" may be linked after "(" -> 1 + 23 + 1
		{"parenthesised URL", "(https://a.co)", 25, 14 + 19},
	} {
		got := WeightedLength(c.in)
		if got < c.x || got != c.want {
			t.Errorf("%s: %d (X %d, want %d)", c.name, got, c.x, c.want)
		}
	}
}

func TestProductLine(t *testing.T) {
	for _, c := range []struct {
		in   []Product
		want string
	}{
		{nil, ""},
		{[]Product{{"Fortinet", "Fortinet"}}, "Fortinet"},
		{[]Product{{"Fortinet", "Fortinet FortiOS"}}, "Fortinet / FortiOS"},
		{[]Product{{"Microsoft", "Windows"}, {"microsoft", "Windows Server"}}, "Microsoft / Windows, Windows Server"},
		{[]Product{{"Apache", "Tomcat"}, {"Apache", "tomcat"}}, "Apache / Tomcat"},
		{[]Product{{"a", "b"}, {"c", "d"}, {"e", "f"}, {"g", "h"}, {"i", "j"}}, "a / b · c / d · e / f +2"},
		{[]Product{{"n/a", "n/a"}, {"-", "*"}, {"Acme", "Widget"}}, "Acme / Widget"},
		{[]Product{{"@evil", "https://evil.example/x"}}, "[at]evil"},
	} {
		if got := ProductLine(c.in); got != c.want {
			t.Errorf("ProductLine(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClean(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"  Remote\ncode\texecution  ", "Remote code execution"},
		{"@nday ping @elonmusk", "[at]nday ping [at]elonmusk"},
		{"＠fullwidth", "[at]fullwidth"},
		{"see https://evil.example/pwn now", "see now"},
		{"evil.com/pwn and example.org", "evil[.]com/pwn and example[.]org"},
		{"ASP.NET Core flaw", "ASP[.]NET Core flaw"},
		{"#hashtag #1 ＃tag $AAPL $5", "hashtag 1 tag AAPL $5"},
		{"<script>alert(1)</script>", "<script>alert(1)</script>"}, // plain text; the page escapes it
		{"a\u202eb\u200bc\x00d", "abcd"},
		{"javascript://x", ""},
		// hosts after any character, non-ASCII hosts and TLDs, hashtags with digits
		{"see 中evil.com now", "see 中evil[.]com now"},
		{"see дevil.com/login now", "see дevil[.]com/login now"},
		{"see x_y.evil.com now", "see x_y[.]evil[.]com now"},
		{"see évil.com", "see évil[.]com"},
		{"visit exämple.com now", "visit exämple[.]com now"},
		{"visit evil.みんな now", "visit evil[.]みんな now"},
		{"see evil.рф now", "see evil[.]рф now"},
		{"see #1day and #0click", "see 1day and 0click"},
		{"a。b．c｡d", "a[.]b[.]c[.]d"},
		{"x.#y", "x[.]y"}, // a dropped "#" cannot join a host
		{"Apache 2.4.1 and v1.2", "Apache 2.4.1 and v1.2"},
		{"👍🏽❤️ 1️⃣", "👍❤ 1"}, // emoji modifiers removed
		{"中https://evil.com/x", "中"},
	} {
		got := Clean(c.in)
		if got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
		if Linkable(got) {
			t.Errorf("Clean(%q) = %q is linkable", c.in, got)
		}
	}
	for _, s := range []string{"evil.com", "中evil.com", "https://nday.land", "a.рф"} {
		if !Linkable(s) {
			t.Errorf("Linkable(%q) = false", s)
		}
	}
}

// hostile checks every body the builder can make: within budget, no
// mention, hashtag, cashtag, link or control character.
func hostile(t *testing.T, body string) {
	t.Helper()
	if n := WeightedLength(body); n > BodyBudget {
		t.Errorf("body weighs %d > %d:\n%s", n, BodyBudget, body)
	}
	if strings.ContainsAny(body, "@＠＃#$") {
		for i, r := range []rune(body) {
			if (r == '@' || r == '＠') || ((r == '#' || r == '＃' || r == '$') && i+1 < len([]rune(body)) && unicode.IsLetter([]rune(body)[i+1])) {
				t.Errorf("mention/hashtag/cashtag in %q", body)
				break
			}
		}
	}
	if Linkable(body) {
		t.Errorf("linkable text in %q", body)
	}
	for _, r := range body {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Errorf("control %U in %q", r, body)
		}
	}
}

func TestBuild(t *testing.T) {
	b := Build(Input{CVE: "CVE-2026-1234", Stage: "kev_added", Days: ip(12), Title: "Windows SMB Client Elevation of Privilege",
		Products: []Product{{"Microsoft", "Microsoft Windows"}}, Source: "kev"})
	want := "CVE-2026-1234 +KEV T+12d\nMicrosoft / Windows\nWindows SMB Client Elevation of Privilege\nAdded to the CISA KEV catalog (known exploited)."
	if b != want {
		t.Errorf("Build:\n%s\nwant\n%s", b, want)
	}
	hostile(t, b)
	b = Build(Input{CVE: "CVE-2026-1", Stage: "poc_published", Source: "metasploit"})
	if b != "CVE-2026-1 +POC\nPublic PoC available: Metasploit module." {
		t.Errorf("minimal: %q", b)
	}
	b = Build(Input{CVE: "CVE-2026-1", Stage: "exploited_in_wild", Days: ip(-3), Source: "Some Feed\n@x"})
	if b != "CVE-2026-1 +ITW T-3d\nExploitation in the wild reported (source: unknown)." {
		t.Errorf("itw: %q", b)
	}
	b = Build(Input{CVE: "CVE-2026-1", Stage: "poc_published", Source: "ghsa"})
	if !strings.HasSuffix(b, "Public PoC available (source: ghsa).") {
		t.Errorf("poc other: %q", b)
	}
	// hostile and long titles always fit, the title is cut first
	long := strings.Repeat("overflow ", 400)
	cjk := strings.Repeat("远程代码执行漏洞", 100)
	emoji := strings.Repeat("💥🔥👩‍💻", 100)
	links := strings.Repeat("http://a.example/x evil.com/y @user #tag ", 40)
	bidi := "safe\u202etxt.exe \u2066hidden\u2069 " + strings.Repeat("x", 300)
	prods := []Product{}
	for i := 0; i < 40; i++ {
		prods = append(prods, Product{strings.Repeat("Vendor", 10), strings.Repeat("产品", 50)})
	}
	for _, title := range []string{long, cjk, emoji, links, bidi, "", "<img src=x onerror=alert(1)>",
		"Update now at 中secure-update.com/patch", "see 中evil.com, x_y.evil.com, evil.みんな #1day $AAPL"} {
		for _, ps := range [][]Product{nil, prods, {{"@admin", "#root"}}} {
			for _, st := range Stages {
				b := Build(Input{CVE: "CVE-2026-99999999", Stage: st, Days: ip(12345), Title: title, Products: ps, Source: "exploitdb"})
				hostile(t, b)
				if !strings.HasPrefix(b, "CVE-2026-99999999 +") {
					t.Errorf("head lost: %q", b)
				}
			}
		}
	}
	b = Build(Input{CVE: "CVE-2026-1", Stage: "kev_added", Title: "Update now at 中secure-update.com/patch"})
	if !strings.Contains(b, "中secure-update[.]com/patch") || Linkable(b) {
		t.Errorf("hostile host: %q", b)
	}
	// a long title is cut with an ellipsis, not dropped
	b = Build(Input{CVE: "CVE-2026-1", Stage: "kev_added", Title: long})
	if !strings.Contains(b, "overflow overflow") || !strings.Contains(b, "…") {
		t.Errorf("long title: %q", b)
	}
}

func TestNormalizePostURL(t *testing.T) {
	ok := map[string]string{
		"https://x.com/ndayland/status/1857000000000000001":         "https://x.com/ndayland/status/1857000000000000001",
		"https://twitter.com/ndayland/status/123":                   "https://x.com/ndayland/status/123",
		"https://www.x.com/nday_land/status/123/":                   "https://x.com/nday_land/status/123",
		"https://mobile.twitter.com/ndayland/status/123?s=20&t=abc": "https://x.com/ndayland/status/123",
		"  https://x.com/ndayland/status/123#frag ":                 "https://x.com/ndayland/status/123",
	}
	for in, want := range ok {
		if got, good := NormalizePostURL(in); !good || got != want {
			t.Errorf("NormalizePostURL(%q) = %q %v, want %q", in, got, good, want)
		}
	}
	for _, in := range []string{"", "http://x.com/a/status/1", "https://x.com.evil.example/a/status/1", "https://evil.example/x.com/a/status/1",
		"https://x.com/a/status/abc", "https://x.com/i/status/1", "https://x.com/a/status/0", "https://x.com/abcdefghijklmnop/status/1",
		"https://x.com/a/status/1/photo/1", "javascript:alert(1)", "https://x.com/a b/status/1", "https://x.com/a/status/123456789012345678901",
		"https://user@x.com/a/status/1", "https://x.com/a/status/0123", "https://x.com/a/status/00", "https://x.com/a/status/1?a b",
		"https://x.com/a/status/1#x y"} {
		if got, good := NormalizePostURL(in); good {
			t.Errorf("NormalizePostURL(%q) accepted: %q", in, got)
		}
	}
}

func TestComposeURL(t *testing.T) {
	body := "CVE-2026-1 +KEV T+0d\nA & B = 100% \"quoted\" #x?"
	link := "https://www.nday.land/vuln/CVE-2026-1"
	u := ComposeURL(body, link)
	if !strings.HasPrefix(u, "https://x.com/intent/tweet?text=") {
		t.Fatalf("base: %s", u)
	}
	if strings.ContainsAny(strings.TrimPrefix(u, "https://x.com/intent/tweet?text="), " \n&#+\"") {
		t.Errorf("not fully encoded: %s", u)
	}
	p, err := url.Parse(u)
	if err != nil || p.Host != "x.com" || p.Path != "/intent/tweet" || len(p.Query()) != 1 || p.Query().Get("text") != body+"\n"+link {
		t.Errorf("decoded %v %v %q", err, p, p.Query().Get("text"))
	}
	if !strings.Contains(u, "%20") || !strings.Contains(u, "%0A") {
		t.Errorf("spaces/newlines: %s", u)
	}
}
