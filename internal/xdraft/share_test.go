package xdraft

import (
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestShare: Share is Build for a draft stage; without one it is the same
// body without the stage code, T+ figure and sentence; it always fits one
// post with any link; hostile upstream text is cleaned as in a draft.
func TestShare(t *testing.T) {
	base := Input{CVE: "CVE-2026-12345", Days: ip(12), Title: "Widget RCE via upload", Source: "metasploit",
		Products: []Product{{"Acme", "Widget"}}}
	for _, st := range Stages {
		in := base
		in.Stage = st
		if Share(in) != Build(in) {
			t.Errorf("%s: share %q, build %q", st, Share(in), Build(in))
		}
	}
	for _, st := range []string{"", "disclosed", "patch_released", "bogus"} {
		in := base
		in.Stage = st
		if got, want := Share(in), "CVE-2026-12345\nAcme / Widget\nWidget RCE via upload"; got != want {
			t.Errorf("stage %q: %q, want %q", st, got, want)
		}
	}
	if got := Share(Input{CVE: "CVE-2026-1"}); got != "CVE-2026-1" {
		t.Errorf("bare: %q", got)
	}

	// always within the budget, with the longest link of any locale
	link := "https://www.nday.land/zh-hant/vuln/CVE-2026-1234567890123"
	long := strings.Repeat("漏洞 exploit chain ", 80)
	var many []Product
	for i := 0; i < 20; i++ {
		many = append(many, Product{strings.Repeat("Vendor", 10) + string(rune('A'+i)), strings.Repeat("产品", 40)})
	}
	for _, st := range append([]string{""}, Stages...) {
		for _, in := range []Input{
			{CVE: "CVE-2026-1234567890123", Stage: st, Days: ip(-12345), Title: long, Products: many, Source: "zz"},
			{CVE: "GHSA-aaaa-bbbb-cccc", Stage: st, Title: strings.Repeat("😀️", 300)},
			{CVE: "CVE-2026-1", Stage: st, Title: strings.Repeat("a.b ", 200), Products: many[:1]},
		} {
			body := Share(in)
			if n := WeightedLength(ComposeText(body, link)); n > MaxWeighted || !FitsWithLink(body) {
				t.Errorf("stage %q: %d weighted with the link: %q", st, n, body)
			}
		}
	}

	// hostile title and products: cleaned (no link, mention, tag, bidi)
	in := Input{CVE: "CVE-2026-2", Stage: "", Title: "see https://evil.example/a evil.com @admin #pwn $TSLA ‮gnp.exe⁦",
		Products: []Product{{"@vendor", "#prod.io"}}}
	body := Share(in)
	for _, bad := range []string{"https://", "evil.com", "@", "#pwn", "#prod", "$TSLA", "‮", "⁦"} {
		if strings.Contains(body, bad) {
			t.Errorf("share keeps %q: %q", bad, body)
		}
	}
	if Linkable(body) {
		t.Errorf("share is linkable: %q", body)
	}
}

// TestComposeTextURL: the text-only compose intent has the body as its
// only parameter, no url parameter and no link in the text.
func TestComposeTextURL(t *testing.T) {
	body := "CVE-2026-12345 +KEV T+3d\nAcme / Widget\nAdded to the CISA KEV catalog (known exploited)."
	u := ComposeTextURL(body)
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host != "x.com" || p.Path != "/intent/tweet" {
		t.Fatalf("%q %v", u, err)
	}
	q := p.Query()
	if len(q) != 1 || q.Get("text") != body || q.Has("url") {
		t.Errorf("query %v", q)
	}
	if strings.Contains(q.Get("text"), "nday.land") || strings.Contains(q.Get("text"), "https://") || Linkable(q.Get("text")) {
		t.Errorf("link in the text: %q", q.Get("text"))
	}
	if strings.ContainsAny(strings.TrimPrefix(u, ComposeBase+"?text="), " \n+") {
		t.Errorf("not encoded: %s", u)
	}
	// ComposeURL is unchanged: the same intent with "\n" + link
	if ComposeURL(body, "https://www.nday.land/vuln/CVE-2026-12345") != ComposeTextURL(body+"\nhttps://www.nday.land/vuln/CVE-2026-12345") {
		t.Error("ComposeURL changed")
	}
}

// TestFitsAlone: the text alone may use all of MaxWeighted; the budget with
// the link stays BodyBudget.
func TestFitsAlone(t *testing.T) {
	if BodyBudget != 256 || MaxWeighted != 280 {
		t.Fatalf("budgets %d %d", BodyBudget, MaxWeighted)
	}
	for _, c := range []struct {
		s           string
		alone, link bool
	}{
		{strings.Repeat("a", 256), true, true},
		{strings.Repeat("a", 257), true, false},
		{strings.Repeat("a", 280), true, false},
		{strings.Repeat("a", 281), false, false},
		{strings.Repeat("漏", 140), true, false},
		{strings.Repeat("漏", 141), false, false},
	} {
		if FitsAlone(c.s) != c.alone || FitsWithLink(c.s) != c.link {
			t.Errorf("%d runes: alone %v link %v", len([]rune(c.s)), FitsAlone(c.s), FitsWithLink(c.s))
		}
	}
}

func TestValidForm(t *testing.T) {
	for _, f := range []string{"link", "image", "image_reply"} {
		if !ValidForm(f) {
			t.Errorf("%q refused", f)
		}
	}
	for _, f := range []string{"", "Link", "image-reply", "video", " link"} {
		if ValidForm(f) {
			t.Errorf("%q accepted", f)
		}
	}
	if Forms[0] != FormLink {
		t.Error("the default form is not first")
	}
}

// TestCleanSigilRuns: no run of sigils leaves a live hashtag, cashtag or
// mention; a lone "#" and "$5" stay.
func TestCleanSigilRuns(t *testing.T) {
	for in, want := range map[string]string{
		"##tag":     "tag",
		"###a":      "a",
		"#＃#a":      "a",
		"＃#tag":     "tag",
		"$$TSLA":    "TSLA",
		"$＄$A":      "A",
		"#$TSLA":    "TSLA",
		"#_x":       "_x",
		"# #a":      "# a",
		"#":         "#",
		"a # b":     "a # b",
		"$5":        "$5",
		"$$5":       "$$5",
		"#$5":       "#$5",
		"@@a":       "[at][at]a",
		"#@a":       "#[at]a",
		"＠＠x":       "[at][at]x",
		"C# and F#": "C# and F#",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	s := Share(Input{CVE: "CVE-2026-3", Title: "##pwned $$TSLA", Products: []Product{{Vendor: "##acme"}}})
	if live.MatchString(s) {
		t.Errorf("share keeps a live tag: %q", s)
	}
}

// live: a sigil followed by what makes it a hashtag, cashtag or mention.
var live = regexp.MustCompile(`[#＃][\p{L}\p{N}\p{M}_]|[$＄][\p{L}\p{M}_]|[@＠]`)

// TestCleanSigilProperty: random strings over sigils, "_", a letter, a
// digit and a space never come out with a live tag.
func TestCleanSigilProperty(t *testing.T) {
	alpha := []rune{'#', '＃', '$', '＄', '@', '＠', '_', 'a', '1', ' '}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50000; i++ {
		r := make([]rune, 1+rng.Intn(12))
		for j := range r {
			r[j] = alpha[rng.Intn(len(alpha))]
		}
		if got := Clean(string(r)); live.MatchString(got) {
			t.Fatalf("Clean(%q) = %q", string(r), got)
		}
	}
}
