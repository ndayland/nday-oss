package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"nday.land/nday/internal/testutil"
)

func TestClassify(t *testing.T) {
	const www, api = "www.nday.land", "api.nday.land"
	tests := []struct {
		domain, method, uri string
		status              int
		want                Class
	}{
		{www, "GET", "/", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "home", Locale: "en"}},
		{www, "GET", "/hot?since=7d", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "home", Locale: "en"}},
		{www, "GET", "/zh-hans/", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "home", Locale: "zh-hans"}},
		{www, "GET", "/zh-hans", 301, Class{Kind: "redirect", BaseKind: "page", PageKind: "home", Locale: "zh-hans"}},
		{www, "GET", "/fr/hot", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "home", Locale: "fr"}},
		{www, "GET", "/vuln", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "vuln_list", Locale: "en"}},
		{www, "GET", "/vuln?q=%20Log4J%0A", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "vuln_list", Locale: "en", Search: "log4j"}},
		{www, "GET", "/vuln?q=CVE-2024-3094", 302, Class{Kind: "redirect", BaseKind: "page", PageKind: "vuln_list", Locale: "en"}},
		{www, "GET", "/ja/vuln/cve-2024-3094", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "vuln", Locale: "ja", CVE: "CVE-2024-3094"}},
		{www, "GET", "/vuln/CVE-2024-3094", 404, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "vuln", Locale: "en"}},
		{www, "GET", "/vuln/NOPE", 400, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "vuln", Locale: "en"}},
		{www, "GET", "/stats", 304, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "stats", Locale: "en"}},
		{www, "GET", "/vuln/CVE-2024-3094", 304, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "vuln", Locale: "en", CVE: "CVE-2024-3094"}},
		{www, "GET", "/static/app.css", 304, Class{Kind: "static", BaseKind: "static"}},
		{api, "GET", "/v1/raw/kev/X.json", 304, Class{Kind: "api", BaseKind: "api", APIEndpoint: "raw"}},
		{www, "HEAD", "/stats", 200, Class{Kind: "page", BaseKind: "page", PageKind: "stats", Locale: "en"}},
		{www, "GET", "/src", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "src", Locale: "en"}},
		{www, "GET", "/es/about", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "about", Locale: "es"}},
		{www, "GET", "/ko/login", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "login", Locale: "ko"}},
		{www, "GET", "/account", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "account", Locale: "en"}},
		{www, "GET", "/zh-hans/welcome?next=%2Fvuln", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "welcome", Locale: "zh-hans"}},
		{www, "GET", "/api/affected/suggest?q=forti", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "suggest"}},
		{api, "GET", "/v1/affected/suggest?q=forti", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "suggest"}},
		{www, "GET", "/rules/3", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "rules", Locale: "en"}},
		{www, "GET", "/admin", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "admin", Locale: "en"}},
		{www, "GET", "/zh-hant/whatever", 404, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "other", Locale: "zh-hant"}},
		{www, "POST", "/vuln", 405, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "vuln_list", Locale: "en"}},
		{www, "GET", "/feed.xml", 200, Class{Kind: "feed", BaseKind: "feed", Locale: "en"}},
		{www, "GET", "/ja/feed.xml", 200, Class{Kind: "feed", BaseKind: "feed", Locale: "ja"}},
		{www, "GET", "/static/app.css", 200, Class{Kind: "static", BaseKind: "static"}},
		{www, "GET", "/robots.txt", 200, Class{Kind: "static", BaseKind: "static"}},
		{www, "GET", "/favicon.ico", 200, Class{Kind: "static", BaseKind: "static"}},
		{www, "GET", "/auth/github/start?return=/", 302, Class{Kind: "redirect", BaseKind: "auth"}},
		{www, "GET", "/api/me", 200, Class{Kind: "auth", BaseKind: "auth"}},
		{www, "POST", "/account/delete", 403, Class{Kind: "auth", BaseKind: "auth", Error: true}},
		{www, "GET", "/api/discuss/t/1", 200, Class{Kind: "auth", BaseKind: "auth"}},
		{www, "GET", "/api/posts/CVE-2026-1234", 200, Class{Kind: "auth", BaseKind: "auth"}},
		{www, "GET", "/discussed", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "discussed", Locale: "en"}},
		{www, "GET", "/zh-hans/discussed?offset=50", 200, Class{Kind: "page", BaseKind: "page", PageView: true, PageKind: "discussed", Locale: "zh-hans"}},
		{www, "GET", "/healthz", 200, Class{Kind: "health", BaseKind: "health"}},
		{api, "GET", "/healthz", 200, Class{Kind: "health", BaseKind: "health"}},
		// single-host mode: the API on the site host
		{www, "GET", "/api/hot", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "hot"}},
		{www, "GET", "/api/vuln/cve-2024-3094", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "vuln", CVE: "CVE-2024-3094"}},
		{www, "GET", "/api/search?q=x", 308, Class{Kind: "redirect", BaseKind: "api", APIEndpoint: "search"}},
		{www, "GET", "/raw/kev/X.json", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "raw"}},
		// API host
		{api, "GET", "/v1/hot", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "hot"}},
		{api, "GET", "/v1/discussed?limit=10", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "discussed"}},
		{www, "GET", "/api/discussed", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "discussed"}},
		{api, "GET", "/v1/vuln/CVE-2021-44228", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "vuln", CVE: "CVE-2021-44228"}},
		{api, "GET", "/v1/vuln/CVE-2021-44228", 404, Class{Kind: "api", BaseKind: "api", APIEndpoint: "vuln", Error: true}},
		{api, "GET", "/v1/search?q=Barracuda", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "search", Search: "barracuda"}},
		{api, "GET", "/v1/sources", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "sources"}},
		{api, "GET", "/v1/stats", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "stats"}},
		{api, "GET", "/v1/raw/kev/X.json", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "raw"}},
		{api, "GET", "/raw/kev/X.json", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "raw"}},
		{api, "GET", "/", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "index"}},
		{api, "GET", "/v1", 200, Class{Kind: "api", BaseKind: "api", APIEndpoint: "index"}},
		{api, "GET", "/v1/nope", 404, Class{Kind: "api", BaseKind: "api", APIEndpoint: "other", Error: true}},
		{api, "GET", "/wp-admin", 404, Class{Kind: "api", BaseKind: "api", APIEndpoint: "other", Error: true}},
		{api, "GET", "/robots.txt", 200, Class{Kind: "static", BaseKind: "static"}},
		// unmatched host (apex redirect, direct-IP probes): site rules
		{"", "GET", "/", 308, Class{Kind: "redirect", BaseKind: "page", PageKind: "home", Locale: "en"}},
		{"", "GET", "/.env", 404, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "other", Locale: "en"}},
		{www, "GET", "/about", 500, Class{Kind: "page", BaseKind: "page", Error: true, PageKind: "about", Locale: "en"}},
	}
	for _, tc := range tests {
		got := Classify(tc.domain, tc.method, tc.uri, tc.status)
		if got != tc.want {
			t.Errorf("Classify(%q, %s %s, %d)\n got %+v\nwant %+v", tc.domain, tc.method, tc.uri, tc.status, got, tc.want)
		}
	}
}

func TestIsBotAndFamily(t *testing.T) {
	tests := []struct {
		ua     string
		bot    bool
		family string
	}{
		{"", true, "(empty)"},
		{"   ", true, "(empty)"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", false, ""},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36", false, ""},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", false, ""},
		{"Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.16", false, ""},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true, "Googlebot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0)", true, "bingbot"},
		{"Mozilla/5.0 (compatible; YandexBot/3.0)", true, "YandexBot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", true, "GPTBot"},
		{"Mozilla/5.0 (compatible; ExampleSiteBot/1.0)", true, "ExampleSiteBot"},
		{"Mozilla/5.0 (compatible; acme-crawler/2)", true, "acme-crawler"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0 Safari/537.36", true, "HeadlessChrome"},
		{"Mozilla/5.0 (compatible) Slurp", true, "other"},
		{"Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", true, "UptimeRobot"},
		{"curl/8.7.1", true, "curl"},
		{"Wget/1.21", true, "Wget"},
		{"python-requests/2.32.3", true, "python-requests"},
		{"Python-urllib/3.12", true, "python-urllib"},
		{"Go-http-client/2.0", true, "Go-http-client"},
		{"okhttp/4.12.0", true, "okhttp"},
		{"libwww-perl/6.72", true, "libwww-perl"},
		{"Java/17.0.2", true, "Java"},
		{"node-fetch/1.0", true, "node-fetch"},
		{"axios/1.7.2", true, "axios"},
		{"Feedly/1.0 (+http://www.feedly.com/fetcher.html)", true, "other"},
		{"NetNewsWire (RSS Reader; https://netnewswire.com/)", true, "other"},
		{"facebookexternalhit/1.1", true, "facebookexternalhit"},
		{"Mozilla/5.0 zgrab/0.x", true, "zgrab"},
		{"Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 SomeScript", false, ""}, // a browser-looking UA without a token counts as human
		{"SomethingElse/1.0", true, "other"},
	}
	for _, tc := range tests {
		if got := IsBot(tc.ua); got != tc.bot {
			t.Errorf("IsBot(%q) = %v, want %v", tc.ua, got, tc.bot)
		}
		if tc.bot {
			if got := BotFamily(tc.ua); got != tc.family {
				t.Errorf("BotFamily(%q) = %q, want %q", tc.ua, got, tc.family)
			}
		}
	}
}

func TestSearchTerm(t *testing.T) {
	tests := map[string]string{
		"":                                     "",
		"q=":                                   "",
		"q=%20%20":                             "",
		"q=Log4J":                              "log4j",
		"q=+Log4J+":                            "log4j",
		"since=7d&q=Barracuda":                 "barracuda",
		"q=a&q=b":                              "a",
		"q=x%00y%0D%0Az%E2%80%8B":              "xyz",  // controls and a zero-width (format) character removed
		"q=%ZZ&q=fine":                         "fine", // a broken pair is skipped
		"q=" + strings.Repeat("A", 80):         strings.Repeat("a", 64),
		"q=" + strings.Repeat("%E6%BC%8F", 70): strings.Repeat("漏", 64),
		"q=%FF%FEok":                           "ok",
	}
	for in, want := range tests {
		if got := SearchTerm(in); got != want {
			t.Errorf("SearchTerm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRefererHost(t *testing.T) {
	own := func(h string) bool { return h == "nday.land" || strings.HasSuffix(h, ".nday.land") }
	tests := map[string]string{
		"":                                              "",
		"https://news.ycombinator.com/item?id=1":        "news.ycombinator.com",
		"https://WWW.Google.COM:443/search?q=x":         "www.google.com",
		"http://example.org./path":                      "example.org",
		"https://www.nday.land/vuln":                    "",
		"https://nday.land/":                            "",
		"https://api.nday.land/v1/hot":                  "",
		"android-app://com.slack/":                      "",
		"not a url":                                     "",
		"https://evil.example/\"x\"?a=\r\n":             "", // control characters: not a valid URL
		"https://evil.example/\"x\"?a=1":                "evil.example",
		"https://" + strings.Repeat("a", 256) + ".com/": "",
		"https://[2001:db8::1]:8443/x":                  "2001:db8::1",
	}
	for in, want := range tests {
		if got := RefererHost(in, own); got != want {
			t.Errorf("RefererHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCVEAndPaths(t *testing.T) {
	for in, want := range map[string]string{
		"CVE-2024-3094": "CVE-2024-3094", "cve-2024-3094": "CVE-2024-3094", "CVE-2026-124194": "CVE-2026-124194",
		"CVE-2024-123": "", "CVE-2024-3094x": "", "CVE-२०२४-3094": "", "": "", "CVE%2D2024%2D3094": "CVE-2024-3094",
		"CVE-2024-" + strings.Repeat("1", 25): "",
	} {
		if got := NormalizeCVE(in); got != want {
			t.Errorf("NormalizeCVE(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NotFoundPath("/a?secret=1"); got != "/a" {
		t.Errorf("NotFoundPath = %q", got)
	}
	long := "/" + strings.Repeat("é", 150)
	if got := NotFoundPath(long); len(got) > 200 || !strings.HasPrefix(long, got) || len(got) < 199 {
		t.Errorf("NotFoundPath long = %d bytes", len(got))
	}
	for in, want := range map[int]string{200: "2xx", 304: "3xx", 404: "4xx", 503: "5xx", 0: "other", 99: "other", 600: "other", 101: "1xx"} {
		if got := StatusClass(in); got != want {
			t.Errorf("StatusClass(%d) = %q", in, got)
		}
	}
}

func TestVisitorKey(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	a := VisitorKey(salt, "2026-11-13", "203.0.113.1", "UA")
	if a != VisitorKey(salt, "2026-11-13", "203.0.113.1", "UA") {
		t.Fatal("not deterministic")
	}
	for _, other := range [][8]byte{
		VisitorKey(salt, "2026-11-14", "203.0.113.1", "UA"), // next day: unrelated
		VisitorKey(salt, "2026-11-13", "203.0.113.2", "UA"),
		VisitorKey(salt, "2026-11-13", "203.0.113.1", "UA2"),
		VisitorKey(salt, "2026-11-13", "203.0.113.1U", "A"), // separator: no ambiguity
		VisitorKey([]byte("other salt"), "2026-11-13", "203.0.113.1", "UA"),
	} {
		if other == a {
			t.Errorf("collision: %x", other)
		}
	}
}

// The locale prefixes must match the UI's catalog list.
func TestLocalesMatchCatalog(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(testutil.RepoRoot(), "internal/webui/i18n/locales.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		Locales []struct {
			Prefix string `json:"prefix"`
		} `json:"locales"`
	}
	if err := json.Unmarshal(b, &cat); err != nil {
		t.Fatal(err)
	}
	var prefixes []string
	for _, l := range cat.Locales {
		if l.Prefix != "" {
			prefixes = append(prefixes, l.Prefix)
		}
	}
	// The same set, in any order: locales.json is ordered for the language
	// menu, which has nothing to do with matching a URL prefix.
	want := append([]string(nil), Locales...)
	sort.Strings(prefixes)
	sort.Strings(want)
	if !reflect.DeepEqual(prefixes, want) {
		t.Errorf("locales.json prefixes %v, stats.Locales %v", prefixes, want)
	}
}

// The search-term privacy rule: a term used by one visitor (any number of
// times) is never stored; two distinct visitors make it stored.
func TestSearchTermThreshold(t *testing.T) {
	salt := make([]byte, 32)
	a := newDayAgg("2026-11-13", salt, func(string) bool { return false })
	line := func(ip, ua, uri string) *Line {
		return &Line{Day: "2026-11-13", ClientIP: ip, UserAgent: ua, Domain: "www.nday.land", Method: "GET", URI: uri, Status: 200}
	}
	for i := 0; i < 5; i++ {
		a.add(line("203.0.113.1", "Mozilla/5.0 A", "/vuln?q=Alice+Private"))
	}
	a.add(line("203.0.113.1", "Mozilla/5.0 A", "/vuln?q=shared"))
	a.add(line("203.0.113.1", "Mozilla/5.0 B", "/vuln?q=Shared")) // same IP, other UA = other visitor
	a.add(line("192.0.2.1", "curl/8", "/v1/search?q=solo"))       // not the API host: page kind other, no term
	_, tops := a.rows(scanResult{}, 0)
	var got []string
	for _, r := range tops {
		if r.Kind == TopSearch {
			got = append(got, r.Key)
		}
	}
	if !reflect.DeepEqual(got, []string{"shared"}) {
		t.Errorf("stored search terms %v, want [shared]", got)
	}
}
