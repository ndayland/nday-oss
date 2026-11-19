// Package stats rolls the web access logs (docs/logging.md) up into daily
// operations statistics in PostgreSQL and reads them back for the admin UI.
// The tables, every metric/dim/kind value, the classification rules and the
// privacy rules are documented in docs/stats.md; this file holds the pure
// classification functions.
package stats

import (
	"crypto/sha256"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Request kinds (stats_daily metric "req_kind").
const (
	KindPage     = "page"
	KindAPI      = "api"
	KindFeed     = "feed"
	KindStatic   = "static"
	KindAuth     = "auth"
	KindHealth   = "health"
	KindRedirect = "redirect"
)

// Page kinds (metric "pv_page").
var PageKinds = []string{"home", "discussed", "vuln_list", "vuln", "stats", "src", "about", "login", "account", "welcome", "rules", "admin", "other"}

// API endpoints (metric "api_endpoint").
var APIEndpoints = []string{"hot", "discussed", "vuln", "search", "suggest", "sources", "stats", "raw", "index", "other"}

// Locales are the URL prefixes of internal/webui/i18n/locales.json ("" =
// English at the root, reported as "en"). A test keeps the two in sync.
var Locales = []string{"zh-hans", "zh-hant", "ja", "ko", "es", "fr"}

// Class is what Classify derives from one access line.
type Class struct {
	// Kind is the primary kind; every 3xx response except 304 is
	// KindRedirect.
	Kind string
	// BaseKind is the kind before the 3xx override (errors are attributed
	// to it: metric "req_error_kind").
	BaseKind string
	// Error: status >= 400.
	Error bool
	// PageView: GET of an HTML page on the site host answered 200, or 304
	// (a browser revalidating its copy: pages carry an ETag).
	PageView bool
	PageKind string // for KindPage
	Locale   string // for pages and the feed: "en", "zh-hans", ...
	// APIEndpoint for KindAPI.
	APIEndpoint string
	// CVE: normalised id of a vulnerability page or API vuln lookup, a CVE
	// id or a GHSA id (valid format only, else "").
	CVE string
	// Search: normalised search term of a successful GET search (page /vuln
	// or API search), "" if none.
	Search string
}

// isAPIHost: the configured API host is "api.<site>" (docs/stats.md).
func isAPIHost(domain string) bool { return strings.HasPrefix(domain, "api.") }

// Classify classifies one request. domain is the access line's "domain"
// (the configured canonical host or ""), uri its escaped path plus query.
func Classify(domain, method, uri string, status int) Class {
	path, rawQuery, _ := strings.Cut(uri, "?")
	c := Class{Error: status >= 400}
	ok := status == 200 || status == 304 // a served (or revalidated) response
	switch {
	case path == "/healthz":
		c.Kind = KindHealth
	case isAPIHost(domain):
		switch {
		case path == "/robots.txt":
			c.Kind = KindStatic
		case path == "/" || path == "/v1" || path == "/v1/":
			c.Kind, c.APIEndpoint = KindAPI, "index"
		case strings.HasPrefix(path, "/raw/"):
			c.Kind, c.APIEndpoint = KindAPI, "raw"
		case strings.HasPrefix(path, "/v1/"):
			c.Kind = KindAPI
			c.APIEndpoint, c.CVE = apiEndpoint(strings.TrimPrefix(path, "/v1"))
		default:
			c.Kind, c.APIEndpoint = KindAPI, "other"
		}
	case strings.HasPrefix(path, "/static/") || path == "/robots.txt" || path == "/favicon.ico":
		c.Kind = KindStatic
	case strings.HasPrefix(path, "/auth/") || strings.HasPrefix(path, "/account/") || path == "/api/me" ||
		strings.HasPrefix(path, "/api/discuss/") || strings.HasPrefix(path, "/api/posts/"):
		c.Kind = KindAuth
	case strings.HasPrefix(path, "/api/"): // single-host mode (or a 308 to the API host)
		c.Kind = KindAPI
		c.APIEndpoint, c.CVE = apiEndpoint(strings.TrimPrefix(path, "/api"))
	case strings.HasPrefix(path, "/raw/"):
		c.Kind, c.APIEndpoint = KindAPI, "raw"
	default:
		loc, rest := splitLocale(path)
		c.Locale = loc
		if rest == "/feed.xml" {
			c.Kind = KindFeed
			break
		}
		c.Kind = KindPage
		c.PageKind, c.CVE = pageKind(rest)
		c.PageView = method == "GET" && ok
	}
	c.BaseKind = c.Kind
	if status >= 300 && status < 400 && status != 304 {
		c.Kind = KindRedirect
		c.PageView = false
	}
	if c.Kind != KindAPI && c.Kind != KindPage || c.Kind == KindPage && !c.PageView {
		c.CVE = ""
	}
	if c.Kind == KindAPI && !ok {
		c.CVE = ""
	}
	if method == "GET" && ok && (c.PageView && c.PageKind == "vuln_list" ||
		c.Kind == KindAPI && c.APIEndpoint == "search") {
		c.Search = SearchTerm(rawQuery)
	}
	return c
}

// splitLocale strips a locale prefix: "/zh-hans/vuln" -> ("zh-hans", "/vuln"),
// "/zh-hans" -> ("zh-hans", "/"), "/vuln" -> ("en", "/vuln").
func splitLocale(path string) (string, string) {
	seg, rest, slash := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	for _, l := range Locales {
		if seg == l {
			if !slash {
				return l, "/"
			}
			return l, "/" + rest
		}
	}
	return "en", path
}

func pageKind(p string) (kind, cve string) {
	switch p {
	case "/", "/hot":
		return "home", ""
	case "/discussed":
		return "discussed", ""
	case "/vuln":
		return "vuln_list", ""
	case "/stats", "/src", "/about", "/login", "/account", "/welcome":
		return p[1:], ""
	}
	switch {
	case strings.HasPrefix(p, "/vuln/"):
		return "vuln", NormalizeCVE(strings.TrimPrefix(p, "/vuln/"))
	case p == "/rules" || strings.HasPrefix(p, "/rules/"):
		return "rules", ""
	case p == "/admin" || strings.HasPrefix(p, "/admin/"):
		return "admin", ""
	}
	return "other", ""
}

// apiEndpoint maps a path relative to the API root ("/hot", "/vuln/X").
func apiEndpoint(p string) (endpoint, cve string) {
	switch p {
	case "/hot", "/discussed", "/search", "/sources", "/stats":
		return p[1:], ""
	case "/affected/suggest":
		return "suggest", ""
	}
	switch {
	case strings.HasPrefix(p, "/vuln/"):
		return "vuln", NormalizeCVE(strings.TrimPrefix(p, "/vuln/"))
	case strings.HasPrefix(p, "/raw/"):
		return "raw", ""
	}
	return "other", ""
}

// cveRe is the ASCII form of model.IsValidCVEID's pattern, with an upper
// bound on the sequence length; ghsaRe a GHSA id (upper-cased), the id of a
// vulnerability without a CVE.
var (
	cveRe  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	ghsaRe = regexp.MustCompile(`^GHSA(-[23456789CFGHJMPQRVWX]{4}){3}$`)
)

// NormalizeCVE canonicalises a vulnerability id from a path ("" if invalid):
// a CVE id upper case, a GHSA id as the site writes it
// ("GHSA-gpwc-27cw-rh9r").
func NormalizeCVE(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	s = strings.ToUpper(s)
	switch {
	case cveRe.MatchString(s):
		return s
	case ghsaRe.MatchString(s):
		return "GHSA" + strings.ToLower(s[4:])
	}
	return ""
}

// SearchTerm extracts and normalises the q parameter of a raw query: first
// q value, control characters removed, trimmed, lower-cased, at most 64
// characters. "" when absent or empty.
func SearchTerm(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	q, _ := url.ParseQuery(rawQuery) // keeps the pairs parsed before an error
	return NormalizeTerm(q.Get("q"))
}

// NormalizeTerm is the search-term normalisation of SearchTerm.
func NormalizeTerm(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.ToLower(strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > 64 {
		s = strings.TrimSpace(string([]rune(s)[:64]))
	}
	return s
}

// RefererHost returns the lower-cased host (no port, no path, no query) of
// an http(s) referer, or "" when there is none, it is one of our own hosts
// (own reports that), or it is longer than 255 bytes.
func RefererHost(ref string, own func(host string) bool) string {
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "" || len(h) > 255 || own(h) {
		return ""
	}
	for _, r := range h {
		if r <= ' ' || r == 0x7f {
			return ""
		}
	}
	return h
}

// NotFoundPath is the path of a 404 (query dropped), at most 200 bytes.
func NotFoundPath(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	if len(p) > 200 {
		p = p[:200]
		for !utf8.ValidString(p) && len(p) > 0 { // never split a character
			p = p[:len(p)-1]
		}
	}
	return p
}

// VisitorKey is the daily pseudonymous visitor id: the first 8 bytes of
// SHA-256(salt ‖ day ‖ 0 ‖ client_ip ‖ 0 ‖ user_agent). The day makes keys
// of different days unrelated; the secret salt makes them irreversible
// without the database.
func VisitorKey(salt []byte, day, clientIP, userAgent string) [8]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(day))
	h.Write([]byte{0})
	h.Write([]byte(clientIP))
	h.Write([]byte{0})
	h.Write([]byte(userAgent))
	var sum [sha256.Size]byte
	var k [8]byte
	copy(k[:], h.Sum(sum[:0]))
	return k
}

// botTokens: a user agent containing any of these (case-insensitive) is a
// bot. The single list of the heuristic (docs/stats.md).
var botTokens = []string{
	// self-declared crawlers, monitors and link expanders
	"bot", "crawl", "spider", "slurp", "monitor", "uptime", "preview", "fetch", "scan",
	"archiver", "facebookexternalhit", "embedly", "whatsapp", "telegram", "discord", "slack",
	"lighthouse", "pingdom", "validator",
	// vulnerability and port scanners
	"zgrab", "masscan", "nmap", "nuclei", "sqlmap", "nikto", "censys", "shodan", "expanse", "netcraft",
	// HTTP libraries and command-line clients
	"curl", "wget", "python-requests", "python-urllib", "python-httpx", "aiohttp", "go-http-client",
	"okhttp", "libwww", "java/", "apache-httpclient", "node-fetch", "axios", "undici", "httpie",
	"guzzlehttp", "ruby", "scrapy", "postman", "insomnia", "powershell", "winhttp", "reqwest",
	// headless and automated browsers
	"headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright", "electron/",
	// feed readers
	"feed", "rss", "newsblur", "inoreader", "tiny tiny", "netnewswire", "miniflux", "freshrss",
}

// IsBot is the human/bot heuristic on the user agent: empty, containing a
// botTokens entry, or not starting like a browser ("Mozilla/" or "Opera").
// It is a heuristic: a script that sends a browser user agent counts as
// human, and an unusual browser may count as a bot.
func IsBot(ua string) bool {
	if strings.TrimSpace(ua) == "" {
		return true
	}
	l := strings.ToLower(ua)
	for _, t := range botTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return !strings.HasPrefix(l, "mozilla/") && !strings.HasPrefix(l, "opera")
}

// botFamilies maps a lower-case user-agent substring to a family name for
// the "bot_ua" top list; the first match wins (specific before generic).
var botFamilies = []struct{ token, name string }{
	{"googlebot", "Googlebot"}, {"google-inspectiontool", "Google-InspectionTool"},
	{"adsbot-google", "AdsBot-Google"}, {"googleother", "GoogleOther"}, {"bingbot", "bingbot"},
	{"applebot", "Applebot"}, {"duckduckbot", "DuckDuckBot"}, {"yandex", "YandexBot"},
	{"baiduspider", "Baiduspider"}, {"sogou", "Sogou"}, {"bytespider", "Bytespider"},
	{"petalbot", "PetalBot"}, {"gptbot", "GPTBot"}, {"chatgpt-user", "ChatGPT-User"},
	{"oai-searchbot", "OAI-SearchBot"}, {"claudebot", "ClaudeBot"}, {"claude-user", "Claude-User"},
	{"perplexitybot", "PerplexityBot"}, {"ccbot", "CCBot"}, {"ahrefsbot", "AhrefsBot"},
	{"semrushbot", "SemrushBot"}, {"mj12bot", "MJ12bot"}, {"dotbot", "DotBot"},
	{"facebookexternalhit", "facebookexternalhit"}, {"zgrab", "zgrab"}, {"censys", "Censys"}, {"twitterbot", "Twitterbot"},
	{"linkedinbot", "LinkedInBot"}, {"slackbot", "Slackbot"}, {"discordbot", "Discordbot"},
	{"telegrambot", "TelegramBot"}, {"whatsapp", "WhatsApp"}, {"uptimerobot", "UptimeRobot"},
	{"headlesschrome", "HeadlessChrome"}, {"phantomjs", "PhantomJS"},
	{"python-requests", "python-requests"}, {"python-urllib", "python-urllib"},
	{"python-httpx", "python-httpx"}, {"aiohttp", "aiohttp"}, {"go-http-client", "Go-http-client"},
	{"curl", "curl"}, {"wget", "Wget"}, {"okhttp", "okhttp"}, {"libwww", "libwww-perl"},
	{"node-fetch", "node-fetch"}, {"axios", "axios"}, {"undici", "undici"}, {"java/", "Java"},
	{"apache-httpclient", "Apache-HttpClient"}, {"scrapy", "Scrapy"},
}

// genericBotRe picks a self-declared name like "FooBot/1.2" or "bar-crawler".
var genericBotRe = regexp.MustCompile(`(?i)[a-z0-9][a-z0-9._-]{0,40}(?:bot|crawler|spider)\b`)

// BotFamily names the family of a bot user agent: a known family, a
// self-declared "...bot"/"...crawler"/"...spider" token, "(empty)", or "other".
func BotFamily(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "(empty)"
	}
	l := strings.ToLower(ua)
	for _, f := range botFamilies {
		if strings.Contains(l, f.token) {
			return f.name
		}
	}
	if m := genericBotRe.FindString(ua); m != "" {
		return m
	}
	return "other"
}

// StatusClass is "2xx" ... "5xx", or "other".
func StatusClass(status int) string {
	if status >= 100 && status < 600 {
		return string(rune('0'+status/100)) + "xx"
	}
	return "other"
}
