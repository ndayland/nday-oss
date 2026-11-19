package auth

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ReservedNames are names no user (and later no organisation) may take as a
// handle, because the public namespace is root-level (/<name>, like
// huggingface.co/<name>) and these would collide with site routes, locale
// prefixes, roles, brands or confusable system words.
//
// THIS IS THE ONE PLACE THE LIST LIVES. Whoever adds a new top-level route
// to the site (internal/web, internal/webui, cmd/nday) must add its first
// path segment here; TestRoutesReservedAsHandles in internal/webui builds
// the real server and fails for any registered segment missing here.
var ReservedNames = []string{
	// existing top-level routes (internal/web, internal/webui)
	"api", "raw", "healthz", "static", "hot", "vuln", "vulns", "src", "stats", "about",
	"feed", "feeds", "feed.xml", "robots.txt", "favicon.ico", "__i18n", "auth", "account", "welcome",
	"discussed", "rules", "og", "icon",
	// the API host's version prefix (api.nday.land/v1/...)
	"v1",
	// locale prefixes (internal/webui/i18n/locales.json) and the primary tag
	"en", "zh-hans", "zh-hant", "ja", "ko", "es", "fr", "zh", "zh-cn", "zh-tw", "de", "pt", "ru",
	// planned community routes and generic site words
	"u", "org", "orgs", "organization", "organizations", "organisation", "organisations",
	"user", "users", "me", "settings", "new", "login", "logout", "signin", "sign-in",
	// "cli" is the actor shown in the audit log for commands run on the server
	"cli",
	"signup", "sign-up", "signout", "sign-out", "join", "register", "papers", "paper",
	"incidents", "incident", "posts", "post", "collections", "collection", "discussions",
	"discussion", "docs", "doc", "blog", "pricing", "terms", "tos", "privacy", "legal",
	"cookies", "www", "mail", "email", "cdn", "assets", "status", "help", "faq", "search",
	"explore", "trending", "notifications", "inbox", "dashboard", "home", "index",
	"sitemap", "sitemap.xml", "rss", "atom", "graphql", "oauth", "sso", "callback",
	"cve", "cves", "kev", "ghsa", "poc", "pocs", "exploit", "exploits", "advisory",
	"advisories", "products", "product", "vendors", "vendor", "tags", "tag", "topics",
	"well-known", ".well-known", "security.txt", "humans.txt", "ads.txt",
	// roles and system identities
	"admin", "administrator", "admins", "root", "sysadmin", "system", "moderator",
	"moderators", "mod", "mods", "staff", "team", "official", "support", "security",
	"abuse", "postmaster", "hostmaster", "webmaster", "noreply", "no-reply", "info",
	"contact", "billing", "sales", "press", "jobs", "careers",
	"anonymous", "anon", "deleted", "deleted-user", "ghost", "nobody", "everyone",
	"null", "undefined", "none", "true", "false", "test",
	// brand
	"nday", "ndayland", "nday-land", "nday_land", "ndays", "n-day", "n_day",
	// sign-in providers
	"google", "apple", "github", "x", "twitter",
}

var reservedSet = func() map[string]bool {
	m := make(map[string]bool, len(ReservedNames))
	for _, n := range ReservedNames {
		m[strings.ToLower(n)] = true
	}
	return m
}()

// localeLike matches BCP 47-ish "ll-xxxx" names (future locale prefixes
// such as pt-br or zh-hk), which are reserved too.
var localeLike = regexp.MustCompile(`^[a-z]{2}-[a-z]{2,4}$`)

var handleRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{2,29}$`)

// Handle errors (their text is returned to the client as the error message).
var (
	ErrHandleFormat   = errors.New("a handle is 3-30 characters of letters, digits, '_' or '-', starting with a letter or digit")
	ErrHandleReserved = errors.New("this handle is reserved")
)

// CanonicalHandle validates a handle and returns its canonical (lower-case)
// key. The display casing is the input itself.
func CanonicalHandle(h string) (string, error) {
	if !handleRe.MatchString(h) {
		return "", ErrHandleFormat
	}
	key := strings.ToLower(h)
	if IsReserved(key) {
		return "", ErrHandleReserved
	}
	return key, nil
}

// IsReserved reports whether a canonical name is reserved: an exact entry
// of ReservedNames, a locale-like name, or an impersonation of one (see
// impersonates).
func IsReserved(key string) bool {
	return reservedSet[key] || localeLike.MatchString(key) || impersonates(key)
}

// Impersonation rules. Names are compared on a skeleton: lower case, '_', '-'
// and '.' removed, and look-alike digits mapped to letters. A handle is
// reserved when
//
//  1. its skeleton (also after trimming leading/trailing separators)
//     equals the skeleton of a ReservedNames entry: adm1n, admin_, root_;
//  2. after trimming leading/trailing digits and separators it is a
//     protected (brand or role) word: Admin1, moderator1. This digits rule
//     covers protected words only, so kev1, me2, test123, apple1 or es6 stay
//     free although kev, me, test, apple and es are reserved route words;
//  3. its skeleton is one protected word or a concatenation of protected
//     words: helpdesk, verified, nday-official, support-team;
//  4. one of its '_'/'-'/'.' separated parts is a brand word or one of the
//     unambiguous role words in tokenRoleWords: the_admin, real-admin,
//     official-account, the-nday. The everyday words (team, root, security,
//     system, support, staff, trust, safety, mod) are NOT matched as a part:
//     red-team, root_cause, security-researcher, staff_engineer and
//     monday_team are ordinary handles in a security community;
//  5. its skeleton starts with a brand word (nday-news, nd4y) or ends with
//     admin, administrator, moderator or official after at least two other
//     characters (iamadmin, webadmin, superofficial; padmin and sadmin stay
//     free). There is deliberately no suffix rule for staff, team, mod, root
//     or trust (flagstaff, steam, mistrust).
//
// Near-miss spellings (admln, admiin) are out of scope: the durable defence
// against impersonation is a staff badge driven by the role, shown by the UI.
//
// Display names stay free text; only brand/role impersonation is refused
// (see DisplayNameImpersonates).
var (
	brandWords = []string{"nday", "ndayland"}
	roleWords  = []string{"admin", "admins", "administrator", "official", "support", "security", "moderator",
		"moderators", "mod", "mods", "staff", "team", "root", "sysadmin", "sysadm", "system", "abuse", "verified", "trust",
		"safety", "helpdesk"}
	// suffixWords: a skeleton ending in one of these is reserved (rule 5).
	suffixWords = []string{"admin", "administrator", "moderator", "official"}
	// tokenRoleWords: role words that reserve a handle when they are one of
	// its separated parts (rule 4). Brand words always do.
	tokenRoleWords = []string{"admin", "admins", "administrator", "official", "moderator", "moderators", "sysadmin",
		"sysadm", "helpdesk", "verified"}
	tokenSet = func() map[string]bool {
		m := map[string]bool{}
		for _, w := range append(append([]string{}, brandWords...), tokenRoleWords...) {
			m[w] = true
		}
		return m
	}()
	// protectedCJK are role words of the Chinese/Japanese/Korean UI; a
	// display name containing any of them is refused (handles are ASCII).
	protectedCJK = []string{"官方", "管理员", "管理員", "站长", "站長", "客服", "版主", "运营", "運營", "工作人员", "工作人員",
		"公式", "管理者", "운영자", "관리자"}
	protectedSet = func() map[string]bool {
		m := map[string]bool{}
		for _, w := range append(append([]string{}, brandWords...), roleWords...) {
			m[w] = true
		}
		return m
	}()
	reservedSkeletons = func() map[string]bool {
		m := map[string]bool{}
		for _, n := range ReservedNames {
			for _, sk := range skeletons(strings.ToLower(n)) {
				if len(sk) >= 2 {
					m[sk] = true
				}
			}
		}
		return m
	}()
)

// lookAlike maps digits to the letters they imitate ('1' is handled by
// skeletons: it may stand for 'l' or 'i').
var lookAlike = strings.NewReplacer("0", "o", "3", "e", "4", "a", "5", "s", "7", "t", "8", "b", "$", "s", "@", "a")

// skeletons returns the skeletons of a lower-case name: separators removed,
// digits mapped, '1' read as both 'l' and 'i', and "rn" also read as "m".
func skeletons(s string) []string {
	s = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(lookAlike.Replace(s))
	var out []string
	for _, one := range []string{"l", "i"} {
		v := strings.ReplaceAll(s, "1", one)
		out = append(out, v)
		if strings.Contains(v, "rn") {
			out = append(out, strings.ReplaceAll(v, "rn", "m"))
		}
	}
	return out
}

func isSep(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ' ' }

func isDigitOrSep(r rune) bool { return isSep(r) || r >= '0' && r <= '9' }

// impersonates applies rules 1-5 to a lower-case handle.
func impersonates(key string) bool {
	cands := skeletons(key)
	if core := strings.TrimFunc(key, isSep); core != "" && core != key {
		cands = append(cands, skeletons(core)...)
	}
	for _, sk := range cands {
		if reservedSkeletons[sk] || brandPrefix(sk) || protectedSuffix(sk) || onlyProtected(sk, 1) {
			return true
		}
	}
	if core := strings.TrimFunc(key, isDigitOrSep); core != "" && core != key {
		for _, sk := range skeletons(core) {
			if onlyProtected(sk, 1) {
				return true
			}
		}
	}
	for _, part := range strings.FieldsFunc(key, isSep) {
		for _, sk := range skeletons(part) {
			if tokenSet[strings.TrimFunc(sk, isDigitOrSep)] {
				return true
			}
		}
	}
	return false
}

func protectedSuffix(sk string) bool {
	for _, w := range suffixWords {
		if strings.HasSuffix(sk, w) && len(sk)-len(w) >= 2 {
			return true
		}
	}
	return false
}

func brandPrefix(sk string) bool {
	for _, b := range brandWords {
		if strings.HasPrefix(sk, b) {
			return true
		}
	}
	return false
}

// onlyProtected reports whether s is a concatenation of at least min
// protected words.
func onlyProtected(s string, min int) bool {
	if s == "" {
		return min <= 0
	}
	for w := range protectedSet {
		if strings.HasPrefix(s, w) && onlyProtected(s[len(w):], min-1) {
			return true
		}
	}
	return false
}

// confusable maps Cyrillic and Greek letters that look exactly like Latin
// ones.
var confusable = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
	'һ': 'h', 'ԛ': 'q', 'ԝ': 'w',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
	'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Ү': 'Y',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P',
	'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'ο': 'o', 'α': 'a', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'υ': 'u', 'χ': 'x',
}

// unconfuse maps look-alike letters in every word that mixes Latin with
// another script, or that consists only of look-alike letters ("Аdmin",
// "nԁay", "ΝDΑΥ"); words written in Cyrillic or Greek ("Алексей", "Νίκος")
// are left alone.
func unconfuse(s string) string {
	var b strings.Builder
	word := []rune{}
	flush := func() {
		latin, conf, other := false, 0, false
		for _, r := range word {
			switch {
			case r < 0x80 && unicode.IsLetter(r):
				latin = true
			case confusable[r] != 0:
				conf++
			case unicode.IsLetter(r):
				other = true
			}
		}
		mapIt := conf > 0 && (latin || !other)
		for _, r := range word {
			if c := confusable[r]; mapIt && c != 0 {
				r = c
			}
			b.WriteRune(r)
		}
		word = word[:0]
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			word = append(word, r)
			continue
		}
		flush()
		b.WriteRune(r)
	}
	flush()
	return b.String()
}

// DisplayNameImpersonates reports whether a (sanitised) display name poses
// as the site or its staff. The name is first normalised (NFKC: full-width,
// mathematical and circled letters become ASCII) and look-alike Cyrillic or
// Greek letters in mixed-script words are mapped to Latin. It is refused
// when it contains a CJK role word ("官方账号", "管理员小王"), when one of its
// words starts with a brand word ("nday 官方", "NDAY Support", "ndaybot"),
// or when its letters are only role/brand words ("Admin", "Support Team").
// Ordinary names that merely contain such a word next to others ("Team
// Rocket", "Sunday Mod Fan") are free text and stay allowed.
func DisplayNameImpersonates(name string) bool {
	n := strings.ToLower(unconfuse(norm.NFKC.String(name)))
	for _, w := range protectedCJK {
		if strings.Contains(n, w) {
			return true
		}
	}
	words := strings.FieldsFunc(n, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '$' || r == '@')
	})
	for _, w := range words {
		for _, sk := range skeletons(w) {
			if brandPrefix(strings.TrimFunc(sk, isDigitOrSep)) {
				return true
			}
		}
	}
	var ascii []string
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '$' || r == '@':
			ascii = append(ascii, string(r))
		case unicode.IsLetter(r):
			return false // other words: free text
		}
	}
	for _, sk := range skeletons(strings.Join(ascii, "")) {
		if onlyProtected(sk, 1) {
			return true
		}
	}
	return false
}

// SafeDisplayName sanitises a display name taken from a provider and drops
// it ("") when it impersonates the site (rule above).
func SafeDisplayName(s string) string {
	s = SanitizeDisplayName(s)
	if DisplayNameImpersonates(s) {
		return ""
	}
	return s
}

// MaxDisplayName is the display-name length cap (characters).
const MaxDisplayName = 64

// SanitizeDisplayName removes control, format (bidi overrides, zero-width
// characters, ...), private-use and unassigned code points, maps every
// space separator to ' ', collapses runs of spaces, trims, and caps the
// length. It returns "" when nothing printable remains.
func SanitizeDisplayName(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || unicode.Is(unicode.Zs, r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r),
			unicode.Is(unicode.Cs, r), !unicode.IsPrint(r) && !unicode.IsGraphic(r):
			continue
		}
		if space {
			if n+1 >= MaxDisplayName {
				break
			}
			b.WriteByte(' ')
			n++
			space = false
		}
		if n >= MaxDisplayName {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

var localeRe = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)

// ValidLocale reports whether s is an acceptable locale tag (BCP 47 shape,
// <= 35 characters). Which tags the UI offers is the UI's business.
func ValidLocale(s string) bool { return len(s) <= 35 && localeRe.MatchString(s) }
