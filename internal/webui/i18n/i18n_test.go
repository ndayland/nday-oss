package i18n

import (
	"html/template"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// TestCatalogs validates EVERY catalog file present against keys.json and
// its registry entry: all keys present, no unknown keys, placeholders used ⊆
// declared (and required ones used), plural/select variants complete, no
// HTML, no empty strings, length limits, locale typography. A writer runs:
//
//	go test ./internal/webui/i18n -run TestCatalogs -v
func TestCatalogs(t *testing.T) {
	set, err := Load(embedded)
	if err != nil {
		t.Fatal(err)
	}
	ents, err := fs.ReadDir(embedded, "catalogs")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 2 {
		t.Fatalf("expected at least en and zh-Hans catalogs, got %d", len(ents))
	}
	for _, e := range ents {
		tag := strings.TrimSuffix(e.Name(), ".json")
		l := set.ByTag(tag)
		if l == nil {
			t.Errorf("%s: no registry entry in locales.json", e.Name())
			continue
		}
		t.Run(tag, func(t *testing.T) {
			for _, p := range l.Problems() {
				t.Errorf("%s: %s", tag, p)
			}
			if !l.Enabled() {
				t.Errorf("%s is not enabled", tag)
			}
			t.Logf("%s: %d keys, %d problems", tag, len(set.Reference.Keys()), len(l.Problems()))
		})
	}
	for _, want := range []string{"en", "zh-Hans"} {
		if l := set.ByTag(want); l == nil || !l.Enabled() {
			t.Errorf("%s must ship enabled", want)
		}
	}
}

// TestReferenceSane: the reference itself is well-formed (every select has
// values, examples exist), and plural keys declare a number placeholder.
func TestReferenceSane(t *testing.T) {
	ref, err := LoadReference(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ref.Keys()); n < 300 {
		t.Errorf("only %d keys", n)
	}
	for _, k := range ref.Keys() {
		d := ref.Key(k)
		if d.Kind == "sentence" && d.MaxCols != 0 && d.MaxCols < 20 {
			t.Errorf("%s: sentence with a tiny max_cols", k)
		}
		if len(d.Intent) < 8 {
			t.Errorf("%s: intent too thin", k)
		}
	}
}

func testLocale(t *testing.T, tag string) *Locale {
	t.Helper()
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	l := set.ByTag(tag)
	if l == nil {
		t.Fatalf("no locale %s", tag)
	}
	return l
}

func TestPluralRules(t *testing.T) {
	set, _ := Default()
	cases := map[string]map[int64]string{
		"en":      {0: "other", 1: "one", 2: "other", 21: "other", -1: "one"},
		"es":      {0: "other", 1: "one", 2: "other"},
		"fr":      {0: "one", 1: "one", 2: "other", 100: "other"},
		"zh-Hans": {0: "other", 1: "other", 2: "other"},
		"zh-Hant": {1: "other"},
		"ja":      {1: "other"},
		"ko":      {1: "other"},
	}
	for tag, m := range cases {
		l := set.ByTag(tag)
		for n, want := range m {
			if got := l.PluralCategory(n); got != want {
				t.Errorf("%s: PluralCategory(%d)=%s want %s", tag, n, got, want)
			}
		}
	}
	if got := strings.Join(set.ByTag("ja").PluralCategories(), ","); got != "other" {
		t.Errorf("ja categories %s", got)
	}
	// Selection in rendering.
	en := testLocale(t, "en")
	if got := en.Text("tplus.title.after", "days", 1); got != "1 day after disclosure" {
		t.Errorf("one: %q", got)
	}
	if got := en.Text("tplus.title.after", "days", 0); got != "0 days after disclosure" {
		t.Errorf("zero: %q", got)
	}
	if got := en.Text("tplus.title.after", "days", 2); got != "2 days after disclosure" {
		t.Errorf("other: %q", got)
	}
}

func TestNumberFormat(t *testing.T) {
	set, _ := Default()
	cases := map[string]map[int64]string{
		"en":      {0: "0", 999: "999", 1000: "1,000", 45965: "45,965", 1234567: "1,234,567", -1234: "-1,234"},
		"zh-Hans": {45965: "45,965"},
		"ja":      {45965: "45,965"},
		"ko":      {45965: "45,965"},
		"es":      {1000: "1000", 9999: "9999", 45965: "45.965", 1234567: "1.234.567"},
		"fr":      {1000: "1 000", 45965: "45 965", 999: "999"},
	}
	for tag, m := range cases {
		l := set.ByTag(tag)
		for n, want := range m {
			if got := l.Int(n); got != want {
				t.Errorf("%s: Int(%d)=%q want %q", tag, n, got, want)
			}
		}
	}
	// Numbers inside messages use the locale's grouping.
	if got := testLocale(t, "en").Text("statusline.vulns", "n", int64(45965)); got != "vulns 45,965" {
		t.Errorf("message number %q", got)
	}
}

func TestListsAndJoin(t *testing.T) {
	en, zh := testLocale(t, "en"), testLocale(t, "zh-Hans")
	for _, c := range []struct {
		l     *Locale
		kind  string
		items []string
		want  string
	}{
		{en, ListAnd, nil, ""}, {en, ListAnd, []string{"a"}, "a"}, {en, ListAnd, []string{"a", "b"}, "a and b"},
		{en, ListAnd, []string{"a", "b", "c"}, "a, b, and c"}, {en, ListAnd, []string{"a", "b", "c", "d"}, "a, b, c, and d"},
		{en, ListSeq, []string{"a", "b", "c"}, "a, b, c"},
		{zh, ListAnd, []string{"a", "b", "c"}, "a、b、c"}, {zh, ListSeq, []string{"a", "b"}, "a、b"},
	} {
		if got := c.l.List(c.kind, c.items); got != c.want {
			t.Errorf("%s %s %v = %q want %q", c.l.Tag, c.kind, c.items, got, c.want)
		}
	}
	if got := en.Join([]string{"A.", "B."}); got != "A. B." {
		t.Errorf("en join %q", got)
	}
	if got := zh.Join([]string{"甲。", "乙。"}); got != "甲。乙。" {
		t.Errorf("zh join %q", got)
	}
	// HTML lists keep items as HTML and escape the pattern text.
	if got := en.ListHTML(ListAnd, []template.HTML{"<a>x</a>", "<b>y</b>"}); got != "<a>x</a> and <b>y</b>" {
		t.Errorf("html list %q", got)
	}
}

func TestRenderEscapingAndMissing(t *testing.T) {
	en, zh := testLocale(t, "en"), testLocale(t, "zh-Hans")
	got := en.HTML("search.none", "query", `<script>"x"</script>`)
	if strings.Contains(string(got), "<script>") || !strings.Contains(string(got), "&lt;script&gt;") {
		t.Errorf("value not escaped: %s", got)
	}
	got = en.HTML("legend.tplus", "token", template.HTML("<code>T+</code>"))
	if !strings.Contains(string(got), "<code>T+</code>") {
		t.Errorf("html value not inserted: %s", got)
	}
	if got := zh.HTML("vuln.rejected.reason", "reason", Upstream("dup <x>")); got != `原因（原文）：<span lang="en">dup &lt;x&gt;</span>` {
		t.Errorf("upstream: %s", got)
	}
	if got := en.HTML("vuln.rejected.reason", "reason", Upstream("dup")); got != "Reason (verbatim): dup" {
		t.Errorf("upstream en: %s", got)
	}
	if got := en.Text("no.such.key"); got != MissingOpen+"no.such.key"+MissingClose {
		t.Errorf("missing key: %q", got)
	}
	if got := en.Text("search.none"); !strings.Contains(got, MissingOpen) {
		t.Errorf("missing value not marked: %q", got)
	}
	if got := en.Text("legend.tplus", "token", template.HTML("<code>T+</code>")); !strings.Contains(got, MissingOpen) {
		t.Errorf("HTML in plain text not refused: %q", got)
	}
	// Select messages.
	if got := en.Text("stage.name", "stage", "KEV"); got != "added to KEV" {
		t.Errorf("select %q", got)
	}
	if got := en.Text("ev.generic", "stage", "other", "source", "x"); got != "x reported an event." {
		t.Errorf("select other %q", got)
	}
}

// TestValidateCatches: the checks a writer relies on really fire.
func TestValidateCatches(t *testing.T) {
	src, _ := fs.ReadFile(embedded, "catalogs/en.json")
	base := string(src)
	cases := []struct {
		name, old, new, want string
	}{
		{"missing key", `"sbar.utc": "all times UTC",`, ``, "sbar.utc: missing"},
		{"unknown key", `"sbar.utc": "all times UTC",`, `"sbar.utc": "all times UTC", "sbar.extra": "x",`, "sbar.extra: unknown key"},
		{"unknown placeholder", `"statusline.vulns": "vulns {n}"`, `"statusline.vulns": "vulns {count}"`, "unknown placeholder {count}"},
		{"unused placeholder", `"statusline.vulns": "vulns {n}"`, `"statusline.vulns": "vulns"`, "placeholder {n} is not used"},
		{"html tag", `"sbar.utc": "all times UTC"`, `"sbar.utc": "all <b>times</b> UTC"`, "HTML tag"},
		{"entity", `"sbar.utc": "all times UTC"`, `"sbar.utc": "all&nbsp;times UTC"`, "HTML entity"},
		{"empty", `"sbar.utc": "all times UTC"`, `"sbar.utc": ""`, "sbar.utc: empty"},
		{"too long", `"btn.copy": "copy"`, `"btn.copy": "copy this command to the clipboard"`, "too long"},
		{"plural variant missing", `"one": "{n} event",`, ``, `plural variant "one" missing`},
		{"select variant missing", `"KEV": "added to KEV"`, `"XYZ": "added to KEV"`, `select variant "KEV" missing`},
		{"sentence end", `"status.kev.not_listed": "Not in CISA KEV."`, `"status.kev.not_listed": "Not in CISA KEV"`, "a sentence must end"},
		{"unbalanced brace", `"statusline.vulns": "vulns {n}"`, `"statusline.vulns": "vulns {n"`, "unclosed"},
		{"edge space", `"sbar.utc": "all times UTC"`, `"sbar.utc": "all times UTC "`, "whitespace"},
	}
	set, _ := Default()
	en := set.ByTag("en")
	for _, c := range cases {
		if !strings.Contains(base, c.old) {
			t.Fatalf("%s: fixture text %q not in en.json", c.name, c.old)
		}
		cat, probs := ParseCatalog([]byte(strings.Replace(base, c.old, c.new, 1)))
		if cat != nil {
			probs = append(probs, Validate(en, cat, set.Reference)...)
		}
		if !strings.Contains(strings.Join(probs, "\n"), c.want) {
			t.Errorf("%s: want a problem containing %q, got %v", c.name, c.want, probs)
		}
	}
	// Locale typography: CJK full-width punctuation, French no-break spaces.
	zh := set.ByTag("zh-Hans")
	if p := checkText(zh, set.Reference.Key("status.kev.not_listed"), "", "尚未列入 CISA KEV."); !strings.Contains(strings.Join(p, ";"), "。") {
		t.Errorf("zh ASCII full stop not caught: %v", p)
	}
	if p := checkText(zh, set.Reference.Key("cat.clear"), "", "可以搜索:"); len(p) == 0 {
		t.Error("zh ASCII colon not caught")
	}
	fr := set.ByTag("fr")
	if p := checkText(fr, set.Reference.Key("cat.clear"), "", "Vous pouvez chercher :"); len(p) == 0 {
		t.Error("fr ordinary space before ':' not caught")
	}
	if p := checkText(fr, set.Reference.Key("cat.clear"), "", "Vous pouvez chercher :"); len(p) != 0 {
		t.Errorf("fr no-break space rejected: %v", p)
	}
	if p := checkText(fr, set.Reference.Key("search.none"), "", "Aucun résultat pour « {query} »."); len(p) != 0 {
		t.Errorf("fr guillemets rejected: %v", p)
	}
	if p := checkText(fr, set.Reference.Key("search.none"), "", "Aucun résultat pour « {query} »."); len(p) == 0 {
		t.Error("fr guillemets with ordinary spaces not caught")
	}
}

// TestLoadRules: a catalog without a registry entry is an error; a broken
// catalog only disables its locale; the primary locale must be valid.
func TestLoadRules(t *testing.T) {
	copyFS := func() fstest.MapFS {
		m := fstest.MapFS{}
		_ = fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := fs.ReadFile(embedded, p)
				m[p] = &fstest.MapFile{Data: b}
			}
			return nil
		})
		return m
	}
	m := copyFS()
	m["catalogs/xx.json"] = &fstest.MapFile{Data: []byte(`{"locale":"xx","messages":{}}`)}
	if _, err := Load(m); err == nil {
		t.Error("catalog without registry entry accepted")
	}
	m = copyFS()
	m["catalogs/ja.json"] = &fstest.MapFile{Data: []byte(`{"locale":"ja","messages":{"sbar.utc":"UTC"}}`)}
	set, err := Load(m)
	if err != nil {
		t.Fatal(err)
	}
	if set.ByTag("ja").Enabled() || set.ByPrefix("ja") != nil || len(set.ByTag("ja").Problems()) < 100 {
		t.Errorf("incomplete ja enabled: %d problems", len(set.ByTag("ja").Problems()))
	}
	m = copyFS()
	m["catalogs/en.json"] = &fstest.MapFile{Data: []byte(`{"locale":"en","messages":{}}`)}
	if _, err := Load(m); err == nil {
		t.Error("invalid primary catalog accepted")
	}
}

func TestPathsAndCSS(t *testing.T) {
	set, _ := Default()
	en, zh := set.ByTag("en"), set.ByTag("zh-Hans")
	for in, want := range map[string]string{"/": "/zh-hans/", "/vuln/X": "/zh-hans/vuln/X", "/?a=b": "/zh-hans/?a=b", "": "/zh-hans/"} {
		if got := zh.Path(in); got != want {
			t.Errorf("Path(%q)=%q", in, got)
		}
	}
	if en.Path("/src") != "/src" || en.Home() != "/" {
		t.Error("primary paths")
	}
	css := FontCSS(set)
	for _, want := range []string{`:root:lang(zh-Hans) { --cjk: "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei"`,
		`:root:lang(zh-Hant) { --cjk: "PingFang TC", "Microsoft JhengHei"`, `:root:lang(ja) { --cjk: "Hiragino Sans"`,
		`:root:lang(ko) { --cjk: "Apple SD Gothic Neo", "Malgun Gothic"`} {
		if !strings.Contains(css, want) {
			t.Errorf("css missing %q in %s", want, css)
		}
	}
	if Cols("ab") != 2 || Cols("漏洞") != 4 || Cols("한국") != 4 || Cols("かな") != 4 {
		t.Error("Cols")
	}
}
