package webui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"nday.land/nday/internal/webui/i18n"
)

// The scans below keep user-visible natural language out of templates, Go
// view code and app.js, so every word comes from a catalog.
//
// Templates (except templates/debug/, a developer tool): comments and
// {{actions}} are removed; what remains is literal markup. In its text nodes
// and in the user-visible attributes (title, aria-label, placeholder, alt)
// every Han/Kana/Hangul character fails, and every alphabetic word must be in
// templateTokens — a short allowlist of language-neutral tokens (codes,
// brand, vim mode, keys). This is stricter than a list of forbidden English
// words: a new English word in a template fails until it is moved to the
// catalog or (if it truly is a neutral token) allowlisted here.
//
// Go (non-test files of this package except scenarios.go/debug.go): every
// string literal is checked. Han/Kana/Hangul fails. A literal that looks like
// natural language (two alphabetic words of 2+ letters separated by a space)
// fails unless it is an argument of a logging/error call or listed in
// goPhrases (commands, CSP, endpoint names). Single English words in Go are
// NOT caught (they are indistinguishable from class names, keys and enum
// values); the rendered-page test TestPrimaryLocaleHasNoCJK and the probe
// test TestGeneratedTextIsCatalogOnly cover the generated text instead.
//
// app.js: string literals with Han/Kana/Hangul or two-word phrases fail;
// its words come from data-t-* attributes and data-hint/data-dismiss.
//
// Limits: a single English word assembled in Go (e.g. a label "ok"), text
// built from runes or byte slices, and CSS content: strings are not checked.

var templateTokens = map[string]bool{
	"nday": true, "land": true, "rss": true, "api": true, "NORMAL": true, "HTTP": true, "REJECTED": true,
	"DIS": true, "PAT": true, "ANA": true, "POC": true, "ITW": true, "KEV": true, "Enter": true,
	"T": true, "d": true, "Z": true, // T+, T+8d, 2026-11-09T22:15Z
	"j": true, "k": true, "y": true, "r": true, "o": true, "u": true, // keyboard keys
	"init": true, // the command echo of the welcome page ("nday init --handle ...")
}

// tokenRe matches flags (--since), paths (~/vuln/) and HTML entities, which
// are language-neutral by design.
var tokenRe = regexp.MustCompile(`--[a-z-]+|~/[a-z/]*|&[a-z]+;|&#[0-9]+;`)

var goPhrases = map[string]bool{
	CSP: true, "internal error": true, "public, max-age=60": true, "public, max-age=86400": true,
	"public, max-age=300": true, "public, max-age=31536000, immutable": true,
	"User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /raw/\n": true,
	"curl -s ": true, "pip install -U ": true, "npm install ": true, "gem install ": true, "dotnet add package ": true,
	" --version ": true, "GET /api/hot": true, "GET /api/vuln/{cve}": true, "GET /api/search": true, "GET /api/sources": true,
	"GET /api/stats": true, "GET /raw/{source}/{key}.json": true, "GET /healthz": true, "GET ": true,
	"(detail could not be rendered)": true, "404 not found": true, "expected true or false": true,
	"tag:nday.land,2026:transition/": true, "text/html; charset=utf-8": true, "text/css; charset=utf-8": true,
	"text/javascript; charset=utf-8": true, "application/atom+xml; charset=utf-8": true,
	"mk mk-none": true, "mk mk-known": true, "mk mk-hollow": true, // CSS classes
	"iOS and iPadOS": true, "Palo Alto Networks": true, // brand names of the follow presets (welcome.go)
}

var jsLiterals = map[string]bool{"'use strict'": true, "'btn sm'": true,
	// rel values of links built by discuss.js (comment bodies, posts on X)
	"'nofollow ugc noopener noreferrer'": true, "'noopener noreferrer nofollow'": true}

var (
	wordRe   = regexp.MustCompile(`[A-Za-z]+`)
	phraseRe = regexp.MustCompile(`[A-Za-z]{2,}[ \x{00a0}]+[A-Za-z]{2,}`)
	attrRe   = regexp.MustCompile(`\b(title|aria-label|placeholder|alt)="([^"]*)"`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
	actionRe = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
)

func hasWide(s string) bool {
	for _, r := range s {
		if i18n.IsWide(r) {
			return true
		}
	}
	return false
}

func TestNoHardcodedTextInTemplates(t *testing.T) {
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, "templates/debug/") {
			return err
		}
		b, _ := fs.ReadFile(templateFS, p)
		src := actionRe.ReplaceAllString(string(b), " ") // comments are actions too
		var texts []string
		for _, tag := range tagRe.FindAllString(src, -1) {
			for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
				texts = append(texts, m[2])
			}
		}
		texts = append(texts, tagRe.ReplaceAllString(src, " "))
		for _, s := range texts {
			s = tokenRe.ReplaceAllString(s, " ")
			if hasWide(s) {
				t.Errorf("%s: CJK text in template: %q", p, strings.TrimSpace(s))
			}
			for _, w := range wordRe.FindAllString(s, -1) {
				if !templateTokens[w] {
					t.Errorf("%s: word %q in template text; put it in the catalog", p, w)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// exemptCall reports whether a call's literals are not page text (logging,
// errors, panics, headers).
func exemptCall(c *ast.CallExpr) bool {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name == "panic"
	case *ast.SelectorExpr:
		switch f.Sel.Name {
		case "Error", "Warn", "Info", "Debug", "Errorf", "New", "Set", "Header",
			"MustCompile": // regular expressions (prose.go matches kernel log lines)
			return true
		}
	}
	return false
}

func TestNoHardcodedTextInGo(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "scenarios.go" || f == "debug.go" {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for i := len(stack) - 2; i >= 0; i-- {
				if c, ok := stack[i].(*ast.CallExpr); ok && exemptCall(c) {
					return true
				}
			}
			switch stack[len(stack)-2].(type) {
			case *ast.ImportSpec, *ast.Field: // import paths, struct tags
				return true
			}
			if strings.ContainsAny(s, `<"`) { // markup fragments built for placeholders
				return true
			}
			pos := fset.Position(lit.Pos())
			if hasWide(s) {
				t.Errorf("%s: CJK string literal %q; move it to the catalog", pos, s)
			} else if phraseRe.MatchString(s) && !goPhrases[s] {
				t.Errorf("%s: natural-language string literal %q; move it to the catalog (or allowlist a neutral token in goPhrases)", pos, s)
			}
			return true
		})
	}
}

func TestNoHardcodedTextInJS(t *testing.T) {
	for _, name := range []string{"app.js", "account.js", "discuss.js", "admin.js", "theme.js"} {
		b, err := os.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range jsStrings(string(b)) {
			if hasWide(m) || (phraseRe.MatchString(m) && !jsLiterals[m]) {
				t.Errorf("%s: literal %s; words come from the page (data-t-*, <template id=\"acct-msgs\">)", name, m)
			}
		}
	}
}

// jsStrings returns the string and template literals of a script (with
// their quotes), skipping // and /* */ comments. Regular expression
// literals are not recognised; the scripts keep quotes out of them.
func jsStrings(src string) []string {
	var out []string
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out
			}
			i += end + 3
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return out
			}
			out = append(out, src[i:j+1])
			i = j
		}
	}
	return out
}

// TestKeyUsage: every key of the reference is used by code or templates,
// and every key code or templates use is in the reference.
func TestKeyUsage(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	ref := set.Reference
	prefixes := map[string]bool{}
	for _, k := range ref.Keys() {
		p, _, _ := strings.Cut(k, ".")
		prefixes[p] = true
	}
	keyLit := regexp.MustCompile(`"([a-z]+(?:\.[a-z0-9_]+)+)"`)
	used := map[string]string{}
	scan := func(name, src string) {
		for _, m := range keyLit.FindAllStringSubmatch(src, -1) {
			if strings.HasSuffix(m[1], ".js") || strings.HasSuffix(m[1], ".css") {
				continue // asset names (asset "admin.js"), not message keys
			}
			p, _, _ := strings.Cut(m[1], ".")
			if prefixes[p] {
				used[m[1]] = name
			}
		}
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		scan(f, string(b))
	}
	_ = fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(templateFS, p)
			scan(p, string(b))
		}
		return nil
	})
	// Built from a kind name in i18n.List and Join.
	for _, k := range []string{"sentence.joiner"} {
		used[k] = "i18n"
	}
	for _, kind := range []string{i18n.ListAnd, i18n.ListSeq} {
		for _, part := range []string{"two", "start", "middle", "end"} {
			used["list."+kind+"."+part] = "i18n"
		}
	}
	var unknown, unused []string
	for k, where := range used {
		if ref.Key(k) == nil {
			unknown = append(unknown, k+" ("+where+")")
		}
	}
	for _, k := range ref.Keys() {
		if _, ok := used[k]; !ok {
			unused = append(unused, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		t.Errorf("key used but not in keys.json: %s", k)
	}
	for _, k := range unused {
		t.Errorf("key in keys.json but never used: %s", k)
	}
}
