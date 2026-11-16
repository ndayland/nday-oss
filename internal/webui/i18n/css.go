package i18n

import (
	"html"
	"html/template"
	"strings"
)

// FontCSS returns the per-locale font rules generated from the registry:
//
//	:root:lang(ja) { --cjk: "Hiragino Sans", "Yu Gothic", ...; }
//
// app.css builds --mono and --sans on top of --cjk, so Han characters get the
// regional glyphs of the page's language. Inner elements with another lang
// (lang="en" on upstream text) keep the page's stack, which is what we want:
// Latin glyphs come from the Latin fonts first anyway.
func FontCSS(s *Set) string {
	var b strings.Builder
	b.WriteString("\n/* generated from internal/webui/i18n/locales.json (fonts_cjk) */\n")
	for _, l := range s.All {
		if len(l.FontsCJK) == 0 {
			continue
		}
		var fams []string
		for _, f := range l.FontsCJK {
			fams = append(fams, `"`+strings.NewReplacer(`"`, ``, `\`, ``, "\n", "").Replace(f)+`"`)
		}
		b.WriteString(":root:lang(" + cssIdent(l.Tag) + ") { --cjk: " + strings.Join(fams, ", ") + "; }\n")
	}
	return b.String()
}

func cssIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// htmlExample renders the example of an html placeholder: the page builds
// such values as inline elements (<code>, <kbd>, links, stage codes).
func htmlExample(ex string) template.HTML {
	return template.HTML("<code>" + html.EscapeString(ex) + "</code>")
}
