package webui

import (
	"bytes"
	"html/template"
	"net/http"
	"sort"

	"nday.land/nday/internal/webui/i18n"
)

// Catalog preview for writers (/__i18n/<tag>, only with Options.I18nDebug,
// i.e. NDAY_I18N_DEBUG=1). It renders every message of a locale with the
// example values of keys.json — every plural and select variant — plus the
// rule-generated sentences for the fixed scenarios, so a writer reads the
// whole locale in context on one page. It works for catalogs that are not
// enabled yet (invalid or incomplete): problems are listed at the top and
// missing messages show as ⟦key⟧. ?ref=<tag> adds another locale's output
// under each message, for orientation only.

type debugVariant struct {
	Name string
	Out  template.HTML
	Ref  template.HTML
}

type debugPH struct {
	Name, Kind, Meaning, Example string
	Optional                     bool
}

type debugKey struct {
	Def          *i18n.KeyDef
	Placeholders []debugPH
	Variants     []debugVariant
	SelectOn     string
}

type debugGroup struct {
	G    *i18n.Group
	Keys []debugKey
}

type debugScenario struct {
	Name string
	Keys []string
	Out  template.HTML
	Ref  template.HTML
}

type debugData struct {
	CSS      string
	L        *i18n.Locale
	Ref      *i18n.Locale
	All      []*i18n.Locale
	Problems []string
	Numbers  [][2]string
	Plurals  [][2]string
	Groups   []debugGroup
	Status   []debugScenario
	Events   []debugScenario
	Keys     int
}

func (u *UI) i18nIndex(w http.ResponseWriter, r *http.Request) {
	u.renderDebug(w, r, &debugData{CSS: u.assets.URL("app.css"), All: u.locales.All})
}

func (u *UI) i18nDebug(w http.ResponseWriter, r *http.Request) {
	l := u.locales.ByTag(r.PathValue("tag"))
	if l == nil {
		http.NotFound(w, r)
		return
	}
	var ref *i18n.Locale
	if t := r.URL.Query().Get("ref"); t != "" {
		if rl := u.locales.ByTag(t); rl != nil && rl != l {
			ref = rl
		}
	}
	u.renderDebug(w, r, BuildDebug(u.locales, l, ref, u.assets.URL("app.css")))
}

func (u *UI) renderDebug(w http.ResponseWriter, r *http.Request, d *debugData) {
	var buf bytes.Buffer
	if err := u.tmpl.debug.ExecuteTemplate(&buf, "i18n.tmpl", d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	setHTMLHeaders(h)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

// pluralSamples are counts tried to reach each plural category.
var pluralSamples = []int64{1, 2, 5, 0, 3, 11, 21, 101}

// BuildDebug assembles the catalog preview of l (ref: optional second locale).
func BuildDebug(set *i18n.Set, l, ref *i18n.Locale, css string) *debugData {
	d := &debugData{CSS: css, L: l, Ref: ref, All: set.All, Problems: l.Problems()}
	for _, n := range []int64{0, 1, 7, 1000, 45965, 1234567} {
		d.Numbers = append(d.Numbers, [2]string{i18n.Primary + " " + set.Primary().Int(n), l.Int(n)})
	}
	for _, n := range []int64{0, 1, 2, 5, 21} {
		d.Plurals = append(d.Plurals, [2]string{l.Int(n), l.PluralCategory(n)})
	}
	render := func(loc *i18n.Locale, key string, kv []any) template.HTML {
		if loc == nil {
			return ""
		}
		return loc.Highlight(key, kv...)
	}
	for _, g := range set.Reference.Groups {
		dg := debugGroup{G: g}
		for _, def := range g.Keys {
			dk := debugKey{Def: def}
			var names []string
			for n := range def.Placeholders {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p := def.Placeholders[n]
				dk.Placeholders = append(dk.Placeholders, debugPH{n, p.Kind, p.Meaning, p.Example, p.Optional})
			}
			kv := def.ExampleArgs()
			switch {
			case def.Plural != "":
				dk.SelectOn = "{" + def.Plural + "}"
				for _, cat := range l.PluralCategories() {
					n := int64(-1)
					for _, s := range pluralSamples {
						if l.PluralCategory(s) == cat {
							n = s
							break
						}
					}
					if n < 0 {
						continue
					}
					args := append(append([]any(nil), kv...), def.Plural, n)
					dk.Variants = append(dk.Variants, debugVariant{Name: cat + " (" + l.Int(n) + ")",
						Out: render(l, def.Key, args), Ref: render(ref, def.Key, args)})
				}
			case def.Select != nil:
				dk.SelectOn = def.Select.Var
				for _, v := range def.Select.Values {
					args := append(append([]any(nil), kv...), def.Select.Var, v)
					name := v
					if m := def.Select.Meaning[v]; m != "" {
						name += " — " + m
					}
					dk.Variants = append(dk.Variants, debugVariant{Name: name, Out: render(l, def.Key, args),
						Ref: render(ref, def.Key, args)})
				}
			default:
				dk.Variants = append(dk.Variants, debugVariant{Out: render(l, def.Key, kv), Ref: render(ref, def.Key, kv)})
			}
			dg.Keys = append(dg.Keys, dk)
			d.Keys++
		}
		d.Groups = append(d.Groups, dg)
	}
	for _, s := range StatusScenarios() {
		ms := StatusMessages(s.V)
		ds := debugScenario{Name: s.Name, Out: template.HTML(template.HTMLEscapeString(renderMsgs(l, ms)))}
		if ref != nil {
			ds.Ref = template.HTML(template.HTMLEscapeString(renderMsgs(ref, ms)))
		}
		for _, m := range ms {
			ds.Keys = append(ds.Keys, m.Key)
		}
		d.Status = append(d.Status, ds)
	}
	for _, s := range EventScenarios() {
		ms := EventMessages(s.E)
		ds := debugScenario{Name: s.Name, Out: EventText(l, s.E)}
		if ref != nil {
			ds.Ref = EventText(ref, s.E)
		}
		for _, m := range ms {
			ds.Keys = append(ds.Keys, m.Key)
		}
		d.Events = append(d.Events, ds)
	}
	return d
}
