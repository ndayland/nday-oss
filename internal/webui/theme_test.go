package webui_test

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nday.land/nday/internal/webui"
)

// The colour theme: static/theme.js runs in <head> before the stylesheet
// (render-blocking, so a reader who chose light never sees a dark frame), is
// served like every other hashed asset, and the top bar carries the menu.
func TestThemeScriptAndMenu(t *testing.T) {
	e := newEnv(t)
	if !strings.Contains(webui.CSP, "script-src 'self'") || !strings.Contains(webui.CSP, "style-src 'self'") ||
		strings.Contains(webui.CSP, "unsafe-inline") {
		t.Errorf("CSP changed: %q", webui.CSP)
	}
	script := regexp.MustCompile(`<script src="(/static/theme\.[0-9a-f]{12}\.js)"></script>`)
	for _, p := range []string{"/", "/zh-hans/", "/vuln/CVE-2026-1001", "/about"} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != webui.CSP {
			t.Errorf("%s: %d, CSP %q", p, resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
			continue
		}
		head, _, _ := strings.Cut(body, "</head>")
		m := script.FindStringSubmatchIndex(head)
		css := strings.Index(head, `<link rel="stylesheet"`)
		if m == nil || css < 0 || m[0] > css {
			t.Errorf("%s: theme script missing from <head>, deferred, or after the stylesheet", p)
			continue
		}
		if strings.Index(head, "<script") != m[0] {
			t.Errorf("%s: theme script is not the first script", p)
		}
		src := head[m[2]:m[3]]
		r, js := e.get(t, src)
		if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(js, "nday.theme") {
			t.Errorf("%s: %d %q %q", src, r.StatusCode, r.Header.Get("Cache-Control"), r.Header.Get("Content-Type"))
		}
		if !strings.Contains(body, `<details class="theme">`) {
			t.Errorf("%s: no theme menu", p)
		}
		for _, v := range []string{"dark", "light", "system"} {
			if !strings.Contains(body, `<button type="button" data-theme-set="`+v+`"`) {
				t.Errorf("%s: no %s button", p, v)
			}
		}
		if !strings.Contains(body, `<meta name="color-scheme" content="dark"/>`) {
			t.Errorf("%s: the no-script page is not dark", p)
		}
	}
	if _, body := e.get(t, "/zh-hans/"); !strings.Contains(body, ">跟随系统</button>") {
		t.Error("zh-Hans theme menu not localized")
	}
}

// cssBlock returns the declarations of the first rule whose selector is
// exactly sel (top level of app.css), as name -> value.
func cssBlock(t *testing.T, css, sel string) map[string]string {
	t.Helper()
	i := strings.Index(css, "\n"+sel+" {\n")
	if i < 0 {
		t.Fatalf("app.css: no %q block", sel)
	}
	body := css[i+len(sel)+4:]
	body = body[:strings.Index(body, "\n}")]
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
	out := map[string]string{}
	for _, d := range strings.Split(body, ";") {
		k, v, ok := strings.Cut(d, ":")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

var hexColour = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
var anyColour = regexp.MustCompile(`(?i)^(#[0-9a-f]{3,8}|(rgb|hsl|oklch|lab|lch)a?\(.*\)|white|black|transparent)$`)

// Every colour of the dark :root block is redefined by the light block, so a
// colour added later cannot be forgotten in one theme; the light block holds
// colours only.
func TestLightThemeRedefinesEveryColour(t *testing.T) {
	b, err := os.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	dark := cssBlock(t, css, ":root")
	light := cssBlock(t, css, `:root[data-theme="light"]`)
	if dark["color-scheme"] != "dark" || light["color-scheme"] != "light" {
		t.Errorf("color-scheme: dark %q, light %q", dark["color-scheme"], light["color-scheme"])
	}
	n := 0
	for k, v := range dark {
		if !strings.HasPrefix(k, "--") || !anyColour.MatchString(v) {
			continue
		}
		n++
		if _, ok := light[k]; !ok {
			t.Errorf("%s (%s) is not redefined by the light theme", k, v)
		}
	}
	if n < 20 {
		t.Errorf("only %d colours found in :root; parser broken?", n)
	}
	for k, v := range light {
		if k == "color-scheme" {
			continue
		}
		if !anyColour.MatchString(v) {
			t.Errorf("light theme: %s: %q is not a colour", k, v)
		}
		if _, ok := dark[k]; !ok {
			t.Errorf("light theme: %s has no dark counterpart", k)
		}
	}
}

func luminance(hex string) float64 {
	c := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		x := float64(v) / 255
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*c(hex[1:3]) + 0.7152*c(hex[3:5]) + 0.0722*c(hex[5:7])
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// WCAG contrast of both palettes: text colours >= 4.5:1 on each ground they
// are used on (--bg, --bar, --sel), control borders and the "no record"
// marker >= 3:1, and --bg text on the filled chips (ransomware tag, role
// badge, NORMAL mode, current segment) >= 4.5:1.
func TestThemeContrast(t *testing.T) {
	b, err := os.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	dark := cssBlock(t, css, ":root")
	themes := map[string]map[string]string{"dark": dark, "light": cssBlock(t, css, `:root[data-theme="light"]`)}
	text := []string{"--fg", "--fg2", "--fg3", "--prose", "--hover", "--green", "--dis", "--pat", "--ana", "--poc", "--itw", "--kev",
		"--tc-exec", "--tc-mem", "--tc-authz", "--tc-web"}
	for name, p := range themes {
		col := func(k string) string {
			v := p[k]
			if !hexColour.MatchString(v) {
				t.Fatalf("%s: %s = %q, want #RRGGBB", name, k, v)
			}
			return v
		}
		check := func(fg, bg string, min float64) {
			if c := contrast(col(fg), col(bg)); c < min {
				t.Errorf("%s: %s on %s = %.2f:1, want >= %.1f", name, fg, bg, c, min)
			}
		}
		for _, g := range []string{"--bg", "--bar", "--sel"} {
			for _, k := range text {
				check(k, g, 4.5)
			}
			check("--none", g, 3)
			check("--ctl", g, 3)
		}
		for _, k := range []string{"--green", "--kev", "--fg", "--hover"} {
			check("--bg", k, 4.5)
		}
	}
}
