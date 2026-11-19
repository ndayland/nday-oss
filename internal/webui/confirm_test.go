package webui

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/webui/i18n"
)

// TestConfirmStepShared: the two-step confirm lives in app.js only
// (nday.confirmStep); the other scripts call it and have no arming code or
// browser dialog of their own. Static: there is no DOM to run the scripts in.
func TestConfirmStepShared(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	app := read("app.js")
	for _, want := range []string{"nday.confirmStep = confirmStep;", "nday.confirmable = confirmable;", "nday.disarm = disarm;",
		"'[data-k=\"btn.confirm\"]'", "setTimeout(function () { disarm(btn); }, 5000)", "e.key === 'Escape'", "'blur'"} {
		if !strings.Contains(app, want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
	for _, name := range []string{"admin.js", "account.js", "discuss.js"} {
		src := read(name)
		if !strings.Contains(src, "nday.confirmStep(") {
			t.Errorf("%s does not use nday.confirmStep", name)
		}
		for _, bad := range []string{"window.confirm", "confirm(msg", "dataset.armed = '", "dataset.timer", "armed = setTimeout",
			"frArmed", "admin.msg.confirm", "delete_confirm'", "feed_reset_confirm"} {
			if bad == "delete_confirm'" && name == "discuss.js" {
				continue // its sentence is the armed button's title
			}
			if strings.Contains(src, bad) {
				t.Errorf("%s still contains %q (its own two-step confirm)", name, bad)
			}
		}
	}
	// the buttons account.js builds are marked where they are created
	if n := strings.Count(read("account.js"), "nday.confirmable("); n != 2 {
		t.Errorf("account.js marks %d built buttons, want 2 (passkey and token delete)", n)
	}
	css := read("app.css")
	for _, want := range []string{".btn[data-confirm] {", ".btn[data-confirm]::before { content: attr(data-confirm);",
		`.btn[data-confirm][data-armed="1"]::after { content: attr(data-confirm);`} {
		if !strings.Contains(css, want) {
			t.Errorf("app.css lacks %q", want)
		}
	}
}

// TestConfirmButtonsMarked: every button of a template whose action takes
// the two-step confirm carries data-confirm from the server, so it has its
// final width from the first paint.
func TestConfirmButtonsMarked(t *testing.T) {
	const mark = `data-confirm="{{ts "btn.confirm"}}"`
	acts := regexp.MustCompile(`data-act="(dismiss|xenable|xdisable|xcadd|xcdismiss|xcrestore|ghtrust|ghreject|ghreset|ghowner|ghoenable|ghodisable|` +
		`xddiscard|xdrestore|unsuspend|role|signout|clearsecret|delete)"|data-bulk-act=|id="b-feed-reset"`)
	button := regexp.MustCompile(`(?s)<button\b[^>]*>`)
	n := 0
	_ = fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := fs.ReadFile(templateFS, p)
		for _, tag := range button.FindAllString(string(b), -1) {
			if !acts.MatchString(tag) {
				continue
			}
			n++
			if !strings.Contains(tag, mark) {
				t.Errorf("%s: %s lacks %s", p, tag, mark)
			}
		}
		return nil
	})
	if n < 20 {
		t.Errorf("found %d confirmable buttons, want at least 20", n)
	}
	// submit buttons of forms whose submit is confirmed (admin.js: suspend, corrections, X settings, mark posted,
	// add a trusted GitHub account)
	for file, want := range map[string]int{"admin_user.tmpl": 5, "admin_corr.tmpl": 2, "admin_x.tmpl": 7, "admin_xdrafts.tmpl": 3,
		"admin_github.tmpl": 10, "admin_settings.tmpl": 1, "parts.tmpl": 2, "account.tmpl": 1, "vuln.tmpl": 1} {
		b, err := fs.ReadFile(templateFS, "templates/"+file)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(b), mark); got != want {
			t.Errorf("%s: %d buttons with data-confirm, want %d", file, got, want)
		}
	}
}

// TestConfirmWord: the confirm word is one short word in every locale.
func TestConfirmWord(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"en", "zh-Hans", "zh-Hant", "ja", "ko", "es", "fr"} {
		l := set.ByTag(tag)
		if l == nil {
			t.Errorf("%s: no locale", tag)
			continue
		}
		w := l.Text("btn.confirm")
		if l.FallsBack("btn.confirm") || w == "" || strings.ContainsAny(w, "  ") {
			t.Errorf("%s: btn.confirm = %q (fallback %v)", tag, w, l.FallsBack("btn.confirm"))
		}
	}
}
