package webui_test

import (
	"html/template"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// The about page's list rules show the pinning numbers in force (never
// numbers typed into the catalog), say so when pinning is off, and the
// home page links to them.
func TestAboutHotRules(t *testing.T) {
	e := newEnv(t)
	set := e.ui.Locales()
	en, zh := set.Primary(), set.ByTag("zh-Hans")
	code := func(s string) template.HTML { return template.HTML("<code>" + s + "</code>") }
	pinLines := func(l interface {
		HTML(string, ...any) template.HTML
	}, c site.PinConfig) []string {
		recent, wave := c.Days()
		return []string{
			string(l.HTML("about.hot.pin", "max", c.Max)),
			string(l.HTML("about.hot.pin_count", "n", c.MinResearchers, "window", code("7d"))),
			string(l.HTML("about.hot.pin_recent", "days", recent)),
			string(l.HTML("about.hot.pin_wave", "days", wave)),
		}
	}
	for _, c := range []site.PinConfig{site.DefaultPinConfig,
		{Max: 3, MinResearchers: 1, Recent: 12 * time.Hour, Wave: 2 * 24 * time.Hour}} {
		e.store.SetPinConfig(c)
		_, body := e.get(t, "/about")
		_, zbody := e.get(t, "/zh-hans/about")
		if !strings.Contains(body, `id="hot-rules"`) || !strings.Contains(zbody, `id="hot-rules"`) {
			t.Fatal("no rules section")
		}
		for _, want := range append(pinLines(en, c), string(en.HTML("about.hot.repeat")),
			string(en.HTML("about.hot.window", "window", code("7d"), "stage", template.HTML(`<span class="b st-pat">PAT</span>`),
				"since", code("--since"), "min_stage", code("--min-stage"), "rejected", code("--include-rejected")))) {
			if !strings.Contains(body, want) {
				t.Errorf("en about (%+v) missing %q", c, want)
			}
		}
		for _, want := range pinLines(zh, c) {
			if !strings.Contains(zbody, want) {
				t.Errorf("zh about (%+v) missing %q", c, want)
			}
		}
		if strings.Contains(body, en.Text("about.hot.pin_off")) {
			t.Errorf("pinning on (%+v) but said off", c)
		}
	}
	e.store.SetPinConfig(site.PinConfig{Max: 0, MinResearchers: 2, Recent: time.Hour, Wave: 24 * time.Hour})
	_, body := e.get(t, "/about")
	if !strings.Contains(body, en.Text("about.hot.pin_off")) || strings.Contains(body, `class="rules-l"`) {
		t.Error("pinning off not stated")
	}
	_, body = e.get(t, "/zh-hans/")
	if !strings.Contains(body, `href="/zh-hans/about#hot-rules"`) || !strings.Contains(body, zh.Text("hot.rules_link")) {
		t.Error("home page does not link to the rules")
	}
}

// The vulnerability page explains the exploitability metrics of the vector
// behind the CVSS score, and the hot list says what changed in words.
func TestCVSSAndChangeOnPages(t *testing.T) {
	e := newEnv(t)
	set := e.ui.Locales()
	en := set.Primary()
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	for _, want := range []string{`id="cvh"`, "<code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code>",
		"<code>AV:N</code>", en.Text("vuln.cvss.av", "v", "N"), en.Text("vuln.cvss.ui", "v", "N"), "CVSS 3.1 vector from"} {
		if !strings.Contains(body, want) {
			t.Errorf("vuln page missing %q", want)
		}
	}
	// A vulnerability without a vector has no block, not an empty one.
	_, body = e.get(t, "/vuln/CVE-2026-1001")
	if strings.Contains(body, `id="cvh"`) || strings.Contains(body, en.Text("vuln.cvss.h2")) {
		t.Error("exploit conditions block without a vector")
	}
	_, body = e.get(t, "/?since=30d")
	if !strings.Contains(body, `<span class="w">`+en.Text("hot.change", "stage", "KEV")+`</span> <span class="cd" aria-hidden="true">&#43;KEV</span>`) {
		t.Error("hot row without the change in words")
	}
}
