package webui

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
)

// TestBuildResourcesView: groups in kind order, link texts without the
// scheme and cut, unshowable URLs left out, nil when nothing remains.
func TestBuildResourcesView(t *testing.T) {
	rs := []site.Resource{
		{URL: "https://exploit-db.com/exploits/1", Kind: "poc", Researchers: 1},
		{URL: "https://GitHub.com/o/r/commit/" + strings.Repeat("a", 60), Kind: "patch", Researchers: 3},
		{URL: "https://example.com/", Kind: "other", Researchers: 1},
		{URL: "https://example.com/p?q=1#frag", Kind: "other", Researchers: 2},
		{URL: "javascript:alert(1)", Kind: "other", Researchers: 1},
	}
	v := BuildResourcesView(rs)
	if v == nil || len(v.Groups) != 3 {
		t.Fatalf("%+v", v)
	}
	var got []string
	for _, g := range v.Groups {
		for _, l := range g.Links {
			got = append(got, g.Kind+"|"+g.LabelKey+"|"+l.Text)
		}
	}
	want := []string{"poc|rsch.res.poc|exploit-db.com/exploits/1",
		"patch|rsch.res.patch|github.com/o/r/commit/" + strings.Repeat("a", 25) + "…",
		"other|rsch.res.other|example.com", "other|rsch.res.other|example.com/p?q=1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if BuildResourcesView(nil) != nil || BuildResourcesView([]site.Resource{{URL: "ftp://a.example/", Kind: "other"}}) != nil {
		t.Error("an empty section")
	}
	// a title: shown with the host (Resource.Host, else from the URL)
	v = BuildResourcesView([]site.Resource{{URL: "https://www.Blog.example/p", Kind: "other", Title: "A <b>write-up</b>", Researchers: 1},
		{URL: "https://c.example/q", Host: "c.example", Kind: "other", Title: "Other"}, {URL: "https://d.example/r", Kind: "other"}})
	if l := v.Groups[0].Links; len(l) != 3 || l[0].Title != "A <b>write-up</b>" || l[0].Host != "blog.example" || l[0].Text != "www.blog.example/p" ||
		l[1].Host != "c.example" || l[2].Title != "" || l[2].Host != "" || l[2].Text != "d.example/r" {
		t.Errorf("titles: %+v", l)
	}
}

// TestDiscussLinkParts runs linkParts of static/discuss.js (between its
// begin/end markers) in node: t.co links with an http/https final URL
// become links shown without the scheme; a non-http final URL or a short
// link without a resolved row stays text; the text is otherwise unchanged.
func TestDiscussLinkParts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	b, err := os.ReadFile("static/discuss.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i, j := strings.Index(src, "// linkParts-begin"), strings.Index(src, "// linkParts-end")
	if i < 0 || j < i {
		t.Fatal("no linkParts markers in discuss.js")
	}
	type link struct {
		Short string `json:"short_url"`
		Final string `json:"final_url"`
	}
	type tc struct {
		Text  string `json:"text"`
		Links []link `json:"links"`
	}
	long := "https://github.com/owner/repository/commit/" + strings.Repeat("0123456789", 4)
	cases := []tc{
		{"PoC https://t.co/AAA and https://t.co/BBB https://t.co/AAAx end", []link{
			{"https://t.co/AAA", "https://github.com/o/r/commit/abc"}, {"https://t.co/BBB", "javascript:alert(1)"}}},
		{"no rows https://t.co/CCC", nil},
		{"https://t.co/DDD", []link{{"https://t.co/DDD", long}}},
		{"x https://t.co/EEE", []link{{"https://t.co/EEE", "https://example.com/"}, {"https://t.co/FFF", "https://u:p@example.com/"}}},
		{"", []link{{"https://t.co/GGG", "https://example.com/"}}},
	}
	in, _ := json.Marshal(cases)
	script := src[i:j] + "\nconst cases = " + string(in) + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => linkParts(c.text, c.links))));\n"
	out, err := exec.Command(node, "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	type part struct {
		T    string `json:"t"`
		Href string `json:"href"`
	}
	var got [][]part
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := [][]part{
		{{"PoC ", ""}, {"github.com/o/r/commit/abc", "https://github.com/o/r/commit/abc"},
			{" and https://t.co/BBB https://t.co/AAAx end", ""}},
		{{"no rows https://t.co/CCC", ""}},
		{{"github.com/owner/repository/commit/012345678901…", long}},
		{{"x ", ""}, {"example.com", "https://example.com/"}},
		{{"", ""}},
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("linkParts:\n got %s\nwant %s", g, w)
	}
	// rendering: text nodes and elements only, the link rel of posts
	for _, s := range []string{"textWithIDs(tx, x.t);", "parent.appendChild(d.createTextNode(x.t));", "c.textContent = x.t;",
		"xlink(a, x.href);", "a.textContent = x.t;",
		"(u.protocol !== 'http:' && u.protocol !== 'https:')"} {
		if !strings.Contains(src, s) {
			t.Errorf("discuss.js: missing %q", s)
		}
	}
}

// TestDiscussCVEParts runs cveParts of static/discuss.js in node: CVE ids
// (any case, 4+ digit sequence) come out as their own pieces, the text
// around them unchanged, so the pieces join back to the input.
func TestDiscussCVEParts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	b, err := os.ReadFile("static/discuss.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i, j := strings.Index(src, "// cveParts-begin"), strings.Index(src, "// cveParts-end")
	if i < 0 || j < i {
		t.Fatal("no cveParts markers in discuss.js")
	}
	cases := []string{"PoC for CVE-2026-1234 and cve-2025-123456.", "CVE-2026-123 is not one", "", "CVE-2026-0001CVE-2026-0002",
		"\u202eCVE-2026-55555"}
	in, _ := json.Marshal(cases)
	script := src[i:j] + "\nconst cases = " + string(in) + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => cveParts(c))));\n"
	out, err := exec.Command(node, "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	type part struct {
		T   string `json:"t"`
		CVE bool   `json:"cve,omitempty"`
	}
	var got [][]part
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := [][]part{
		{{"PoC for ", false}, {"CVE-2026-1234", true}, {" and ", false}, {"cve-2025-123456", true}, {".", false}},
		{{"CVE-2026-123 is not one", false}},
		{{"", false}},
		{{"CVE-2026-0001", true}, {"CVE-2026-0002", true}},
		{{"\u202e", false}, {"CVE-2026-55555", true}},
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("cveParts:\n got %s\nwant %s", g, w)
	}
	// the ids are text in a span, never markup
	for _, s := range []string{"const c = el('span', 'rp-cve');", "c.textContent = x.t;"} {
		if !strings.Contains(src, s) {
			t.Errorf("discuss.js: missing %q", s)
		}
	}
	if strings.Contains(src, "innerHTML") {
		t.Error("discuss.js uses innerHTML")
	}
}
