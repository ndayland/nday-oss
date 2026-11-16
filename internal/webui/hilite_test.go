package webui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hlMarkup shows the tokens of a block as «class|text» (plain text as is),
// one line per line, after a "kind:" line.
func hlMarkup(text string) string {
	var b strings.Builder
	b.WriteString("kind: " + hiliteKind(text) + "\n")
	for i, l := range Hilite(text) {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, t := range l.Toks {
			if t.Class == "" {
				b.WriteString(t.Text)
			} else {
				b.WriteString("«" + t.Class + "|" + t.Text + "»")
			}
		}
	}
	return b.String()
}

// hlCase is one block of testdata/hilite/cases.txt: a code block that
// FormatText cut out of the named record (long ones cut to their first
// lines), the shape it stands for, and the tokens it must give.
type hlCase struct{ head, text, want string }

func loadHiliteCases(t testing.TB) (string, []hlCase) {
	t.Helper()
	path := filepath.Join("testdata", "hilite", "cases.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cs []hlCase
	for _, part := range strings.SplitAfter(string(b), "\n%%% end\n") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		head, rest, ok := strings.Cut(strings.TrimPrefix(part, "%%% "), "\n")
		text, want, ok2 := strings.Cut(rest, "\n%%% want\n")
		want, ok3 := strings.CutSuffix(want, "%%% end\n")
		if !ok || !ok2 || !ok3 {
			t.Fatalf("%s: bad case %q", path, part)
		}
		cs = append(cs, hlCase{head, text, strings.TrimSuffix(want, "\n")})
	}
	return path, cs
}

// TestHiliteCases: the tokens of real blocks, one per kind and trap (go test
// ./internal/webui -run TestHiliteCases -update rewrites the "want" parts;
// review the diff).
func TestHiliteCases(t *testing.T) {
	path, cs := loadHiliteCases(t)
	var out strings.Builder
	for _, c := range cs {
		got := hlMarkup(c.text)
		out.WriteString("%%% " + c.head + "\n" + c.text + "\n%%% want\n" + got + "\n%%% end\n")
		if !*update && got != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.head, got, c.want)
		}
	}
	if *update {
		if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// every kind is covered
	kinds := map[string]bool{}
	for _, c := range cs {
		kinds[hiliteKind(c.text)] = true
	}
	for _, k := range kindNames {
		if !kinds[k] {
			t.Errorf("no case of kind %s", k)
		}
	}
}

// TestHiliteTraps pins single rules with lines from real records (CVE
// named) and, where the data has no example, with a written line (marked).
func TestHiliteTraps(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		// "//" after ':' (a URL) or a word ("results//generic") opens no
		// comment (written: the data has no URL in source)
		{"url in src (written)", "url = fetch(\"x\"); // see http://a/b\nget(http://example.com/x);",
			"kind: src\nurl = «hf|fetch»(«hs|\"x\"»); «hc|// see http://a/b»\n«hf|get»(http://example.com/x);"},
		// a string or char literal that does not close on its line is
		// plain and does not reach the next line (written)
		{"open string (written)", "printk(\"abc\nfoo(x);", "kind: src\n«hf|printk»(\"abc\n«hf|foo»(x);"},
		{"open char (written)", "c = 'x;\nbar(y);", "kind: src\nc = 'x;\n«hf|bar»(y);"},
		// CVE-2021-47375: an apostrophe after a letter is not a quote
		{"apostrophe in call", "blk_add_trace_msg(sdb's bt);", "kind: src\n«hf|blk_add_trace_msg»(sdb's bt);"},
		// CVE-2022-49925: "#" in a diagram is neither a comment nor code
		{"hash in diagram", "ib_core_init()\n  roce_gid_mgmt_init()\n    gid_cache_wq = alloc_ordered_workqueue # fail\n    destroy_workqueue(gid_cache_wq)\n    # destroy an unallocated wq",
			"kind: src\n«hf|ib_core_init»()\n  «hf|roce_gid_mgmt_init»()\n    gid_cache_wq = alloc_ordered_workqueue # fail\n    «hf|destroy_workqueue»(gid_cache_wq)\n    # destroy an unallocated wq"},
		// an unclosed /* without its */ in the block ends at the line (written)
		{"unclosed block comment (written)", "foo(); /* never closed\nbar();\nbaz();",
			"kind: src\n«hf|foo»(); «hc|/* never closed»\n«hf|bar»();\n«hf|baz»();"},
		// a /* ... */ over lines with a second column does not span (written)
		{"block comment over two columns (written)", "a();  /* x\nb();         c();\n */",
			"kind: src\n«hf|a»();  «hc|/* x»\n«hf|b»();         «hf|c»();\n */"},
		// shell: '#' at a word's start after a blank only (CVE-2023-52879 shape)
		{"shell hash", "# cd /sys/kernel/tracing\n# echo 'p:sched schedule' > kprobe_events\n# echo x#y $# > f",
			"kind: shell\n«hm|# »«hf|cd» /sys/kernel/tracing\n«hm|# »«hf|echo» «hs|'p:sched schedule'» > kprobe_events\n«hm|# »«hf|echo» x#y $# > f"},
		// offsets hold with blanks around a line (written; FormatText trims
		// trailing blanks, Hilite does not rely on it)
		{"blanks around (written)", "  # echo hi   \n  # ls  ", "kind: shell\n  «hm|# »«hf|echo» hi   \n  «hm|# »«hf|ls»  "},
		{"http blanks (written)", " HTTP/1.1 200 OK  \n X-A: b ", "kind: http\n HTTP/1.1 «hn|200» OK  \n «hf|X-A»: b "},
		// log quotes are not strings (CVE-2025-21912)
		{"log quote", "[    4.250180] OF: /soc/sound@ec500000/ports/port@0/endpoint: Read of boolean property 'frame-master' with a value.",
			"kind: log\n«hm|[    4.250180]» OF: /soc/sound@«hn|ec500000»/ports/port@0/endpoint: Read of boolean property 'frame-master' with a value."},
	} {
		if got := hlMarkup(c.text); got != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

// checkHilite checks the invariants of Hilite's result for text: one line
// per line, tokens that give the text back, no empty token, known classes,
// no two neighbours of one class.
func checkHilite(t testing.TB, text string) {
	t.Helper()
	ls := Hilite(text)
	if len(ls) != strings.Count(text, "\n")+1 {
		t.Fatalf("%d lines for %d", len(ls), strings.Count(text, "\n")+1)
	}
	if got := joinCodeLines(ls); got != text {
		t.Fatalf("not lossless:\n%q\n%q", got, text)
	}
	known := map[string]bool{"": true, HlComment: true, HlString: true, HlNumber: true, HlKeyword: true, HlFunc: true,
		HlError: true, HlMeta: true, HlAdd: true, HlDel: true}
	for _, l := range ls {
		for k, tk := range l.Toks {
			if tk.Text == "" || !known[tk.Class] || strings.Contains(tk.Text, "\n") {
				t.Fatalf("bad token %+v in %q", tk, text)
			}
			if k > 0 && l.Toks[k-1].Class == tk.Class {
				t.Fatalf("unmerged tokens %+v %+v in %q", l.Toks[k-1], tk, text)
			}
		}
	}
}

// TestHiliteLossless: every code block of the prose fixtures and every
// case gives its text back.
func TestHiliteLossless(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "prose", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cs []proseCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cs {
		for _, bl := range FormatText(c.Text, c.Names...) {
			if bl.Code {
				checkHilite(t, bl.Text)
				n++
			}
		}
		checkHilite(t, c.Text) // whole descriptions too
	}
	_, hs := loadHiliteCases(t)
	for _, c := range hs {
		checkHilite(t, c.text)
	}
	for _, s := range []string{"", "\n", "\n\n", "a", "\t", "\"", "'", "/*", "*/", "//", "#", "$ ", "# ", ">>> ", "+", "-",
		"@@ -1 +1 @@", "GET / HTTP/1.1", "GET / HTTP/1.1\n\n/* x\n*/", "$ x\n>>> f(/* a\n*/", "/*\n*/", "/* a\n\n b */", "x\\\n'\\\n'", "\xff\xfe", "a\r\nb"} {
		checkHilite(t, s)
	}
	if n < 10 {
		t.Errorf("only %d code blocks in the prose fixtures", n)
	}
}

// TestHiliteCaps: oversized blocks and lines are plain.
func TestHiliteCaps(t *testing.T) {
	line := "kfree(p); // free"
	big := strings.Repeat(line+"\n", hlMaxLines) + line // hlMaxLines+1 lines
	for _, l := range Hilite(big) {
		if len(l.Toks) != 1 || l.Toks[0].Class != "" {
			t.Fatalf("over %d lines: %+v", hlMaxLines, l)
		}
	}
	if ls := Hilite(strings.Repeat(line+"\n", hlMaxLines-1) + line); ls[0].Toks[0].Class != HlFunc {
		t.Fatalf("%d lines not highlighted: %+v", hlMaxLines, ls[0])
	}
	wide := strings.Repeat("kfree(p); ", hlMaxBytes/10+1)
	if ls := Hilite(wide); len(ls[0].Toks) != 1 {
		t.Fatal("over hlMaxBytes not plain")
	}
	long := "kfree(p);\n" + strings.Repeat("x", fmtMaxLine-8) + " kfree(q);"
	if ls := Hilite(long); ls[0].Toks[0].Class != HlFunc || len(ls[1].Toks) != 1 || ls[1].Toks[0].Class != "" {
		t.Fatalf("long line: %+v", ls)
	}
}

// TestHiliteLinear: the worst inputs within the caps take about as long
// per byte as ordinary code (no quadratic path).
func TestHiliteLinear(t *testing.T) {
	per := func(s string) time.Duration {
		start := time.Now()
		n := 0
		for time.Since(start) < 50*time.Millisecond {
			Hilite(s)
			n++
		}
		return time.Since(start) / time.Duration(n*len(s))
	}
	line := func(unit string) string { return strings.Repeat(unit, (fmtMaxLine-1)/len(unit)) }
	base := per(strings.Repeat("\tret = foo(bar, 0x10); // ok\n", 300))
	for name, s := range map[string]string{
		// every quote, comment opener and gap rescans nothing
		"quotes":   strings.Repeat(line(`"a '`)+"\n", 30),
		"comments": strings.Repeat(line("/* ")+"\n", 30),
		"gaps":     strings.Repeat(line("//     x")+"\n", 30),
		"spans":    strings.Repeat("/*\n", 200) + "*/",
		"log":      strings.Repeat(line("ffff8880 a+0x1/0x2 ")+"\n", 30),
		"shell":    strings.Repeat("$ "+line("a|'b' ")+"\n", 30),
	} {
		if d := per(s); d > 20*base+time.Nanosecond*50 {
			t.Errorf("%s: %v per byte, ordinary code %v", name, d, base)
		}
	}
}

func FuzzHilite(f *testing.F) {
	_, hs := loadHiliteCases(f)
	for _, c := range hs {
		f.Add(c.text)
	}
	for _, s := range []string{"/* a\n b */ c", "$ echo 'x\\\n y' \\\nz", "@@ -1 +1 @@\n+a\n-b", "GET / HTTP/1.1\nA: b\n\n{\"x\":1}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		checkHilite(t, s)
	})
}

// benchBlock is the first case of the given CVE.
func benchBlock(b *testing.B, cve string) string {
	_, hs := loadHiliteCases(b)
	for _, c := range hs {
		if strings.HasPrefix(c.head, cve+" ") {
			return c.text
		}
	}
	b.Fatalf("no case %s", cve)
	return ""
}

// BenchmarkHilite: a typical block (a 30-line lockdep report), a C function,
// and the worst input within the caps (32 KiB of 999-byte lines with a
// comment opener, quote and call in every few bytes).
func BenchmarkHilite(b *testing.B) {
	worst := strings.Repeat(strings.Repeat(`f(a, "b) /* 'c `, 999/16)+"\n", hlMaxLines)
	worst = worst[:min(len(worst), hlMaxBytes)]
	for _, c := range []struct{ name, text string }{
		{"log", benchBlock(b, "CVE-2025-21912")},
		{"src", benchBlock(b, "CVE-2023-54137")},
		{"worst", worst},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.text)))
			for b.Loop() {
				Hilite(c.text)
			}
		})
	}
}
