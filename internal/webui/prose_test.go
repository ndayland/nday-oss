package webui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/site"
)

// proseCase is one description of testdata/prose/cases.json: real records
// picked by hand from the production data (plus one written Chinese
// summary), each for the shape named in Why.
type proseCase struct {
	ID    string   `json:"id"`
	Why   string   `json:"why"`
	Text  string   `json:"text"`
	Names []string `json:"names"`
}

func loadProseCases(t *testing.T) map[string]proseCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "prose", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cs []proseCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	m := map[string]proseCase{}
	for _, c := range cs {
		m[c.ID] = c
	}
	if len(cs) < 40 {
		t.Fatalf("%d cases", len(cs))
	}
	return m
}

// dumpBlocks is a readable rendering: code blocks fenced, inline code in ⟦⟧.
func dumpBlocks(bs []TextBlock) string {
	var b strings.Builder
	for _, x := range bs {
		if x.Code {
			b.WriteString("┏━━ code\n" + x.Text + "\n┗━━\n")
			continue
		}
		for _, s := range x.Segs {
			if s.Code {
				b.WriteString("⟦" + s.Text + "⟧")
			} else {
				b.WriteString(s.Text)
			}
		}
		b.WriteString("\n¶\n")
	}
	return b.String()
}

// TestProseGolden: every fixture's split matches testdata/prose/golden.txt
// (go test ./internal/webui -run TestProseGolden -update rewrites it; review
// the diff).
func TestProseGolden(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "prose", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cs []proseCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&out, "==================== %s — %s\n%s\n", c.ID, c.Why, dumpBlocks(FormatText(c.Text, c.Names...)))
	}
	path := filepath.Join("testdata", "prose", "golden.txt")
	if *update {
		if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file (run: go test ./internal/webui -run TestProseGolden -update): %v", err)
	}
	if string(want) != out.String() {
		t.Error("prose split differs from testdata/prose/golden.txt (run with -update and review the diff)")
	}
}

func codeBlocks(bs []TextBlock) []string {
	var out []string
	for _, b := range bs {
		if b.Code {
			out = append(out, b.Text)
		}
	}
	return out
}

func inlineCode(bs []TextBlock) []string {
	var out []string
	for _, b := range bs {
		for _, s := range b.Segs {
			if s.Code {
				out = append(out, s.Text)
			}
		}
	}
	return out
}

func TestProseCases(t *testing.T) {
	cs := loadProseCases(t)
	get := func(id string) []TextBlock {
		c, ok := cs[id]
		if !ok {
			t.Fatalf("no case %s", id)
		}
		return FormatText(c.Text, c.Names...)
	}

	// The page the owner pointed at: the diagram is one block with its
	// columns, the header row and the blank line after it.
	bs := get("CVE-2026-98260")
	code := codeBlocks(bs)
	if len(code) != 1 {
		t.Fatalf("CVE-2026-98260: %d code blocks\n%s", len(code), dumpBlocks(bs))
	}
	for _, want := range []string{
		"    the non-leader thread B           the parent\n\ntimer_create(CLOCK_THREAD_CPUTIME_ID)\n",
		"\n  arm_timer()            // the node is queued on B\n",
		"\n                              kill(B, SIGKILL)\n",
		"\n                                      timerqueue_del()  // use-after-free",
	} {
		if !strings.Contains(code[0], want) {
			t.Errorf("CVE-2026-98260 diagram lacks %q", want)
		}
	}
	last := bs[len(bs)-1]
	if last.Code || !strings.HasPrefix(last.Segs[0].Text, "[ tglx: Move the cleanup right after ") {
		t.Errorf("trailer is not the last paragraph: %+v", last)
	}
	if bs[0].Code || bs[0].Segs[0].Text != "In the Linux kernel, the following vulnerability has been resolved:" {
		t.Errorf("first paragraph %+v", bs[0])
	}

	// code blocks that must be found
	for id, want := range map[string]string{
		"CVE-2022-48983": "Call Trace:\n <TASK>\n dump_stack_lvl+0xcd/0x134\n ? io_tctx_exit_cb+0x53/0xd3",
		"CVE-2023-53035": "BUG: KMSAN: kernel-infoleak in _copy_to_user+0xc0/0x100 lib/usercopy.c:33",
		"CVE-2024-53168": "mkdir -p /mnt/nfsshare",
		"CVE-2026-89833": "Thread A\t\t\t\tThread B\n- fsync\n - f2fs_do_sync_file",
		"CVE-2026-90393": "CPU0                                          CPU1\nbpf_netns_link_update_prog",
		"CVE-2026-72013": "kexec_file_load\n  -> kimage_file_alloc_init()",
		"CVE-2025-68242": "# echo \"/media *(rw,no_root_squash,sync)\" >> /etc/exports\n# export -ra",
		"CVE-2023-26031": "$ ls -laF /opt/hadoop/bin/container-executor",
		"CVE-2025-54480": "if (tag==0) {",
		"CVE-2026-2332":  "POST / HTTP/1.1\nHost: localhost",
		"CVE-2025-54920": "\"Event\": \"org.apache.hive.jdbc.HiveConnection\",",
		"CVE-2024-32114": "<bean id=\"securityConstraintMapping\"",
		"CVE-2024-0455":  "http://169.254.169.254/latest/meta-data/",
		"CVE-2026-23074": "├── class 1:1",
		"CVE-2026-31647": "[ BUG: Invalid wait context ]",
		"CVE-2026-98629": "tc qdisc add dev test0 clsact",
		"CVE-2024-30397": "root@srx> show system processes extensive | match pkid",
		"zh-summary":     "execve()\n  de_thread(B)\n    exchange_tids(B, leader)  // B 的 PID 归主线程",
	} {
		if !strings.Contains(strings.Join(codeBlocks(get(id)), "\n---\n"), want) {
			t.Errorf("%s: no code block with %q\n%s", id, want, dumpBlocks(get(id)))
		}
	}

	// prose that must stay prose: lists, quoted paragraphs, hanging
	// indents, HTML prose, changelogs, product names
	for _, id := range []string{"CVE-2026-80896", "CVE-2025-21602", "CVE-2018-9397", "CVE-2026-71462", "CVE-2020-1012",
		"CVE-2023-20118", "CVE-2026-31407", "CVE-2023-52586", "CVE-2026-89657", "CVE-2021-44228", "CVE-1999-0001",
		"CVE-2023-40049", "CVE-2017-15841", "CVE-2024-55994", "CVE-2025-9557", "CVE-2024-22234", "CVE-2023-22516"} {
		if code := codeBlocks(get(id)); len(code) != 0 {
			t.Errorf("%s: unexpected code block %q", id, code[0])
		}
	}

	// inline code: what must be marked and what must not
	has := func(id, tok string) bool {
		for _, s := range inlineCode(get(id)) {
			if s == tok {
				return true
			}
		}
		return false
	}
	for id, toks := range map[string][]string{
		"CVE-2026-98260": {"de_thread()", "posix_cputimers", "PIDTYPE_PID", "bprm->point_of_no_return", "k_itimer"},
		"CVE-2026-62858": {"yourls_get_request()", "file_exists()", "YOURLS_PAGEDIR"},
		"CVE-1999-0001":  {},
		"zh-summary":     {"execve()", "de_thread()", "PIDTYPE_PID", "exec_mmap()", "k_itimer", "fs/exec.c", "CONFIG_POSIX_TIMERS"},
	} {
		for _, tok := range toks {
			if !has(id, tok) {
				t.Errorf("%s: %q not inline code; got %q", id, tok, inlineCode(get(id)))
			}
		}
	}
	for id, toks := range map[string][]string{
		"CVE-2023-40049": {"WS_FTP"},                   // the product
		"CVE-2017-15841": {"Snapdragon_High_Med_2016"}, // the product
		"CVE-2025-3135":  {"fcba_zzm"},                 // the vendor
		"CVE-2022-25130": {"V2_Firmware"},
		"CVE-2023-26782": {"Configuration->Cache"},
		"CVE-2021-44228": {"2.0-beta9", "2.15.0", "JNDI", "CVE-2021-44228"},
	} {
		for _, tok := range toks {
			if has(id, tok) {
				t.Errorf("%s: %q marked as code", id, tok)
			}
		}
	}
	// CJK text is never inside inline code
	for _, s := range inlineCode(get("zh-summary")) {
		if cjkCount(s) > 0 {
			t.Errorf("zh: CJK in inline code %q", s)
		}
	}
}

// TestProseInline pins the inline rules on single sentences.
func TestProseInline(t *testing.T) {
	for in, want := range map[string]string{
		"calls foo() then":                      "calls ⟦foo()⟧ then",
		"in obj->member() and ns::name().":      "in ⟦obj->member()⟧ and ⟦ns::name()⟧.",
		"the skb->len field":                    "the ⟦skb->len⟧ field",
		"(see CONFIG_FOO_BAR).":                 "(see ⟦CONFIG_FOO_BAR⟧).",
		"edit fs/exec.c, or /etc/passwd.":       "edit ⟦fs/exec.c⟧, or ⟦/etc/passwd⟧.",
		"a `--flag value` here":                 "a ⟦--flag value⟧ here",
		"the my_var, 'snake_case' and x_y":      "the ⟦my_var⟧, '⟦snake_case⟧' and x_y",
		"$_GET and $HOME but not $5":            "⟦$_GET⟧ and ⟦$HOME⟧ but not $5",
		"versions 1.2.3 to v2.0_rc1 and 2_0":    "versions 1.2.3 to v2.0_rc1 and 2_0",
		"see https://example.com/a_b/c.php now": "see https://example.com/a_b/c.php now",
		"mail foo_bar@example.com today":        "mail foo_bar@example.com today",
		"www.example.com/x_y.php and e.g. this": "www.example.com/x_y.php and e.g. this",
		"example.com/index.php is a host":       "example.com/index.php is a host",
		"CVE-2024-1234 and GHSA-abcd-efgh-ijkl": "CVE-2024-1234 and GHSA-abcd-efgh-ijkl",
		"on x86_64 and fe80::1 hosts":           "on x86_64 and fe80::1 hosts",
		"Setup->Users->Username menu":           "Setup->Users->Username menu",
		"A -> B and a :: b":                     "A -> B and a :: b",
		"version(s) and function(s)":            "version(s) and function(s)",
		"调用foo_bar()时，CONFIG_X_Y开启":             "调用⟦foo_bar()⟧时，⟦CONFIG_X_Y⟧开启",
		"an unterminated `tick":                 "an unterminated `tick",
	} {
		got := dumpBlocks(FormatText(in))
		got = strings.TrimSuffix(got, "\n¶\n")
		if got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// TestProseLossless: nothing of the text is lost or reordered. Paragraph
// segments join back to the source lines (backticks around Tick
// segments); code blocks hold the source lines without their common
// indentation and trailing blanks.
func TestProseLossless(t *testing.T) {
	cs := loadProseCases(t)
	texts := []string{"", " \n\t\n", "one line", "a\r\nb\rc", "x\x00y\x01z\x7f\u0085", "\ttab\n\t\tcode();\n\t\tmore();"}
	for _, c := range cs {
		texts = append(texts, c.Text)
	}
	for _, s := range texts {
		clean := cleanText(s)
		var src []string
		for _, l := range strings.Split(clean, "\n") {
			if b := strings.TrimSpace(l); b != "" && !reFence.MatchString(b) {
				src = append(src, b)
			}
		}
		var got []string
		for _, b := range FormatText(s) {
			var text string
			if b.Code {
				text = b.Text
			} else {
				var j strings.Builder
				for _, sg := range b.Segs {
					if sg.Tick {
						j.WriteString("`" + sg.Text + "`")
					} else {
						j.WriteString(sg.Text)
					}
				}
				text = j.String()
			}
			for _, l := range strings.Split(text, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					got = append(got, l)
				}
			}
		}
		if strings.Join(got, "\n") != strings.Join(src, "\n") {
			t.Errorf("text changed:\n%q\n%q", strings.Join(src, "\n"), strings.Join(got, "\n"))
		}
	}
}

// TestProseHostileInput: control characters, invalid UTF-8, huge inputs
// and pathological shapes give a bounded result quickly.
func TestProseHostileInput(t *testing.T) {
	long := strings.Repeat("a_b(", 1<<18) // 1 MiB, one line, a token start every 4 bytes
	for name, s := range map[string]string{
		"1MiB line":      long,
		"1MiB commas":    strings.Repeat("x,", 1<<19),
		"1MiB parens":    "f(" + strings.Repeat(")", 1<<20),
		"1MiB backticks": strings.Repeat("`", 1<<20),
		"60KiB lines":    strings.Repeat("  foo();\n", 60<<10/9),
		"60KiB blanks":   strings.Repeat("\n", 60<<10) + "x",
		"60KiB bullets":  strings.Repeat("- a\n", 15<<10),
		"60KiB tokens":   strings.Repeat("a_b ", 15<<10),
		"invalid utf8":   "\xff\xfe foo_bar() \xc3",
		"controls":       "a\x00b\x1bc\x7fd\u0085e\u202eevil\u2066",
	} {
		start := time.Now()
		bs := FormatText(s)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: %v", name, d)
		}
		n, spans := 0, 0
		for _, b := range bs {
			n += len(b.Text)
			for _, sg := range b.Segs {
				n += len(sg.Text)
				if sg.Code {
					spans++
				}
				if !utf8.ValidString(sg.Text) || strings.ContainsAny(sg.Text, "\x00\x1b\x7f\u0085\r") {
					t.Errorf("%s: unclean segment %q", name, sg.Text)
				}
			}
			if !utf8.ValidString(b.Text) || strings.ContainsAny(b.Text, "\x00\x1b\x7f\u0085\r") {
				t.Errorf("%s: unclean code block", name)
			}
		}
		if n > len(s)*3+16 || spans > fmtMaxInline {
			t.Errorf("%s: output %d bytes, %d spans for %d input bytes", name, n, spans, len(s))
		}
	}
}

// TestProseViewModel: the page splits Summary (and on zh pages the
// English original) with the record's product names; the plain strings
// stay as they were.
func TestProseViewModel(t *testing.T) {
	desc := "In WS_FTP Server the ws_handler() bug:\n\n  ws_handler();\n  return;"
	zh := "WS_FTP 的 ws_handler() 有缺陷。"
	v := &site.VulnDetail{CVEID: "CVE-2026-1", Description: &desc, SummaryZh: &zh,
		Products: []site.Product{{Vendor: "Progress Software", Product: "WS_FTP Server"}}}
	for _, tag := range []string{"en", "zh-Hans"} {
		vv := BuildVulnView(loc(t, tag), v, time.Now(), NewAPI("https://nday.land", ""))
		if tag == "en" {
			if vv.Summary != desc || vv.OrigText != nil {
				t.Errorf("en: %q %v", vv.Summary, vv.OrigText)
			}
		} else if vv.Summary != zh || vv.Description != desc || vv.OrigText == nil {
			t.Errorf("zh: %q %q", vv.Summary, vv.Description)
		}
		all := dumpBlocks(vv.SummaryText) + dumpBlocks(vv.OrigText)
		if strings.Contains(all, "⟦WS_FTP⟧") || !strings.Contains(all, "⟦ws_handler()⟧") {
			t.Errorf("%s: %s", tag, all)
		}
	}
}

// TestShareCardIgnoresDescription: the share card (and so its URL key)
// does not depend on the description.
func TestShareCardIgnoresDescription(t *testing.T) {
	a, b := "plain words", "BUG: KASAN\n  foo_bar();\n<script>"
	ta := "t"
	va := &site.VulnDetail{CVEID: "CVE-2026-1", Title: &ta, Description: &a}
	vb := &site.VulnDetail{CVEID: "CVE-2026-1", Title: &ta, Description: &b}
	if cardPath(cardFor(va)) != cardPath(cardFor(vb)) {
		t.Error("share card depends on the description")
	}
}
