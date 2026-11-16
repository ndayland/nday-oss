package webui

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Upstream descriptions are plain text. CVE records of the Linux kernel are
// commit messages: hard-wrapped at ~72 columns, with indented call-flow
// diagrams, crash reports, code and shell lines. FormatText splits such a
// text into prose paragraphs and code blocks and marks unmistakable code
// tokens inside the prose, so the page can show code as code. It produces
// no markup: the template renders every piece with normal escaping.
//
// The rules were derived from the ~406k descriptions of the production data
// (testdata/prose/ holds the cases that pinned them down; prose_test.go):
//
//   - Blocks are runs of non-blank lines; lines between markdown ``` fences
//     are code. A line votes "code" strongly when it has a signature (kernel
//     log, sanitizer or lockdep report, stack frame, register or memory
//     dump, shell or device prompt, HTTP request/response line), as a
//     statement when it is shaped like source (call line, assignment,
//     control statement, preprocessor, comment, braces, XML tag, JSON key),
//     or weakly when it is indented by two or more columns or column-aligned
//     and its words do not read as a sentence.
//   - Bullet items ("*", "-", "1.") and their wrapped continuation lines are
//     prose: the CVE services turn HTML lists into indented "  *  " items.
//     So is a hanging indent: the indented lines that continue a paragraph
//     whose first line is not indented.
//   - Weak lines next to code lines join them; a lone weakly indented line
//     (a quoted commit subject, an indented sentence) stays prose; a single
//     prose line squeezed between code lines of one block is code (a table
//     row, a diagram row).
//   - Code runs separated only by blank lines are one block.
//   - Prose keeps its line breaks (the page shows it white-space: pre-line,
//     as before): re-flowing would merge list items, trailers ("Fixes:",
//     "[ tglx: … ]") and the many one-sentence-per-line records.
//
// The cost is linear in the input; lines longer than fmtMaxLine bytes never
// count as code and texts longer than fmtMaxInput are one plain paragraph.
//
// The page shows a code block line by line (TextBlock.Lines), each line
// split into tokens by Hilite (hilite.go) for syntax colours.

const (
	fmtMaxInput  = 64 << 10 // bytes; longer texts are not analysed
	fmtMaxLine   = 1000     // bytes; longer lines are prose
	fmtMaxInline = 300      // inline code spans per text
	fmtMaxTick   = 120      // bytes between backticks
)

// TextBlock is one paragraph (Code=false, Segs) or one code block (Code=true,
// Text: its lines, common indentation removed, joined by "\n").
type TextBlock struct {
	Code bool
	Text string
	Segs []TextSeg
}

// Numbered reports whether a code block gets line numbers: two lines or
// more (a number beside a one-line snippet says nothing).
func (b TextBlock) Numbered() bool { return b.Code && strings.Contains(b.Text, "\n") }

// Gutter is the class that sizes the line-number column: "g2" up to 99
// lines, "g3" up to 999, "g4" beyond.
func (b TextBlock) Gutter() string {
	switch n := strings.Count(b.Text, "\n") + 1; {
	case n < 100:
		return "g2"
	case n < 1000:
		return "g3"
	}
	return "g4"
}

// TextSeg is a run of a paragraph: plain text or one inline code token.
// Tick reports that the token was written between backticks in the source
// (which are left out of Text).
type TextSeg struct {
	Text string
	Code bool
	Tick bool
	// Arrow is Text split at "->" when it has one: the template keeps each
	// "->" on one line (browsers wrap after the '-' of "bprm->point").
	Arrow []string
}

// FormatText splits a plain-text description into paragraphs and code
// blocks. It is total: any string gives a well-defined result; "" gives nil.
func FormatText(s string, names ...string) []TextBlock {
	s = cleanText(s)
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if len(s) > fmtMaxInput {
		return []TextBlock{{Segs: []TextSeg{{Text: s}}}}
	}
	ls := splitLines(s)
	voteLines(ls)
	return emit(ls, newInliner(names))
}

// cleanText makes s valid UTF-8 without control characters other than tab
// and newline (CRLF and lone CR become newlines; NUL, the rest of C0, DEL
// and C1 become U+FFFD).
func cleanText(s string) string {
	clean := utf8.ValidString(s)
	if clean {
		for i := 0; i < len(s); i++ {
			if c := s[i]; (c < 0x20 && c != '\t' && c != '\n') || c == 0x7f || c == 0xc2 {
				clean = false
				break
			}
		}
	}
	if clean {
		return s
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch {
		case r == '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				continue
			}
			b.WriteByte('\n')
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Line votes.
const (
	vProse  = iota
	vWeak   // indented or column-aligned
	vStmt   // source statement or call line
	vStrong // log, report, dump, prompt, HTTP, fenced
)

type fline struct {
	raw    string // as in the source
	body   string // trimmed
	indent int    // columns (tab = 8)
	blank  bool
	block  int  // index of the blank-line separated block
	vote   int  // vProse..vStrong
	cont   bool // bullet item or its wrapped continuation (always prose)
	fenced bool // between markdown ``` fences
}

func splitLines(s string) []fline {
	raws := strings.Split(s, "\n")
	ls := make([]fline, len(raws))
	open := -1 // markdown fence
	for i, r := range raws {
		l := &ls[i]
		l.raw = r
		l.body = strings.TrimSpace(r)
		l.blank = l.body == ""
		if !l.blank {
			l.indent = indentWidth(r)
		}
		if reFence.MatchString(l.body) {
			if open < 0 {
				open = i
				continue
			}
			// ```…``` : the lines between are code, the fences are markup
			ls[open].blank, l.blank = true, true
			for k := open + 1; k < i; k++ {
				ls[k].fenced = !ls[k].blank
			}
			open = -1
		}
	}
	block, prevBlank := 0, true
	for i := range ls {
		l := &ls[i]
		if !l.blank && prevBlank && i > 0 {
			block++
		}
		prevBlank = l.blank
		l.block = block
	}
	return ls
}

func indentWidth(s string) int {
	w := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			w++
		case '\t':
			w = w/8*8 + 8
		default:
			return w
		}
	}
	return w
}

var (
	// reStrong: lines that are code wherever they appear.
	reStrong = regexp.MustCompile(`^(?:` + strings.Join([]string{
		// kernel log, sanitizer and lockdep reports
		`\[\s*\d+\.\d+\]`, `\[<[0-9a-f]{8,16}>\]`,
		`\?\s+\S+\+0x[0-9a-f]+/0x[0-9a-f]+`, `[\w.$]+\+0x[0-9a-f]+/0x[0-9a-f]+`,
		`(?:BUG|WARNING|INFO|ODEBUG|UBSAN|KASAN|KMSAN|KCSAN|KFENCE|Oops|DMA-API|refcount_t|Internal error): \S`,
		`Kernel panic - not syncing`, `general protection fault`, `Unable to handle kernel`, `kernel BUG at `,
		`unreferenced object 0x`, `list_(?:add|del) corruption`, `-+\[ cut here \]-+$`, `-+\[ end trace`,
		`Call [Tt]race:`, `</?(?:TASK|IRQ|NMI|SOFTIRQ|EOI)>$`, `Modules linked in:`, `Hardware name: `, `Workqueue: `,
		`Code: (?:[0-9a-f]{2,8}|<[0-9a-f]{2}>|Unable)`, `RIP: [0-9a-f]{4}:`, `(?:pc|lr|sp) : `, `CPU: \d+ (?:UID: \d+ )?PID: \d+`,
		`(?:Allocated|Freed) by task \d+`, `The buggy address `, `Memory state around the buggy address`,
		`(?:Read|Write) of size \d+ at addr`, `irq event stamp: `, `(?:hard|soft)irqs last \w+ at`, `stack backtrace:$`,
		`Possible unsafe locking scenario`, `\*\*\* DEADLOCK \*\*\*$`, `Chain exists of:$`, `-> #\d+ `, `#\d+: [0-9a-f]{16} \(`,
		`(?:Uninit|Local variable \S+) was (?:created|stored) at:`, `Last potentially related work creation:`,
		`(?:CR[0-4]|FS|GS|CS|DS|ES|DR\d|PKRU|pstate):\s+[0-9a-f]`, `(?:raw|head|page): [0-9a-f]{16}`, `>?[0-9a-f]{8,16}: (?:[0-9a-f]{2,16}[ .]){4}`,
		`={10,}$`, `#PF: `, `PGD [0-9a-f]+ `, `\[ BUG: `, `\S+ #\d+ (?:Not tainted|Tainted: )`, `\d+ locks? held by `,
		`other info that might help`, `\S+ is trying to (?:acquire|lock)`, `but task is already holding lock`,
		`[0-9a-f]{16} \(&?[\w>.\-\[\]]+\)\{`, `hex dump \(first \d+ bytes\):`, `backtrace \(crc [0-9a-f]+\):`, `comm "[^"]*", pid \d+`,
		// a stack frame without an offset: "func file.c:123 [inline]"
		`[\w.$]+(?:\+0x[0-9a-f]+/0x[0-9a-f]+)? [\w./-]+\.[chS]:\d+\b`,
		// two or more register/value pairs: "RAX: 0000… RBX: 0000…", "x29: … x28: …"
		`(?:[A-Za-z][A-Za-z0-9]{1,4} ?: ?[0-9a-f]{8,16}\s+){2}`,
		// shell prompts ("# " only before a command: "# Summary" is a markdown heading)
		`\$ [a-z./~]`, `# (?:echo|cat|ls|cd|mount|umount|mkdir|insmod|rmmod|modprobe|ip|tc|nft|iptables|sysctl|perf|rm|dd|mkfs\S*|fio|bpftool|chmod|chown|ln|touch|cp|mv|sh|bash|python3?|gcc|make|git|curl|wget|export|\./\S+)(?: |$)`,
		`[\w.-]+@[\w.-]+(?::\S*)?[#$>] \S`,
		// HTTP messages
		`(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) /\S* HTTP/\d`, `HTTP/\d(?:\.\d)? \d{3}\b`,
	}, "|") + `)`)

	// reStmt: source statements, call lines and other lines that are code
	// when they stand on their own or come with other code (a line of an
	// XSS payload inside a sentence is not a code block).
	reStmt = regexp.MustCompile(`^(?:` + strings.Join([]string{
		// preprocessor, comments, braces
		`#\s*(?:include|define|ifdef|ifndef|endif|undef|pragma|if|elif|else)\b`,
		`(?://|/\*|\*/)`, `[{}\[\]()][{}\[\]()\s]*[;,]?$`,
		// XML, JSON (HTML text markup such as <p> or <li> is not code: some
		// records are prose written as HTML)
		`</?[A-Za-z][\w:.-]*(?:\s[^<>]*)?/?>`, `<!--`, `<!\[CDATA\[`, `<\?xml`, `<!DOCTYPE`,
		`"[^"]{1,80}"\s*:\s*(?:"|\{|\[|\d|true|false|null)`,
		`(?:if|while|for|switch) ?\(.*\)\s*\{?$`, `(?:else|do|try)\s*\{$`, `\} ?(?:else|while|catch)\b`,
		`(?:return\b.*|goto \w+|break|continue);$`, `case [^:]{1,60}:$`, `default:$`,
		`(?:def|class) [A-Za-z_]\w*\s*[(:]`, `from [\w.]+ import `, `import [\w.]+;?$`,
		`(?:function\s*\w*\s*\(|(?:const|let|var) \w+ ?=)`, `(?:public|private|protected|static) [\w<>\[\], ]+[ (]`,
		`(?:struct|union|enum) \w+ ?\{$`,
		// call line: name(...) with nothing after but ;, {, , or a comment
		`(?:->\s*)?[A-Za-z_]\w*(?:(?:->|\.|::)[A-Za-z_]\w*|\[[^\]]*\])*\(.*\)\s*[;{,]?\s*(?:(?://|/\*|#|<-).*)?$`,
		// assignment: lhs that is a code token, or a terminated statement
		`[A-Za-z_*&][\w>.\-\[\]*&]*\s*(?:[-+*/|&^]|<<|>>)?=\s*[^=].*;$`,
		`[A-Za-z_]\w*(?:->|\.|\[)[\w>.\-\[\]]*\s*(?:[-+*/|&^]|<<|>>)?=\s*[^=]`,
		// tree drawing: "-> foo()", "|-- foo", "`-> foo", "├── foo"
		`(?:->|[|` + "`" + `+]-+>?)\s*\S`, `[├└│┌┬┼]`,
	}, "|") + `)`)

	reBullet = regexp.MustCompile(`^(?:[*•·▪◦‣–-]|\d{1,2}[.)]|\(\d{1,2}\)|[a-z][.)])\s+`)
	reGap    = regexp.MustCompile(`\S(?:[ \t\x{a0}]*\t[ \t\x{a0}]*|[ \x{a0}]{3,})\S`) // column-aligned text (some records align with NBSP)
	rePrompt = regexp.MustCompile(`^(?:\$ |# |[\w.-]+@[\w.-]+(?::\S*)?[#$>] )\S`)
	reFence  = regexp.MustCompile("^```[\\w+#.-]{0,20}$")
	reWord   = regexp.MustCompile(`^[A-Za-z][a-z]*(?:'[a-z]+)?[,.;:!?)]*$`)
	reHTTPRL = regexp.MustCompile(`^(?:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) /\S* HTTP/\d|HTTP/\d(?:\.\d)? \d{3}\b)`)
)

// proseLike reports whether a line reads as a sentence: six or more words,
// at least 60% of them plain words, no column gaps; or a short line of
// plain words ending like a wrapped sentence; or a bare link. Han, kana and
// hangul text counts as prose too.
func proseLike(body string) bool {
	if cjkCount(body) >= 4 || bareLink(body) {
		return true
	}
	words := strings.Fields(body)
	// column gaps make a table row; gaps after the end of a sentence are
	// padding ("…this vulnerability.   However, …", NBSP runs)
	for _, g := range reGap.FindAllStringIndex(body, -1) {
		if !strings.ContainsAny(body[g[0]:g[0]+1], ".!?") {
			return false
		}
	}
	plain := 0
	for _, w := range words {
		if reWord.MatchString(w) {
			plain++
		}
	}
	if len(words) < 6 {
		// the short last line of a wrapped sentence: "needed for exploitation."
		return len(words) >= 2 && plain == len(words) && strings.ContainsAny(body[len(body)-1:], ".,")
	}
	// a command line is made of plain words too ("ip l add veth3 type veth
	// peer veth4")
	if shellCmds[words[0]] && !strings.HasSuffix(body, ".") {
		return false
	}
	return plain*10 >= len(words)*6
}

// shellCmds start the command lines of reproducers in the data.
var shellCmds = map[string]bool{"ip": true, "tc": true, "echo": true, "cat": true, "mount": true, "umount": true,
	"mkdir": true, "insmod": true, "rmmod": true, "modprobe": true, "nft": true, "iptables": true, "ip6tables": true,
	"sysctl": true, "perf": true, "rm": true, "dd": true, "fio": true, "bpftool": true, "chmod": true, "ln": true,
	"touch": true, "cp": true, "mv": true, "sh": true, "bash": true, "gcc": true, "make": true, "git": true, "curl": true,
	"wget": true, "cd": true, "ls": true, "devlink": true, "ethtool": true, "bridge": true, "losetup": true, "dmsetup": true,
	"xfs_io": true, "truncate": true, "sleep": true, "taskset": true, "sudo": true, "export": true, "ping": true,
	"nc": true, "socat": true, "iw": true, "ovs-vsctl": true, "brctl": true, "mkfs": true, "mkfs.ext4": true, "mkfs.xfs": true,
	"mkfs.btrfs": true, "btrfs": true, "fallocate": true, "systemctl": true, "npm": true, "pip": true, "docker": true,
	"kubectl": true, "python": true, "python3": true, "ssh": true, "ifconfig": true, "exportfs": true, "timeout": true,
	"dmesg": true, "tee": true, "chown": true, "grep": true, "./": true}

// cmdLine: a line that starts with a command of shellCmds (or ./prog) and
// has arguments.
func cmdLine(b string) bool {
	w, rest, ok := strings.Cut(b, " ")
	return ok && strings.TrimSpace(rest) != "" && (shellCmds[w] || strings.HasPrefix(w, "./"))
}

// reParenProse: words joined after a parenthesis are a sentence, not a
// call ("version(s) and function(s)").
var reParenProse = regexp.MustCompile(`\) (?:and|or|of|in|to|is|are|was|the|for|with|as|by|on)\b`)

// bareLink: a line that is only URLs or markdown links/images.
func bareLink(body string) bool {
	for _, w := range strings.Fields(body) {
		w = strings.TrimLeft(w, "([<\"'*")
		if !(strings.HasPrefix(w, "http://") || strings.HasPrefix(w, "https://") || strings.HasPrefix(w, "![") ||
			strings.HasPrefix(w, "[") && strings.Contains(w, "](")) {
			return false
		}
	}
	return body != ""
}

// stmtWords counts the plain words of a code-shaped line outside string
// literals and a trailing comment.
func stmtWords(body string) int {
	if k := strings.Index(body, "//"); k > 0 {
		body = body[:k]
	}
	if k := strings.Index(body, "/*"); k > 0 {
		body = body[:k]
	}
	if strings.ContainsAny(body, `"'`) {
		var b strings.Builder
		var q byte
		for i := 0; i < len(body); i++ {
			c := body[i]
			switch {
			case q != 0:
				if c == q {
					q = 0
				}
			case c == '"' || c == '\'' && (i == 0 || !isWordByte(body[i-1])):
				q = c
			default:
				b.WriteByte(c)
			}
		}
		body = b.String()
	}
	return plainWords(body)
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func cjkCount(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x2E80 && (unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r)) {
			n++
		}
	}
	return n
}

// plainWords counts the words of body that are ordinary words.
func plainWords(body string) int {
	n := 0
	for _, w := range strings.Fields(body) {
		if len(w) > 1 && reWord.MatchString(w) {
			n++
		}
	}
	return n
}

// voteLine classifies one line on its own.
func voteLine(l *fline) int {
	b := l.body
	if len(b) > fmtMaxLine {
		return vProse
	}
	if reStrong.MatchString(b) {
		return vStrong
	}
	if stmtLine(b) {
		return vStmt
	}
	if (l.indent >= 2 || reGap.MatchString(b)) && !proseLike(b) {
		return vWeak
	}
	return vProse
}

// stmtLine reports whether a line without a strong signature is a source
// statement (also used by hilite.go).
func stmtLine(b string) bool {
	return cjkCount(b) < 4 && !bareLink(b) &&
		(reStmt.MatchString(b) || strings.HasSuffix(b, ";") && strings.ContainsAny(b, "([=")) &&
		stmtWords(b) <= 2 && !htmlText(b) && !reParenProse.MatchString(b)
}

func isCode(v int) bool { return v != vProse }

// midSentence: the line does not introduce something (':'), open a block
// ('{') or continue a command ('\').
func midSentence(b string) bool {
	r, _ := utf8.DecodeLastRuneInString(b)
	return r != '：' && !strings.ContainsRune(`:{;=\`, r) // U+FF1A fullwidth colon
}

// wordy: at least three words, 40% of them plain; the lines of a hanging
// indent are ("200 vs 400 response reveals existence of arbitrary"), wrapped
// code is not ("ZYNQMP_DMA_NUM_DESCS),").
func wordy(b string) bool {
	n := len(strings.Fields(b))
	return n >= 3 && plainWords(b)*10 >= n*4
}

// htmlTextTags are the HTML elements of prose written as HTML (old
// Microsoft records: "<p>…</p>", "<ul>", "</li>").
var htmlTextTags = map[string]bool{"p": true, "ul": true, "ol": true, "li": true, "br": true, "strong": true, "em": true,
	"b": true, "i": true, "u": true, "a": true, "span": true, "div": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "table": true, "tr": true, "td": true, "th": true, "tbody": true, "thead": true, "blockquote": true,
	"dl": true, "dt": true, "dd": true, "hr": true, "sup": true, "sub": true}

// htmlText reports whether b starts with an HTML text-markup tag.
func htmlText(b string) bool {
	if !strings.HasPrefix(b, "<") {
		return false
	}
	name := strings.TrimPrefix(b[1:], "/")
	end := strings.IndexFunc(name, func(r rune) bool { return !(r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r))) })
	if end < 0 {
		return false
	}
	return htmlTextTags[strings.ToLower(name[:end])]
}

// voteLines sets vote on every line.
func voteLines(ls []fline) {
	// a block whose "- name" lines sit at three or more indentations is a
	// call tree ("- fsync / - f2fs_do_sync_file / - f2fs_fsync_node_pages"),
	// not a list
	tree := map[int]bool{}
	for i := 0; i < len(ls); {
		j := i
		var ind []int
		for ; j < len(ls) && ls[j].block == ls[i].block; j++ {
			if l := ls[j]; !l.blank && (strings.HasPrefix(l.body, "- ") || strings.HasPrefix(l.body, "-> ")) && !slices.Contains(ind, l.indent) {
				ind = append(ind, l.indent)
			}
		}
		tree[ls[i].block] = len(ind) >= 3
		i = j
	}
	// per line, with bullet continuation
	contCol, hang := -1, false
	for i := range ls {
		l := &ls[i]
		if l.blank || l.fenced {
			contCol = -1
			if l.fenced {
				l.vote = vStrong
			}
			continue
		}
		l.vote = voteLine(l)
		if l.vote < vStrong && strings.Trim(l.body, "*•·-") == "" && len(l.body) <= 2 {
			l.vote, l.cont = vProse, true // an empty list item
			continue
		}
		if m := reBullet.FindStringIndex(l.body); m != nil && l.vote < vStrong {
			rest := l.body[m[1]:]
			if l.vote == vStmt || tree[l.block] && strings.HasPrefix(l.body, "-") && !proseLike(rest) {
				l.vote = max(l.vote, vWeak)
			} else {
				l.vote, l.cont = vProse, true
				contCol, hang = l.indent+m[1], false
			}
			continue
		}
		if contCol >= 0 && l.indent == contCol && (hang && l.vote < vStmt && !reGap.MatchString(l.body) || !hang && l.vote < vStrong) {
			l.vote, l.cont = vProse, true
			continue
		}
		contCol, hang = -1, false
		// a hanging indent: a paragraph whose first line is not indented
		// and stops mid-sentence goes on in the indented lines below it
		// (lines with column gaps are a table, not the paragraph)
		if l.vote == vProse && l.indent == 0 && i+1 < len(ls) && !ls[i+1].blank && ls[i+1].indent > 0 &&
			(i == 0 || ls[i-1].blank) && midSentence(l.body) && wordy(l.body) && !reGap.MatchString(ls[i+1].body) {
			contCol, hang = ls[i+1].indent, true
			l.cont = true
		}
	}
	// a block of command lines without sentences is a script, indented or
	// not ("mkdir -p /mnt/x" / "mount /dev/sdb /mnt/x" in kernel reproducers)
	for i := 0; i < len(ls); {
		j, n, cmds, prose, cont := i, 0, 0, false, false
		for ; j < len(ls) && ls[j].block == ls[i].block; j++ {
			if l := &ls[j]; !l.blank {
				n++
				if cmdLine(l.body) || cont { // a command, or the rest of one ("\")
					cmds++
				}
				cont = strings.HasSuffix(l.body, `\`)
			}
		}
		for k := i; k < j && n >= 2 && cmds*10 >= n*6 && !prose; k++ {
			l := &ls[k]
			prose = !l.blank && l.vote == vProse && !cmdLine(l.body) && !strings.HasPrefix(l.body, "#") && proseLike(l.body)
		}
		if n >= 2 && cmds*10 >= n*6 && !prose {
			cont = false
			for k := i; k < j; k++ {
				// commands, their continuations and comments; an
				// unindented heading ("Conditions to recreate:") stays
				if l := &ls[k]; !l.blank && l.vote == vProse && !l.cont &&
					(cont || l.indent > 0 || cmdLine(l.body) || strings.HasPrefix(l.body, "#")) {
					l.vote = vWeak
				}
				cont = strings.HasSuffix(ls[k].body, `\`)
			}
		}
		i = j
	}
	// a block that holds an HTTP request or response line is the message:
	// headers and body are code too
	for i := 0; i < len(ls); {
		j, http := i, false
		for ; j < len(ls) && ls[j].block == ls[i].block; j++ {
			http = http || ls[j].vote == vStrong && reHTTPRL.MatchString(ls[j].body)
		}
		for k := i; k < j && http; k++ {
			if !ls[k].blank && ls[k].vote == vProse {
				ls[k].vote = vWeak
			}
		}
		i = j
	}
	// what follows a shell or device prompt in its block is the command's
	// output, unless it reads as a sentence
	for k, out := 0, false; k < len(ls); k++ {
		l := &ls[k]
		switch {
		case l.blank:
			out = false
		case l.vote == vStrong && rePrompt.MatchString(l.body):
			out = true
		case out && l.vote == vProse && !l.cont && !proseLike(l.body):
			l.vote = vWeak
		case out && l.vote == vProse:
			out = false
		}
	}
	// indented prose next to code inside a block joins it (diagram rows
	// with words, wrapped comments); bullet items do not
	join := func(k, from int) {
		l := &ls[k]
		if !l.blank && l.vote == vProse && !l.cont && l.indent > 0 && len(l.body) <= fmtMaxLine &&
			from >= 0 && from < len(ls) && !ls[from].blank && ls[from].block == l.block && isCode(ls[from].vote) &&
			!proseLike(l.body) && !htmlText(l.body) {
			l.vote = vWeak
		}
	}
	for k := 1; k < len(ls); k++ {
		join(k, k-1)
	}
	for k := len(ls) - 2; k >= 0; k-- {
		join(k, k+1)
	}
	// an indented block without statements or column gaps whose lines read
	// mostly as sentences is a quoted paragraph ("Quoting the reporter:")
	for i := 0; i < len(ls); {
		j, n, prose, ok := i, 0, 0, true
		for ; j < len(ls) && ls[j].block == ls[i].block; j++ {
			if l := &ls[j]; !l.blank {
				n++
				ok = ok && l.indent > 0 && l.vote <= vWeak && !reGap.MatchString(l.body)
				if ok && l.vote == vProse && proseLike(l.body) {
					prose++
				}
			}
		}
		if ok && n > 1 && prose*2 >= n {
			for k := i; k < j; k++ {
				ls[k].vote = vProse
			}
		}
		i = j
	}
	// weakly indented lines without column gaps between two prose lines of
	// the same indentation are part of that paragraph
	for i := 1; i < len(ls); {
		if ls[i].vote != vWeak || ls[i-1].blank || ls[i-1].vote != vProse {
			i++
			continue
		}
		j, ok := i, true
		for ; j < len(ls) && !ls[j].blank && ls[j].vote == vWeak; j++ {
			ok = ok && ls[j].indent == ls[i-1].indent && !reGap.MatchString(ls[j].body)
		}
		if ok && j < len(ls) && !ls[j].blank && ls[j].vote == vProse && ls[j].indent == ls[i-1].indent {
			for k := i; k < j; k++ {
				ls[k].vote = vProse
			}
		}
		i = j
	}
	// one prose line between code lines of the same block is code (a table
	// row, "Uninit was created at:")
	for k := 1; k+1 < len(ls); k++ {
		l, p, n := &ls[k], &ls[k-1], &ls[k+1]
		if !l.blank && !isCode(l.vote) && !l.cont && !p.blank && isCode(p.vote) && !n.blank && isCode(n.vote) &&
			(p.vote > vWeak || n.vote > vWeak || !proseLike(l.body)) {
			l.vote = vWeak
		}
	}
	// runs of code inside a block
	prevCode := func(k int) bool { // nearest non-blank line before k is code
		for k--; k >= 0; k-- {
			if !ls[k].blank {
				return isCode(ls[k].vote)
			}
		}
		return false
	}
	nextCode := func(k int) bool {
		for k++; k < len(ls); k++ {
			if !ls[k].blank {
				return isCode(ls[k].vote)
			}
		}
		return false
	}
	type run struct{ i, j int } // [i, j)
	var lone []run
	for i := 0; i < len(ls); {
		if ls[i].blank || !isCode(ls[i].vote) {
			i++
			continue
		}
		j := i + 1
		for j < len(ls) && !ls[j].blank && ls[j].block == ls[i].block && isCode(ls[j].vote) {
			j++
		}
		if j-i == 1 {
			lone = append(lone, run{i, j})
		}
		i = j
	}
	var demote []int
	for _, r := range lone {
		l := &ls[r.i]
		wholeBlock := (r.i == 0 || ls[r.i-1].blank) && (r.j == len(ls) || ls[r.j].blank)
		switch {
		case l.vote == vStrong:
		case l.vote == vStmt && (l.indent > 0 || wholeBlock):
		case wholeBlock && (prevCode(r.i) || nextCode(r.i)):
		default:
			demote = append(demote, r.i)
		}
	}
	for _, k := range demote {
		ls[k].vote = vProse
	}
}

// emit groups classified lines into blocks.
func emit(ls []fline, in *inliner) []TextBlock {
	var out []TextBlock
	for i := 0; i < len(ls); {
		if ls[i].blank {
			i++
			continue
		}
		if isCode(ls[i].vote) {
			// code lines, blank lines between them, until a prose line
			j, end := i, i
			for j < len(ls) && (ls[j].blank || isCode(ls[j].vote)) {
				if !ls[j].blank {
					end = j + 1
				}
				j++
			}
			out = append(out, TextBlock{Code: true, Text: codeText(ls[i:end])})
			i = end
			continue
		}
		j := i + 1
		for j < len(ls) && !ls[j].blank && ls[j].block == ls[i].block && !isCode(ls[j].vote) {
			j++
		}
		raws := make([]string, 0, j-i)
		for k := i; k < j; k++ {
			raws = append(raws, ls[k].raw)
		}
		out = append(out, TextBlock{Segs: in.segs(strings.Join(raws, "\n"))})
		i = j
	}
	return out
}

// codeText joins code lines: trailing blanks cut, the indentation common to
// all non-blank lines removed, runs of blank lines kept as one.
func codeText(ls []fline) string {
	prefix, first := "", true
	for _, l := range ls {
		if l.blank {
			continue
		}
		lead := l.raw[:len(l.raw)-len(strings.TrimLeft(l.raw, " \t"))]
		if first {
			prefix, first = lead, false
			continue
		}
		n := 0
		for n < len(prefix) && n < len(lead) && prefix[n] == lead[n] {
			n++
		}
		prefix = prefix[:n]
	}
	var b strings.Builder
	blank := false
	for _, l := range ls {
		if l.blank {
			blank = true
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
			if blank {
				b.WriteByte('\n')
			}
		}
		blank = false
		b.WriteString(strings.TrimRight(l.raw[len(prefix):], " \t"))
	}
	return b.String()
}

// Inline code.

var (
	// an identifier chain with optional subscripts and one call
	reExpr    = regexp.MustCompile(`^[A-Za-z_][\w]*(?:\[[\w+\-*>.]*\])*(?:(?:->|::|\.)[A-Za-z_]\w*(?:\[[\w+\-*>.]*\])*)*(?:\([\w,.\->&*\[\]]*\))?$`)
	reSnake   = regexp.MustCompile(`[A-Za-z0-9]_[A-Za-z0-9]`)
	rePath    = regexp.MustCompile(`^(?:\.{1,2}/|/|~/)?(?:[\w@+-][\w.@+-]*/)+[\w.+-]*\.(?:` + codeExts + `)$`)
	reSysPath = regexp.MustCompile(`^/(?:etc|proc|sys|dev|tmp|var|usr|bin|sbin|root|home|opt|boot|run)/[\w.+-]+(?:/[\w.+-]+)*$`)
	reVar     = regexp.MustCompile(`^\$[A-Za-z_]\w*$`)
)

const codeExts = `c|h|cc|cpp|cxx|hpp|hh|go|rs|py|rb|php|phtml|inc|js|mjs|cjs|ts|tsx|jsx|java|kt|scala|cs|swift|m|mm|pl|pm|sh|bash|lua|asp|aspx|ashx|jsp|jspx|cgi|vue|svelte|erl|ex|exs|S|s|dts|dtsi|conf|cfg|ini|xml|json|yaml|yml|toml|properties|env|sql|tpl|twig|config`

// codeToken reports whether a punctuation-trimmed token is unmistakably code.
func codeToken(t string) bool {
	if len(t) < 3 || len(t) > 200 {
		return false
	}
	if t[0] == '$' {
		return reVar.MatchString(t)
	}
	if strings.ContainsAny(t, "/\\") {
		if rePath.MatchString(t) {
			first, _, _ := strings.Cut(strings.TrimLeft(t, "./~"), "/")
			return !strings.Contains(first, ".") // a host name: a URL without scheme
		}
		return reSysPath.MatchString(t)
	}
	if !reExpr.MatchString(t) {
		return false
	}
	switch {
	case strings.HasSuffix(t, "()"):
		return true
	case strings.Contains(t, "->"):
		return !reMenu.MatchString(t) // "Setup->Users->Username" is a menu path
	case strings.Contains(t, "::"):
		return true
	}
	// snake_case or SCREAMING_SNAKE in an identifier (not after a dot: "1.2_beta")
	core := t
	if k := strings.IndexAny(core, "(["); k >= 0 {
		core = core[:k]
	}
	if len(core) < 4 || reTitleSnake.MatchString(core) || strings.EqualFold(core, "x86_64") {
		return false // "X_T", "Snapdragon_High_Med_2016", an architecture
	}
	for _, part := range strings.Split(core, ".") {
		if reSnake.MatchString(part) {
			return true
		}
	}
	return false
}

// reTitleSnake: Capitalized_Words_2016, the way some vendors write product
// names.
var (
	reTitleSnake = regexp.MustCompile(`^(?:[A-Z][a-z]+|[A-Z]?\d+)(?:_(?:[A-Z][a-z]+|[A-Z]?\d+))+$`)
	reMenu       = regexp.MustCompile(`^[A-Z][a-z]+(?:->[A-Z][a-z]+)+$`)
)

// hasCodeToken reports whether s contains a code token.
func hasCodeToken(s string) bool {
	in := inliner{}
	for _, sg := range in.segs(s) {
		if sg.Code {
			return true
		}
	}
	return false
}

func isTokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("_./\\-:>()[]~$", c) >= 0
}

// inliner finds inline code in the paragraphs of one text.
type inliner struct {
	names map[string]bool // lower-case words of the record's product and vendor names: never code ("WS_FTP")
	spans int             // code spans so far (at most fmtMaxInline)
}

func newInliner(names []string) *inliner {
	in := &inliner{names: map[string]bool{}}
	for _, n := range names {
		for _, w := range strings.Fields(n) {
			if strings.ContainsAny(w, "_/:-.") && len(w) <= 200 {
				in.names[strings.ToLower(w)] = true
			}
		}
	}
	return in
}

// segs splits a paragraph into plain text and code tokens. Joining the
// segments (with backticks around Tick ones) gives s back.
func (in *inliner) segs(s string) []TextSeg {
	spans := &in.spans
	var out []TextSeg
	plain := 0 // start of pending plain text
	flush := func(to int) {
		if to > plain {
			out = append(out, TextSeg{Text: s[plain:to]})
		}
	}
	code := func(i, j int, tick bool) {
		lo, hi := i, j
		if tick {
			lo, hi = i-1, j+1
		}
		flush(lo)
		seg := TextSeg{Text: s[i:j], Code: true, Tick: tick}
		if strings.Contains(seg.Text, "->") {
			seg.Arrow = strings.Split(seg.Text, "->")
		}
		out = append(out, seg)
		plain = hi
		*spans++
	}
	i := 0
	for i < len(s) && *spans < fmtMaxInline {
		switch c := s[i]; {
		case isSpaceByte(c):
			i++
		case c == '`':
			// `code`: on one line, not empty, not too long
			if end := strings.IndexByte(s[i+1:min(len(s), i+2+fmtMaxTick)], '`'); end > 0 {
				if in := s[i+1 : i+1+end]; !strings.Contains(in, "\n") && strings.TrimSpace(in) != "" {
					code(i+1, i+1+end, true)
					i += end + 2
					continue
				}
			}
			i++
		default:
			// a word: up to whitespace or a backtick. URLs, e-mail
			// addresses and host names are never code.
			we := i
			for we < len(s) && !isSpaceByte(s[we]) && s[we] != '`' {
				we++
			}
			word := s[i:we]
			if strings.Contains(word, "://") || strings.Contains(word, "@") ||
				strings.HasPrefix(strings.ToLower(strings.TrimLeft(word, "(<[\"'")), "www.") {
				i = we
				continue
			}
			// ASCII token runs inside the word (CJK text around them
			// stays plain)
			for k := i; k < we && *spans < fmtMaxInline; {
				if !isTokenByte(s[k]) {
					k++
					continue
				}
				j := k
				for j < we && isTokenByte(s[j]) {
					j++
				}
				if j-k <= 256 {
					if a, b := trimToken(s, k, j); a < b && codeToken(s[a:b]) && !in.names[strings.ToLower(s[a:b])] {
						code(a, b, false)
					}
				}
				k = j
			}
			i = we
		}
	}
	flush(len(s))
	return out
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

// trimToken cuts punctuation around s[i:j] that belongs to the sentence:
// leading brackets and colons, trailing sentence marks, unbalanced closing
// brackets.
func trimToken(s string, i, j int) (int, int) {
	for i < j && strings.IndexByte("([:-", s[i]) >= 0 {
		i++
	}
	for i < j {
		c := s[j-1]
		switch {
		case strings.IndexByte(".,:;-", c) >= 0:
			j--
		case c == ')' && strings.Count(s[i:j], "(") < strings.Count(s[i:j], ")"):
			j--
		case c == ']' && strings.Count(s[i:j], "[") < strings.Count(s[i:j], "]"):
			j--
		default:
			return i, j
		}
	}
	return i, j
}
