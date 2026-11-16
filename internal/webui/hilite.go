package webui

import (
	"regexp"
	"strings"
)

// Hilite colours the code blocks that FormatText cuts out of upstream
// descriptions. It produces no markup: it splits a block into lines and the
// lines into tokens, each with one class of a small fixed set, and the
// template renders every token with normal escaping.
//
// The rules come from the 9,739 code blocks that FormatText finds in the
// 405,761 descriptions of the full database (2026-11; TestHiliteCorpus in
// hilite_corpus_test.go reruns the count over a dump). Nearly all of them
// are from Linux kernel commit messages. A block gets one kind, from the
// share of its lines with each shape; a line with a signature of its own (a
// log line, a prompt) is tokenized as such in any block, the other lines by
// the block's kind:
//
//   - log (5,689 blocks): kernel log, oops, sanitizer, lockdep and kmemleak
//     reports, stack traces, register dumps; a block with 30% or more log
//     lines. A log line is one with a signature of reStrong (the list
//     prose.go uses to find code), a printk timestamp (also after a "<4>"
//     level) or syslog prefix, a decoded frame "func (file.c:12)", a
//     crash(8) frame "#3 [addr] func at addr" or a /proc stack frame
//     "[<0>] func+0x1/0x2". Colours: the severity marker that opens a report
//     ("BUG: KASAN:", "WARNING:", "Kernel panic - not syncing") as an error,
//     section labels ("Call Trace:", "Modules linked in:") as keywords, the
//     function of a frame, hex numbers (0x…, or 8+ hex digits with a digit,
//     or 16 letters); timestamps, frame offsets "+0x1a/0x30", "[module]",
//     "[inline]", "[<addr>]", file:line, "<TASK>" and the bytes after "Code:"
//     dim. Quotes are never strings in a log. Statement lines of a log block
//     (the lock() calls of a lockdep scenario) are tokenized as src.
//   - src (2,563): C-like source and the call-flow diagrams of kernel commits
//     (pseudo-C with calls, "//" comments, "->" arrows, two columns for two
//     CPUs or threads); a block with 30% or more statement lines, not
//     counting the bare names of a call tree. Colours: comments, strings and
//     char literals closed on their line, numbers, file:line, preprocessor
//     directives, a few keywords and the identifier right before "(". A
//     keyword is one only where it is used as one ("if (", "for x in",
//     "case …:", "struct name"; not "timer->function", "null-ptr-deref",
//     "class=", "(for each dev)"). A line whose words outside comments and
//     strings read as a sentence (three or more plain words that are not
//     keywords or arguments) keeps only its comments and strings. Text after
//     " # " or a "<-" arrow is an annotation: plain, its words not counted.
//     objdump lines stay plain.
//   - shell (487): prompt transcripts ("$ cmd", "# cmd" with a known
//     command, "user@host:~# cmd", "[root@host ~]# cmd", ">>> expr") and
//     command scripts (half or more lines start with a known command). The
//     prompt is dim, the command words (also after |, ;, &&, $( and `) are
//     functions, shell keywords are keywords, quotes closed on their line are
//     strings, "#" after a blank is a comment. A command's output is plain
//     unless it is a log line; source before the first prompt (the program a
//     transcript compiles) is src; ">>> " lines are src.
//   - diff (5): a hunk or file header, or only "+", "-" and context lines
//     with both "+" and "-": "+" lines added, "-" lines removed, headers dim.
//   - http (5): a request or status line: method keyword, status number,
//     header names as functions, the body as src.
//   - plain (990): everything else (tables, hex dumps, trees of names,
//     prose that FormatText kept as code). Only log lines get colours.
//
// Wrong colours are worse than none, so every rule is anchored on a shape
// that the data showed to be unambiguous, and a line that does not fit its
// block's kind is left plain. The traps of the data, each pinned by a case
// of hilite_test.go (testdata/hilite/cases.txt): apostrophes ("leader's",
// "doesn't") never open a string; strings never span lines (a shell quote
// left open makes the rest of the command plain, and a string holding "$("
// too); "#" is a comment only in shell context and only after a blank (not
// "#include", not "#0", not a root prompt "# cmd"); "//" opens a comment
// only after a blank or punctuation and not before a path ("http://",
// "results//generic", "//srv/share"); a "//" or one-line "/*" comment ends
// at a column gap (four spaces or a tab before more text), so the second
// column of a CPU0/CPU1 diagram keeps its own calls and comments; a "/*"
// comment spans lines only in src, only to its "*/" within 40 lines and
// only if none of those lines has a column gap.
//
// Hilite is lossless (the token texts of all lines joined by "\n" are the
// block's text), total and linear in its input. Blocks of more than
// hlMaxLines lines or hlMaxBytes bytes (none in the data, whose largest
// block has 111 lines and 3.9 KiB) and lines longer than fmtMaxLine bytes
// are plain.

// Token classes (the stylesheet colours them; "" is plain text).
const (
	HlComment = "hc" // comment
	HlString  = "hs" // string or character literal
	HlNumber  = "hn" // number, hex value, address
	HlKeyword = "hk" // keyword, report section label, HTTP method
	HlFunc    = "hf" // called function, frame function, shell command, HTTP header name
	HlError   = "he" // log severity marker
	HlMeta    = "hm" // dim: timestamp, frame offset, file:line, prompt, diff header
	HlAdd     = "ha" // diff: added line
	HlDel     = "hd" // diff: removed line
)

const (
	hlMaxLines = 400
	hlMaxBytes = 32 << 10
	hlSpanMax  = 40 // lines a /* comment may span
)

// CodeTok is a run of a code line with one class ("" is plain).
type CodeTok struct {
	Class string
	Text  string
}

// CodeLine is one line of a code block, without its line break.
type CodeLine struct{ Toks []CodeTok }

// Lines are the lines of a code block, tokenized by Hilite (the template
// wraps each in an element so the stylesheet can number them).
func (b TextBlock) Lines() []CodeLine { return Hilite(b.Text) }

// Block kinds.
const (
	kindPlain = iota
	kindLog
	kindSrc
	kindShell
	kindDiff
	kindHTTP
)

var kindNames = [...]string{"plain", "log", "src", "shell", "diff", "http"}

// Hilite splits a code block into lines of tokens.
func Hilite(text string) []CodeLine {
	lines := strings.Split(text, "\n")
	out := make([]CodeLine, len(lines))
	if len(text) > hlMaxBytes || len(lines) > hlMaxLines {
		for i, l := range lines {
			out[i] = plainLine(l)
		}
		return out
	}
	h := newHiliter(lines)
	for i := range lines {
		out[i] = h.line(i)
	}
	return out
}

func plainLine(l string) CodeLine {
	if l == "" {
		return CodeLine{}
	}
	return CodeLine{Toks: []CodeTok{{Text: l}}}
}

// Line facts used to choose the block kind and each line's tokenizer.
type hlLine struct {
	s      string
	body   string // trimmed
	long   bool   // longer than fmtMaxLine: plain
	log    bool   // a log signature (logSig) and not a prompt or HTTP line
	prompt int    // length of a shell prompt at the start of s (0: none)
	py     bool   // the prompt is ">>> "
	cmd    bool   // a command line without prompt (cmdLine)
	stmt   bool   // a source statement or call line
	http   bool   // HTTP request or status line
}

type hiliter struct {
	ls     []hlLine
	kind   int
	script bool // shell block without prompts: "#" lines are comments
	// /* spans (src): close[i] is the first line >= i that holds "*/" (or
	// len), gaps[i] the number of lines before i with a column gap
	close, gaps []int
	cmtEnd      int  // line where the open /* comment ends, -1: none
	shellCont   int  // the previous line was a shell line ending in "\" (shCont, shQuoted)
	out         bool // after a prompt: command output
	head        bool // http: between a request or status line and a blank line
	firstPrompt int  // index of the first prompt line (len: none)
	preSrc      bool // the lines before the first prompt are source
}

var (
	// a shell prompt: "$ ", "user@host:~# ", "[root@host ~]# ", ">>> ";
	// "# " is checked apart (it is a heading or a comment as often)
	rePromptHL = regexp.MustCompile(`^\s*(?:\$ |[\w.-]+@[\w.-]+(?::\S*)?\s?[#$>] |\[[\w.@~/ -]+\][#$] |>>> )`)
	reHashCmd  = regexp.MustCompile(`^[ \t]*# (?:\./|/|~/)?[a-z][\w.+-]*(?: |$)`)
	reHunk     = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)
	reColGap   = regexp.MustCompile(`\S(?:\t| {4,})\S`)
	reCall     = regexp.MustCompile(`[A-Za-z_]\w*\(`)
	// a bare name in a call tree ("  - f2fs_write_inode", "|-- foo"): not
	// counted for or against source
	reTreeName = regexp.MustCompile("^(?:[-|`+>:*]+\\s*)*[A-Za-z_][\\w.]*$")
	reCmdShape = regexp.MustCompile(`^(?:\./|/|~/)?[a-z][\w.+-]*(?: |$)`)
)

func newHiliter(raw []string) *hiliter {
	h := &hiliter{ls: make([]hlLine, len(raw)), cmtEnd: -1}
	n, nLog, nPrompt, nCmd, nStmt, nHTTP, nName := 0, 0, 0, 0, 0, 0, 0
	h.firstPrompt = len(raw)
	hashPrompt := false
	hunk, plus, minus, other, fileHdr := false, 0, 0, 0, false
	for i, s := range raw {
		l := &h.ls[i]
		l.s, l.body = s, strings.TrimSpace(s)
		if l.body == "" {
			continue
		}
		n++
		if len(s) > fmtMaxLine {
			l.long = true
			other++
			continue
		}
		b := l.body
		if reHunk.MatchString(s) {
			hunk = true
		}
		switch {
		case strings.HasPrefix(s, "+++ ") && i > 0 && strings.HasPrefix(raw[i-1], "--- "):
			fileHdr = true
		case strings.HasPrefix(s, "+") && !strings.HasPrefix(s, "+0x"):
			plus++
		case strings.HasPrefix(s, "-"):
			minus++
		case !strings.HasPrefix(s, " ") && !strings.HasPrefix(s, "\t") && !reHunk.MatchString(s):
			other++
		}
		if m := rePromptHL.FindStringIndex(s); m != nil && m[1] < len(s) {
			l.prompt, l.py = m[1], strings.HasSuffix(s[:m[1]], ">>> ")
		} else if reHashCmd.MatchString(s) {
			lead := strings.IndexByte(s, '#') + 2
			if w := firstWord(s[lead:]); shellCmds[w] || strings.HasPrefix(w, "./") {
				l.prompt = lead
				hashPrompt = true
			}
		}
		l.http = reHTTPRL.MatchString(b)
		l.log = l.prompt == 0 && !l.http && logSig(b)
		l.cmd = l.prompt == 0 && cmdLine(b)
		// (a log line is never a statement: reStrong comes first in voteLine)
		l.stmt = !l.log && l.prompt == 0 && (stmtLine(b) || reCall.MatchString(b) && stmtWords(b) <= 2)
		if l.prompt > 0 {
			h.firstPrompt = min(h.firstPrompt, i)
		}
		switch {
		case l.log:
			nLog++
		case l.prompt > 0:
			nPrompt++
		case l.http:
			nHTTP++
		case l.cmd:
			nCmd++
		case l.stmt:
			nStmt++
		case reTreeName.MatchString(b):
			nName++
		}
	}
	// "# cmd" is a prompt in a transcript whose other "#" lines are
	// prompts with a known command ("# exec 5>>events/…/enable")
	for i := range h.ls {
		if l := &h.ls[i]; hashPrompt && l.prompt == 0 && !l.long && reHashCmd.MatchString(l.s) &&
			!proseLike(strings.TrimSpace(l.s[strings.IndexByte(l.s, '#')+2:])) {
			l.prompt, l.log, l.cmd, l.stmt = strings.IndexByte(l.s, '#')+2, false, false, false
			h.firstPrompt = min(h.firstPrompt, i)
		}
	}
	// the lines before the first prompt of a transcript: the source of the
	// program it runs, or anything else (plain)
	pre, preStmt := 0, 0
	for i := 0; i < h.firstPrompt && i < len(h.ls); i++ {
		if l := h.ls[i]; l.body != "" {
			pre++
			if l.stmt {
				preStmt++
			}
		}
	}
	h.preSrc = preStmt > 0 && preStmt*10 >= pre*3
	switch {
	case n == 0:
	case hunk || fileHdr || plus > 0 && minus > 0 && other == 0:
		h.kind = kindDiff
	case nHTTP > 0 && nLog == 0:
		h.kind = kindHTTP
	case nLog > 0 && nLog*10 >= n*3:
		h.kind = kindLog
	case nPrompt > 0 || nCmd > 0 && nCmd*2 >= n:
		h.kind = kindShell
		h.script = nPrompt == 0
	case nStmt > 0 && nStmt*10 >= (n-nName)*3:
		h.kind = kindSrc
	}
	if h.kind == kindSrc {
		h.close = make([]int, len(raw)+1)
		h.gaps = make([]int, len(raw)+1)
		h.close[len(raw)] = len(raw)
		for i := len(raw) - 1; i >= 0; i-- {
			h.close[i] = h.close[i+1]
			if strings.Contains(raw[i], "*/") {
				h.close[i] = i
			}
		}
		for i, s := range raw {
			h.gaps[i+1] = h.gaps[i]
			if reColGap.MatchString(s) {
				h.gaps[i+1]++
			}
		}
	}
	return h
}

// logSig reports whether a trimmed line has a log signature.
func logSig(b string) bool {
	return reLogTime.MatchString(b) || reStrong.MatchString(b) || reDecoded.MatchString(b) || reCrashFrame.MatchString(b)
}

// line tokenizes line i (lines are tokenized in order).
func (h *hiliter) line(i int) CodeLine {
	l := &h.ls[i]
	sc := &scanner{s: l.s}
	cont := h.shellCont
	h.shellCont = 0
	switch {
	case l.body == "":
		h.out, h.head = false, false
		return plainLine(l.s)
	case l.long:
		h.cmtEnd = -1
		return plainLine(l.s)
	case h.cmtEnd >= i:
		// inside a /* comment opened on an earlier line
		if h.cmtEnd > i {
			sc.mark(0, len(l.s), HlComment)
			return sc.done()
		}
		k := strings.Index(l.s, "*/") + 2
		sc.mark(0, k, HlComment)
		h.cmtEnd = -1
		h.src(sc, i, k)
		return sc.done()
	}
	switch h.kind {
	case kindDiff:
		diffLine(sc)
		return sc.done()
	case kindHTTP:
		h.httpLine(sc, i)
		return sc.done()
	}
	switch {
	case l.prompt > 0:
		sc.mark(len(l.s)-len(strings.TrimLeft(l.s, " \t")), l.prompt, HlMeta)
		if l.py {
			h.src(sc, i, l.prompt)
		} else {
			h.shellCont = shellLine(sc, l.prompt, true)
		}
		h.out = h.shellCont == 0
		return sc.done()
	case cont == shQuoted:
		h.shellCont = shellQuoted(l.s)
		h.out = h.shellCont == 0 && h.firstPrompt <= i
		return sc.done()
	case cont == shCont:
		h.shellCont = shellLine(sc, 0, false)
		h.out = h.shellCont == 0 && h.firstPrompt <= i
		return sc.done()
	case l.log:
		logLine(sc)
		return sc.done()
	}
	switch h.kind {
	case kindLog:
		if l.stmt {
			h.src(sc, i, 0)
		} else {
			logLine(sc)
		}
	case kindShell:
		switch {
		case i < h.firstPrompt && h.preSrc:
			h.src(sc, i, 0)
		case h.out:
			// command output stays plain
		case h.script && strings.HasPrefix(l.body, "#"):
			sc.mark(len(l.s)-len(strings.TrimLeft(l.s, " \t")), len(l.s), HlComment)
		case h.script:
			// a command: known, a shell keyword, or shaped like one
			// ("unshare -Urm", "sync") and not a sentence
			h.shellCont = shellLine(sc, 0, l.cmd || shellKeywords[firstWord(l.body)] ||
				reCmdShape.MatchString(l.body) && !proseLike(l.body) && !strings.HasSuffix(firstWord(l.body), ":"))
		}
	case kindSrc:
		h.src(sc, i, 0)
	}
	return sc.done()
}

func firstWord(b string) string {
	w, _, _ := strings.Cut(b, " ")
	return w
}

// scanner collects the tokens of one line: mark(i, j, class) makes s[i:j]
// a token (the text since the previous token is plain); done adds the rest
// as plain text and merges neighbours of one class.
type scanner struct {
	s    string
	toks []struct {
		class string
		i, j  int
	}
	pos int
}

func (sc *scanner) mark(i, j int, class string) {
	if i < sc.pos || j <= i || j > len(sc.s) {
		return
	}
	if i > sc.pos {
		sc.add(sc.pos, i, "")
	}
	sc.add(i, j, class)
	sc.pos = j
}

func (sc *scanner) add(i, j int, class string) {
	if n := len(sc.toks); n > 0 && sc.toks[n-1].class == class && sc.toks[n-1].j == i {
		sc.toks[n-1].j = j
		return
	}
	sc.toks = append(sc.toks, struct {
		class string
		i, j  int
	}{class, i, j})
}

func (sc *scanner) done() CodeLine {
	if sc.pos < len(sc.s) {
		sc.add(sc.pos, len(sc.s), "")
		sc.pos = len(sc.s)
	}
	if len(sc.toks) == 0 {
		return CodeLine{}
	}
	toks := make([]CodeTok, len(sc.toks))
	for k, t := range sc.toks {
		toks[k] = CodeTok{Class: t.class, Text: sc.s[t.i:t.j]}
	}
	return CodeLine{Toks: toks}
}

func isIdentStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }

// gapAt reports whether a column gap starts at s[i] (a tab, or four
// spaces, followed by more text).
func gapAt(s string, i int) bool {
	j := i
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return j < len(s) && (j-i >= 4 || strings.IndexByte(s[i:j], '\t') >= 0)
}

// commentEnd is the end of a "//" (or unclosed "/*") comment starting at
// i: the end of the line or the start of a column gap.
func commentEnd(s string, i int) int {
	for k := i + 2; k < len(s); k++ {
		if (s[k] == ' ' || s[k] == '\t') && gapAt(s, k) {
			return k
		}
	}
	return len(s)
}

// Logs.

var (
	// a printk timestamp ("[  12.345678]", "[  1.2][  T301]", with a "<4>"
	// level before it) or a syslog prefix ("Sep 07 11:55:32 host kernel:")
	reLogTime = regexp.MustCompile(`^\s*(?:<\d>\s*)?(?:\[\s*\d+\.\d+\](?:\[\s*[A-Z]*\s*\d+\])?|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ kernel:)`)
	// decoded frames ("func (fs/x.c:12)") and crash(8) frames ("#3
	// [ffffa25ec6978b60] oops_end at ffffffff8c627f2b")
	reDecoded    = regexp.MustCompile(`^(?:[\w.$]+ \([\w./-]+\.[chS]:\d+|\[<[0-9a-f]+>\] [\w.$]+\+0x)`) // also /proc/PID/stack
	reCrashFrame = regexp.MustCompile(`^#\d+ (\[[0-9a-f]{8,16}\]) ([\w.$]+) at [0-9a-f]+`)
	reLogErr     = regexp.MustCompile(`^(?:(?:BUG|WARNING|INFO|ODEBUG|UBSAN|KASAN|KMSAN|KCSAN|KFENCE|Oops|refcount_t|Internal error|invalid opcode|divide error|DMA-API|assertion failed): ?)+|` +
		`^(?:Kernel panic - not syncing|general protection fault|\[ BUG: [^\]]+\]|Oops ?\[#\d+\]|Unable to handle kernel [a-zA-Z ]*?(?:dereference|paging request|access|fault)|kernel BUG at|unreferenced object|list_(?:add|del) corruption|\*\*\* DEADLOCK \*\*\*)`)
	reLogLabel = regexp.MustCompile(`^(?:Call [Tt]race:|Modules linked in:|Hardware name:|Workqueue:|RIP:|Mem abort info:|Data abort info:|Instruction dump:|stack backtrace:|irq event stamp:|` +
		`Possible unsafe locking scenario:|other info that might help us debug this:|Chain exists of:|but task is already holding lock:|` +
		`(?:Allocated|Freed) by task \d+(?: on cpu \d+ at [\d.]+s)?:|Last potentially related work creation:|Uninit was (?:created|stored) at:|` +
		`Memory state around the buggy address:|The buggy address belongs to|Preemption disabled at:|hex dump \(first \d+ bytes\):|backtrace \(crc [0-9a-f]+\):)`)
	reLogDim   = regexp.MustCompile(`^(?:</?(?:TASK|IRQ|NMI|SOFTIRQ|EOI)>|-+\[ (?:cut here|end trace [0-9a-f]*) \]-+|={10,}$)`)
	reLogFrame = regexp.MustCompile(`^([A-Za-z_.$][\w.$]*)(\+0x[0-9a-f]+/0x[0-9a-f]+)(?: \[[\w-]+\])?`)
	reFileLine = regexp.MustCompile(`^[\w./-]*\w\.(?:c|h|S|rs|cc|cpp):\d+(?::\d+)?`)
	reHexWord  = regexp.MustCompile(`^(?:0x[0-9a-fA-F]+|[0-9a-f]{8,})`)
	reAddrBr   = regexp.MustCompile(`^\[<[0-9a-f]+>\]`)
	// a frame without an offset: "func file.c:123 [inline]", "func (file.c:12)"
	reBareFrame = regexp.MustCompile(`^([A-Za-z_][\w.$]*) \(?[\w./-]*\w\.(?:c|h|S|rs):\d+`)
)

// logStop: words that open sentences of a log, not frames ("at fs/x.c:12").
var logStop = map[string]bool{"at": true, "in": true, "from": true, "by": true, "and": true, "of": true, "to": true, "is": true, "was": true}

// logLine tokenizes a kernel log line.
func logLine(sc *scanner) {
	s := sc.s
	i := 0
	if m := reLogTime.FindStringIndex(s); m != nil {
		sc.mark(len(s)-len(strings.TrimLeft(s, " \t")), m[1], HlMeta)
		i = m[1]
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	rest := s[i:]
	switch {
	case reLogErr.MatchString(rest):
		m := reLogErr.FindStringIndex(rest)
		sc.mark(i, i+len(strings.TrimRight(rest[:m[1]], " ")), HlError)
		i += m[1]
	case strings.HasPrefix(rest, "Code: "):
		sc.mark(i, i+5, HlKeyword)
		sc.mark(i+6, len(s), HlMeta)
		return
	case reLogLabel.MatchString(rest):
		m := reLogLabel.FindStringIndex(rest)
		sc.mark(i, i+m[1], HlKeyword)
		i += m[1]
	case reLogDim.MatchString(rest):
		m := reLogDim.FindStringIndex(rest)
		sc.mark(i, i+m[1], HlMeta)
		i += m[1]
	case reCrashFrame.MatchString(rest):
		m := reCrashFrame.FindStringSubmatchIndex(rest)
		sc.mark(i+m[2], i+m[3], HlMeta)
		sc.mark(i+m[4], i+m[5], HlFunc)
		i += m[5]
	default:
		if m := reBareFrame.FindStringSubmatchIndex(rest); m != nil && reLogFrame.FindStringIndex(rest) == nil && !logStop[rest[:m[3]]] {
			sc.mark(i, i+m[3], HlFunc)
			i += m[3]
		}
	}
	for i < len(s) {
		c := s[i]
		if i > 0 && (isWordByte(s[i-1]) || s[i-1] == '.' || s[i-1] == '/' || s[i-1] == '-' && c != '[' && !strings.HasPrefix(s[i:], "0x")) {
			i++
			continue
		}
		r := s[i:]
		// the word at i (its first 256 bytes, so that the scan stays
		// linear), for cheap checks before the regular expressions
		word := r[:min(len(r), 256)]
		if we := strings.IndexAny(word, " \t()"); we >= 0 {
			word = word[:we]
		}
		switch {
		case c == '[':
			if m := reAddrBr.FindStringIndex(r); m != nil {
				sc.mark(i, i+m[1], HlMeta)
				i += m[1]
				continue
			}
			if strings.HasPrefix(r, "[inline]") {
				sc.mark(i, i+8, HlMeta)
				i += 8
				continue
			}
		case (isIdentStart(c) || c == '.' || c == '$') && strings.Contains(word, "+0x"):
			if m := reLogFrame.FindStringSubmatchIndex(r); m != nil {
				sc.mark(i, i+m[3], HlFunc)
				sc.mark(i+m[4], i+m[1], HlMeta)
				i += m[1]
				continue
			}
		}
		if isWordByte(c) || c == '.' || c == '/' {
			if strings.IndexByte(word, ':') > 0 && strings.IndexByte(word, '.') >= 0 {
				if m := reFileLine.FindStringIndex(r); m != nil && (m[1] == len(r) || !isWordByte(r[m[1]])) {
					sc.mark(i, i+m[1], HlMeta)
					i += m[1]
					continue
				}
			}
			if !isHexByte(c) {
				i++
				continue
			}
			if m := reHexWord.FindStringIndex(r); m != nil && (m[1] == len(r) || !isWordByte(r[m[1]])) &&
				(strings.ContainsAny(r[:m[1]], "0123456789") || m[1] == 16) {
				sc.mark(i, i+m[1], HlNumber)
				i += m[1]
				continue
			}
		}
		i++
	}
}

// Source.

// srcKeywords: C and the scripting languages of the data (JavaScript,
// Python, PHP snippets). Words that are common in diagram prose ("as",
// "from", "with", "this") are left out.
var srcKeywords = map[string]bool{"if": true, "else": true, "for": true, "while": true, "do": true, "switch": true,
	"case": true, "default": true, "return": true, "goto": true, "break": true, "continue": true, "struct": true,
	"union": true, "enum": true, "typedef": true, "static": true, "const": true, "volatile": true, "inline": true,
	"extern": true, "sizeof": true, "unsigned": true, "signed": true, "void": true, "int": true, "char": true,
	"long": true, "short": true, "bool": true, "true": true, "false": true, "NULL": true, "null": true,
	"function": true, "var": true, "let": true, "def": true, "class": true, "import": true, "try": true,
	"catch": true, "throw": true, "None": true, "True": true, "False": true, "elif": true}

var reAsmDump = regexp.MustCompile(`^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} )+`)

var rePreproc = regexp.MustCompile(`^\s*#\s*(?:include|define|undef|ifdef|ifndef|if|elif|else|endif|pragma|error)\b`)

// src tokenizes s[from:] of line i as C-like source.
func (h *hiliter) src(sc *scanner, i, from int) {
	s := sc.s
	first := len(sc.toks)
	k := from
	if reAsmDump.MatchString(s) {
		return // objdump output: bytes and mnemonics, no source tokens
	}
	if from == 0 {
		if m := rePreproc.FindStringIndex(s); m != nil {
			sc.mark(strings.IndexByte(s, '#'), m[1], HlKeyword)
			k = m[1]
			rest := strings.TrimLeft(s[k:], " \t")
			if j := k + len(s[k:]) - len(rest); strings.HasPrefix(rest, "<") {
				if e := strings.IndexByte(rest, '>'); e > 0 {
					sc.mark(j, j+e+1, HlString)
				}
			}
		}
	}
	var code strings.Builder // the text outside comments and strings
	for k < len(s) {
		c := s[k]
		prev := byte(' ')
		if k > 0 {
			prev = s[k-1]
		}
		switch {
		case c == '/' && k+1 < len(s) && s[k+1] == '/' && cmtLead(prev, k == from) && !pathAt(s, k+2):
			e := commentEnd(s, k)
			sc.mark(k, e, HlComment)
			code.WriteByte(' ')
			k = e
			continue
		case c == '/' && k+1 < len(s) && s[k+1] == '*' && (cmtLead(prev, k == from) || prev == '(' || prev == '|'):
			if e := strings.Index(s[k+2:], "*/"); e >= 0 {
				sc.mark(k, k+2+e+2, HlComment)
				k += e + 4
				code.WriteByte(' ')
				continue
			}
			if h.spans(i, k) {
				sc.mark(k, len(s), HlComment)
				h.cmtEnd = h.close[i+1]
				k = len(s)
				continue
			}
			e := commentEnd(s, k)
			sc.mark(k, e, HlComment)
			code.WriteByte(' ')
			k = e
			continue
		case c == '"' || c == '\'' && !isWordByte(prev):
			if e := quoteEnd(s, k); e > 0 {
				sc.mark(k, e, HlString)
				code.WriteByte(' ')
				k = e
				continue
			}
		case c == '#' && (prev == ' ' || prev == '\t' || k == from) && k+1 < len(s) && s[k+1] == ' ':
			// "z_erofs_do_read_page() # for another page": "#" is not a
			// comment in C, but the words after it are not code either
			k = commentEnd(s, k)
			continue
		case c == '<' && k+1 < len(s) && s[k+1] == '-' && (prev == ' ' || prev == '\t'):
			// "<-- use after free": an annotation, plain like the rest of
			// its column, and not counted as words of the line
			k = commentEnd(s, k)
			continue
		case c >= '0' && c <= '9' && !isWordByte(prev) && prev != '.':
			if m := reFileLine.FindStringIndex(s[k:]); m != nil && (k+m[1] == len(s) || !isWordByte(s[k+m[1]])) {
				sc.mark(k, k+m[1], HlMeta)
				k += m[1]
				continue
			}
			e := k + 1
			if c == '0' && e < len(s) && (s[e] == 'x' || s[e] == 'X') {
				e++
				for e < len(s) && isHexByte(s[e]) {
					e++
				}
			} else {
				for e < len(s) && s[e] >= '0' && s[e] <= '9' {
					e++
				}
				if e+1 < len(s) && s[e] == '.' && s[e+1] >= '0' && s[e+1] <= '9' {
					for e++; e < len(s) && s[e] >= '0' && s[e] <= '9'; e++ {
					}
				}
			}
			for e < len(s) && strings.IndexByte("uUlL", s[e]) >= 0 {
				e++
			}
			if e == len(s) || !isWordByte(s[e]) {
				sc.mark(k, e, HlNumber)
			}
			code.WriteString(s[k:e])
			k = e
			continue
		case isIdentStart(c) && !isWordByte(prev):
			if m := reFileLine.FindStringIndex(s[k:]); m != nil && (k+m[1] == len(s) || !isWordByte(s[k+m[1]])) {
				sc.mark(k, k+m[1], HlMeta)
				k += m[1]
				continue
			}
			e := k + 1
			for e < len(s) && isWordByte(s[e]) {
				e++
			}
			w := s[k:e]
			switch {
			case srcKeywords[w] && srcKeyword(s, k, e):
				sc.mark(k, e, HlKeyword)
			case e < len(s) && s[e] == '(':
				sc.mark(k, e, HlFunc)
			}
			code.WriteString(w)
			k = e
			continue
		}
		code.WriteByte(c)
		k++
	}
	// a sentence keeps only its comments and strings
	if proseWords(code.String()) > 2 {
		for t := first; t < len(sc.toks); t++ {
			if c := sc.toks[t].class; c == HlKeyword || c == HlFunc || c == HlNumber {
				sc.toks[t].class = ""
			}
		}
		merged := sc.toks[:first]
		for _, t := range sc.toks[first:] {
			if n := len(merged); n > 0 && merged[n-1].class == t.class && merged[n-1].j == t.i {
				merged[n-1].j = t.j
				continue
			}
			merged = append(merged, t)
		}
		sc.toks = merged
	}
}

// srcKeyword reports whether the keyword s[k:e] is used as one: not a
// member ("timer->function", "x.new"), not part of a hyphenated word
// ("null-ptr-deref"), and "struct", "union" and "enum" before a name.
func srcKeyword(s string, k, e int) bool {
	if k > 0 && (s[k-1] == '.' || s[k-1] == '-' || k > 1 && s[k-2] == '-' && s[k-1] == '>') ||
		e < len(s) && s[e] == '-' && e+1 < len(s) && isWordByte(s[e+1]) {
		return false
	}
	rest := strings.TrimLeft(s[e:], " \t")
	if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
		return false // an attribute or a variable: class="row", new = …
	}
	switch s[k:e] {
	case "struct", "union", "enum":
		return e+1 < len(s) && s[e] == ' ' && isIdentStart(s[e+1])
	case "if", "for", "while", "switch", "catch":
		// "if (", "for x in y", a Python "if x:"; not "(for each macsec dev)"
		return strings.HasPrefix(rest, "(") || s[k:e] == "for" && reForIn.MatchString(rest) ||
			s[k:e] != "catch" && strings.HasSuffix(strings.TrimRight(s, " \t"), ":")
	case "do", "try", "else":
		return rest == "" || strings.IndexByte("{:;", rest[0]) >= 0 || s[k:e] == "else" && strings.HasPrefix(rest, "if")
	case "case":
		return strings.Contains(rest, ":")
	case "default":
		return strings.HasPrefix(rest, ":")
	}
	return true
}

var reForIn = regexp.MustCompile(`^[A-Za-z_]\w* in `)

// pathAt reports whether the word at s[k:] holds a '/': "//srv/share" and
// "//evil.com/x" are paths, "//FREE" and "// use" comments.
func pathAt(s string, k int) bool {
	for ; k < len(s) && s[k] != ' ' && s[k] != '\t'; k++ {
		if s[k] == '/' {
			return true
		}
	}
	return false
}

// cmtLead: a comment opener may follow a blank, the start of the scanned
// text or code punctuation, not a word, ':' ("http://") or '/'.
func cmtLead(prev byte, start bool) bool {
	return start || strings.IndexByte(" \t;){},", prev) >= 0
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// quoteEnd is the end of the string literal that opens at s[i] (after its
// closing quote), or 0 when it does not close on the line or its closing
// quote is followed by a word character ("it's a 'bad' idea" is fine,
// "'s" is not a string).
func quoteEnd(s string, i int) int {
	q := s[i]
	for k := i + 1; k < len(s); k++ {
		switch s[k] {
		case '\\':
			k++
		case q:
			if k+1 < len(s) && isWordByte(s[k+1]) {
				return 0
			}
			return k + 1
		}
	}
	return 0
}

// spans reports whether the unclosed "/*" at s[k] of line i is a comment
// that goes on to the line holding its "*/": within hlSpanMax lines, with
// no column gap after it on line i nor on any line up to the end.
func (h *hiliter) spans(i, k int) bool {
	if h.kind != kindSrc {
		return false
	}
	j := h.close[i+1]
	return j < len(h.ls) && j-i <= hlSpanMax && !reColGap.MatchString(h.ls[i].s[k:]) && h.gaps[j+1]-h.gaps[i+1] == 0
}

// proseWords counts the plain words of code that are not keywords.
func proseWords(code string) int {
	n := 0
	for _, w := range strings.Fields(code) {
		// an argument ("vq," "type))") is not a word of a sentence
		if len(w) > 1 && reWord.MatchString(w) && !srcKeywords[strings.TrimRight(w, ",.;:!?)")] &&
			!strings.HasSuffix(w, ",") && !strings.HasSuffix(w, ")") {
			n++
		}
	}
	return n
}

// Shell.

var shellKeywords = map[string]bool{"for": true, "do": true, "done": true, "while": true, "until": true, "if": true,
	"then": true, "else": true, "elif": true, "fi": true, "case": true, "esac": true, "in": true}

// shellLine tokenizes s[from:] as a shell command line; cmd tells whether
// it starts with a command (not the continuation of one). It reports
// whether the line ends in "\" (the command goes on).
func shellLine(sc *scanner, from int, cmd bool) int {
	s := sc.s
	k := from
	for k < len(s) {
		c := s[k]
		prev := byte(' ')
		if k > from {
			prev = s[k-1]
		}
		switch {
		case c == ' ' || c == '\t':
			k++
			continue
		case c == '#' && (prev == ' ' || prev == '\t'):
			sc.mark(k, len(s), HlComment)
			return 0
		case c == '\'' || c == '"':
			if !isWordByte(prev) {
				// a string with a command substitution inside may hold
				// quotes of its own ("0 $(blockdev --getsz "$DEV")"):
				// like a quote that goes on past the line, the rest of
				// the command is plain (strings never span lines)
				e := quoteEnd(s, k)
				if e == 0 || c == '"' && (strings.Contains(s[k:e], "$(") || strings.Contains(s[k:e], "`")) {
					return shellQuoted(s)
				}
				sc.mark(k, e, HlString)
				k = e
				cmd = false
				continue
			}
		case c == '|' || c == ';' || c == '&' || c == '(' || c == '`':
			cmd = c != '&' || k+1 < len(s) && s[k+1] == '&' || prev == '&'
			if c == '(' && prev != '$' {
				cmd = false
			}
			k++
			continue
		}
		// a word
		e := k
		for e < len(s) && !strings.ContainsRune(" \t|;&`'\"", rune(s[e])) {
			e++
		}
		if e == k {
			k++
			continue
		}
		w := s[k:e]
		if cmd && prev != '$' {
			switch {
			case shellKeywords[w]:
				sc.mark(k, e, HlKeyword)
				// "for x in", "if": what follows is not a command; "do",
				// "then", "else" are followed by one
				cmd = w == "do" || w == "then" || w == "else"
			case strings.Contains(w, "=") || strings.HasPrefix(w, "((") || strings.HasPrefix(w, "["):
				cmd = strings.Contains(w, "=") && !strings.HasPrefix(w, "((")
			case isIdentStart(w[0]) || w[0] == '.' || w[0] == '/' || w[0] == '~':
				sc.mark(k, e, HlFunc)
				cmd = w == "sudo" || w == "timeout" || w == "taskset" || w == "time" || w == "env"
			default:
				cmd = false
			}
		}
		k = e
	}
	if strings.HasSuffix(strings.TrimRight(s, " \t"), `\`) {
		return shCont
	}
	return 0
}

// shellLine results: the command goes on in the next line (shCont), as
// the rest of an open quote (shQuoted, plain).
const (
	shCont = 1 + iota
	shQuoted
)

func shellQuoted(s string) int {
	if strings.HasSuffix(strings.TrimRight(s, " \t"), `\`) {
		return shQuoted
	}
	return 0
}

// Diff and HTTP.

func diffLine(sc *scanner) {
	s := sc.s
	switch {
	case reHunk.MatchString(s):
		m := reHunk.FindStringIndex(s)
		sc.mark(0, m[1], HlMeta)
	case strings.HasPrefix(s, "+++ ") || strings.HasPrefix(s, "--- ") || strings.HasPrefix(s, "diff --git ") ||
		strings.HasPrefix(s, "index ") && strings.Contains(s, ".."):
		sc.mark(0, len(s), HlMeta)
	case strings.HasPrefix(s, "+"):
		sc.mark(0, len(s), HlAdd)
	case strings.HasPrefix(s, "-"):
		sc.mark(0, len(s), HlDel)
	}
}

var reHeader = regexp.MustCompile(`^[A-Za-z][\w-]*:`)

func (h *hiliter) httpLine(sc *scanner, i int) {
	s := sc.s
	l := &h.ls[i]
	h.head = h.head || l.http
	inHead := h.head
	j := len(s) - len(strings.TrimLeft(s, " \t"))
	t := s[j:]
	switch {
	case l.http && strings.HasPrefix(t, "HTTP/"):
		if sp := strings.IndexByte(t, ' '); sp > 0 {
			sc.mark(j+sp+1, j+sp+4, HlNumber)
		}
	case l.http && reHTTPRL.MatchString(t):
		sc.mark(j, j+strings.IndexByte(t, ' '), HlKeyword)
	case inHead && reHeader.MatchString(t):
		sc.mark(j, j+len(reHeader.FindString(t))-1, HlFunc)
	case !inHead:
		h.src(sc, i, 0)
	}
}

// hiliteKind names the kind of a block (for the corpus report).
func hiliteKind(text string) string {
	lines := strings.Split(text, "\n")
	if len(text) > hlMaxBytes || len(lines) > hlMaxLines {
		return "plain"
	}
	return kindNames[newHiliter(lines).kind]
}
