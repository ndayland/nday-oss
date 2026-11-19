// Package md renders the small Markdown subset of nday discussions to HTML.
//
// It is pure (no I/O) and treats its input as untrusted. The output is built
// only from these elements:
//
//	<p> <br> <pre><code> <code> <blockquote> <ul> <ol> <li> <em> <strong> <a>
//
// and <a> only ever carries href (an absolute http:// or https:// URL that
// net/url parses, without user info, made of printable ASCII; or a path built
// by Options.CVELink and checked here) and the fixed rel="nofollow ugc
// noopener noreferrer", plus target="_blank" on an absolute URL when
// Options.NewTab says so. Everything else is escaped text.
//
// Syntax (see docs/discuss.md for the exact rules):
//
//   - paragraphs (blank-line separated); every line break inside a paragraph,
//     list item or quote is a hard break (<br>)
//   - fenced code blocks opened by ``` (3 or more backticks, up to 3 spaces of
//     indentation; the info string is accepted and ignored) and closed by a
//     backtick run at least as long; an unclosed fence runs to the end
//   - `inline code` (any backtick run length; a run without a matching run
//     of the same length is literal)
//   - > blockquotes, one level (a nested ">" is text); paragraphs inside
//   - "- " / "* " bullet lists and "1. " numbered lists, one level; an item
//     continues on following lines indented by at least two spaces (or a
//     tab); a nested list marker is text. <ol> always counts from 1
//   - *em* and **strong** (only "*"; "_" is plain text); runs of three or
//     more "*" are literal
//   - [text](url) links and bare http(s) URLs (autolinks); backslash escapes
//     of ASCII punctuation
//   - CVE ids (CVE-YYYY-NNNN…) link to Options.CVELink(id)
//
// Not supported (rendered as text): headings, images, tables, HTML, footnotes,
// thematic breaks, setext headings, indented code, nested lists or quotes,
// link titles, reference links, "_" emphasis, "~~~" fences.
//
// Robustness: Clean is applied first (invalid UTF-8 becomes U+FFFD; CR/CRLF
// become LF; C0/C1 controls other than tab and LF, DEL, U+FFFE/U+FFFF and the
// Unicode bidi embedding/override/isolate controls U+202A–U+202E and
// U+2066–U+2069 are removed), so the output never contains a control or an
// unterminated bidi embedding and can be placed in an element with
// dir="auto". Every step is a single left-to-right pass or uses
// precomputed tables (backtick-run pairing, URL stop positions, an emphasis
// stack with per-kind counts), so the running time is linear in the input
// length, and the output is at most MaxExpansion*len(src)+64 bytes.
package md

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rel is the fixed rel attribute of every link.
const Rel = "nofollow ugc noopener noreferrer"

// MaxExpansion bounds the output size: len(Render(src, o)) <=
// MaxExpansion*len(src) + 64 for every src (the worst cases are CVE links,
// whose generated path is at most MaxPathLen bytes, and autolinks, whose URL
// appears twice, escaped).
const MaxExpansion = 20

// newTab is the target attribute of an absolute link: Options.NewTab.
const newTab = ` target="_blank"`

func (o Options) target(href string) string {
	if o.NewTab != nil && o.NewTab(href) {
		return newTab
	}
	return ""
}

// MaxPathLen is the longest path accepted from Options.CVELink.
const MaxPathLen = 128

// MaxCVELinks is the number of vulnerability ids (CVE and GHSA ids
// together) linked per rendering; later ones are plain text.
const MaxCVELinks = 30

// MaxURLLen is the longest URL that becomes a link.
const MaxURLLen = 2048

// Options control rendering.
type Options struct {
	// Links: when false, [text](url) and bare URLs are rendered as plain
	// text (comments written by new accounts). CVE and GHSA ids are still
	// linked.
	Links bool
	// CVELink returns the site path of a vulnerability page for a canonical
	// CVE id ("CVE-2026-1234") or GHSA id ("GHSA-gpwc-27cw-rh9r"), e.g.
	// "/zh-hans/vuln/CVE-2026-1234". nil: ids are not linked. A result that
	// is not a plain absolute path (see SafePath) is ignored and the id is
	// rendered as text.
	CVELink func(id string) string
	// NewTab, when set, is asked about each absolute http(s) link; true adds
	// target="_blank" after rel (server-rendered pages). Nil: no target, as
	// in body_html.
	NewTab func(href string) bool
}

// MaxMarks is the number of consecutive combining marks (categories Mn
// and Me) kept after one base character; further ones are dropped (zalgo).
const MaxMarks = 4

// MaxBlankLines is the longest run of blank lines Clean keeps.
const MaxBlankLines = 2

// Clean makes untrusted text safe to process and display:
//
//   - invalid UTF-8 sequences become U+FFFD; CRLF and lone CR become LF;
//   - removed: C0 controls other than tab and LF, DEL, C1 controls, the
//     noncharacters U+FFFE/U+FFFF, the bidi embedding, override and isolate
//     controls (U+202A–U+202E, U+2066–U+2069), and characters that render
//     as nothing: U+200B, U+2060, U+FEFF, U+00AD, U+3164, U+FFA0, U+115F,
//     U+1160, U+180E and the tag characters U+E0000–U+E007F;
//   - more than MaxMarks consecutive combining marks are cut to MaxMarks;
//   - a line of only spaces, tabs, U+200C and U+200D becomes empty, and runs
//     of more than MaxBlankLines blank lines become MaxBlankLines.
//
// Implicit direction marks (U+200E, U+200F, U+061C) and ZWJ/ZWNJ inside
// text are kept: they have no scope, and several scripts and emoji need
// them. Clean is idempotent: Clean(Clean(s)) == Clean(s).
func Clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	marks := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			switch {
			case c == '\r':
				b.WriteByte('\n')
				marks = 0
				if i < len(s) && s[i] == '\n' {
					i++
				}
			case c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f):
				b.WriteByte(c)
				marks = 0
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n == 1:
			b.WriteRune(utf8.RuneError)
			marks = 0
		case dropRune(r):
		case unicode.In(r, unicode.Mn, unicode.Me):
			if marks < MaxMarks {
				b.WriteRune(r)
			}
			marks++
		default:
			b.WriteRune(r)
			marks = 0
		}
	}
	return blankLines(b.String())
}

// blankLines empties lines made only of spaces, tabs, ZWNJ and ZWJ and
// keeps at most MaxBlankLines consecutive blank lines.
func blankLines(s string) string {
	if !strings.Contains(s, "\n") && strings.Trim(s, " \t\u200c\u200d") != "" {
		return s
	}
	lines := strings.Split(s, "\n")
	out := lines[:0]
	blank := 0
	for _, l := range lines {
		if strings.Trim(l, " \t\u200c\u200d") == "" {
			blank++
			if blank > MaxBlankLines {
				continue
			}
			l = ""
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func dropRune(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0xfffe, r == 0xffff:
		return true
	case r == 0x200b, r == 0x2060, r == 0xfeff, r == 0x00ad, r == 0x3164, r == 0xffa0, r == 0x115f, r == 0x1160,
		r == 0x180e, r >= 0xe0000 && r <= 0xe007f:
		return true
	}
	return false
}

// Render renders src (untrusted) to HTML. See the package comment.
func Render(src string, opt Options) string {
	r := &renderer{opt: opt}
	r.out.Grow(len(src) + len(src)/4 + 16)
	r.blocks(strings.Split(Clean(src), "\n"))
	return r.out.String()
}

type renderer struct {
	opt  Options
	out  strings.Builder
	cves int // CVE links emitted so far (at most MaxCVELinks)
}

// ---- blocks ----

func isBlank(l string) bool { return strings.TrimLeft(l, " \t") == "" }

// indent returns the number of leading spaces (a tab counts as 4) and the rest.
func indent(l string) (int, string) {
	n, i := 0, 0
	for i < len(l) && (l[i] == ' ' || l[i] == '\t') {
		if l[i] == '\t' {
			n += 4
		} else {
			n++
		}
		i++
	}
	return n, l[i:]
}

// fenceOpen reports an opening fence: up to 3 spaces, >= 3 backticks, an
// info string without backticks. It returns the run length.
func fenceOpen(l string) int {
	n, rest := indent(l)
	if n > 3 {
		return 0
	}
	k := 0
	for k < len(rest) && rest[k] == '`' {
		k++
	}
	if k < 3 || strings.IndexByte(rest[k:], '`') >= 0 {
		return 0
	}
	return k
}

func fenceClose(l string, open int) bool {
	n, rest := indent(l)
	if n > 3 {
		return false
	}
	k := 0
	for k < len(rest) && rest[k] == '`' {
		k++
	}
	return k >= open && strings.TrimRight(rest[k:], " \t") == ""
}

// quoteLine returns the content of a "> " line.
func quoteLine(l string) (string, bool) {
	n, rest := indent(l)
	if n > 3 || !strings.HasPrefix(rest, ">") {
		return "", false
	}
	rest = rest[1:]
	if strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t") {
		rest = rest[1:]
	}
	return rest, true
}

// list kinds
const (
	notItem = iota
	bullet
	ordered
)

// listItem recognises "- x", "* x" and "1. x" (up to 3 spaces of indentation,
// 1–9 digits, a space or tab after the marker, non-blank content).
func listItem(l string) (kind int, num string, content string) {
	n, rest := indent(l)
	if n > 3 || rest == "" {
		return notItem, "", ""
	}
	var after string
	switch {
	case rest[0] == '-' || rest[0] == '*':
		kind, after = bullet, rest[1:]
	case rest[0] >= '0' && rest[0] <= '9':
		k := 0
		for k < len(rest) && k < 10 && rest[k] >= '0' && rest[k] <= '9' {
			k++
		}
		if k > 9 || k >= len(rest) || rest[k] != '.' {
			return notItem, "", ""
		}
		kind, num, after = ordered, rest[:k], rest[k+1:]
	default:
		return notItem, "", ""
	}
	if after == "" || (after[0] != ' ' && after[0] != '\t') || isBlank(after) {
		return notItem, "", ""
	}
	return kind, num, strings.TrimLeft(after, " \t")
}

// startsBlock reports whether l interrupts a paragraph. A numbered item
// interrupts only when it starts at 1 (so "2024. was a year" stays text).
func startsBlock(l string) bool {
	if fenceOpen(l) > 0 {
		return true
	}
	if _, ok := quoteLine(l); ok {
		return true
	}
	kind, num, _ := listItem(l)
	return kind == bullet || (kind == ordered && num == "1")
}

func (r *renderer) blocks(lines []string) {
	for i := 0; i < len(lines); {
		l := lines[i]
		if isBlank(l) {
			i++
			continue
		}
		if k := fenceOpen(l); k > 0 {
			ind, _ := indent(l)
			j := i + 1
			for j < len(lines) && !fenceClose(lines[j], k) {
				j++
			}
			r.out.WriteString("<pre><code>")
			for _, c := range lines[i+1 : j] {
				// drop up to the opening fence's indentation
				for d := 0; d < ind && strings.HasPrefix(c, " "); d++ {
					c = c[1:]
				}
				r.text(c)
				r.out.WriteByte('\n')
			}
			r.out.WriteString("</code></pre>\n")
			i = j + 1
			continue
		}
		if _, ok := quoteLine(l); ok {
			var inner []string
			for i < len(lines) {
				c, ok := quoteLine(lines[i])
				if !ok {
					break
				}
				inner = append(inner, c)
				i++
			}
			r.quote(inner)
			continue
		}
		if kind, _, _ := listItem(l); kind != notItem {
			i = r.list(lines, i, kind)
			continue
		}
		j := i + 1
		for j < len(lines) && !isBlank(lines[j]) && !startsBlock(lines[j]) {
			j++
		}
		r.para(lines[i:j])
		i = j
	}
}

// para writes <p> with the lines joined by hard breaks.
func (r *renderer) para(lines []string) {
	r.out.WriteString("<p>")
	r.inline(joinLines(lines), true)
	r.out.WriteString("</p>\n")
}

func joinLines(lines []string) string {
	var b strings.Builder
	for k, l := range lines {
		if k > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Trim(l, " \t"))
	}
	return b.String()
}

// quote writes one blockquote whose content is paragraphs only.
func (r *renderer) quote(inner []string) {
	var paras [][]string
	var cur []string
	for _, l := range inner {
		if isBlank(l) {
			if cur != nil {
				paras, cur = append(paras, cur), nil
			}
			continue
		}
		cur = append(cur, l)
	}
	if cur != nil {
		paras = append(paras, cur)
	}
	if len(paras) == 0 {
		return
	}
	r.out.WriteString("<blockquote>\n")
	for _, p := range paras {
		r.para(p)
	}
	r.out.WriteString("</blockquote>\n")
}

// list writes the list starting at lines[i] and returns the next line index.
func (r *renderer) list(lines []string, i, kind int) int {
	tag := "ul"
	if kind == ordered {
		tag = "ol"
	}
	r.out.WriteString("<" + tag + ">\n")
	for i < len(lines) {
		k, _, first := listItem(lines[i])
		if k != kind {
			break
		}
		item := []string{first}
		i++
		for i < len(lines) && !isBlank(lines[i]) {
			if n, _ := indent(lines[i]); n < 2 {
				break
			}
			item = append(item, lines[i])
			i++
		}
		r.out.WriteString("<li>")
		r.inline(joinLines(item), true)
		r.out.WriteString("</li>\n")
	}
	r.out.WriteString("</" + tag + ">\n")
	return i
}

// ---- inline ----

func (r *renderer) text(s string) { escapeTo(&r.out, s) }

func escapeTo(b *strings.Builder, s string) {
	last := 0
	for i := 0; i < len(s); i++ {
		var rep string
		switch s[i] {
		case '&':
			rep = "&amp;"
		case '<':
			rep = "&lt;"
		case '>':
			rep = "&gt;"
		case '"':
			rep = "&#34;"
		case '\'':
			rep = "&#39;"
		default:
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(rep)
		last = i + 1
	}
	b.WriteString(s[last:])
}

// piece is a chunk of inline output; delimiter pieces ("*" or "**") become
// tags when matched.
type piece struct {
	html  string
	kind  int  // 0 = plain html; 1 = em delimiter; 2 = strong delimiter
	open  bool // matched opener
	close bool // matched closer
}

// inline renders one paragraph's inline content. links=false inside link
// text (no nested <a>: no links, autolinks or CVE links there).
func (r *renderer) inline(s string, links bool) {
	pieces := inlinePieces(s, r.opt, links, &r.cves)
	for _, p := range pieces {
		switch {
		case p.kind == 0:
			r.out.WriteString(p.html)
		case p.open && p.kind == 1:
			r.out.WriteString("<em>")
		case p.close && p.kind == 1:
			r.out.WriteString("</em>")
		case p.open:
			r.out.WriteString("<strong>")
		case p.close:
			r.out.WriteString("</strong>")
		default:
			r.out.WriteString(strings.Repeat("*", p.kind))
		}
	}
}

type inl struct {
	s      string
	opt    Options
	links  bool // links/autolinks/CVE links allowed in this context
	pieces []piece
	buf    strings.Builder // pending plain html
	// code spans: backtick runs and, for each, the index of the next run of
	// the same length (-1 if none)
	runStart, runLen, runNext []int
	runAt                     map[int]int // start offset -> run index
	// stop[p]: first index >= p holding a space, tab, LF or ')' (len(s) if none)
	stop []int
	// emphasis stack (piece indices) with per-kind counts
	stack []int
	count [3]int
	cves  *int // shared CVE link counter of the rendering
	brs   int  // consecutive <br> just emitted
}

func inlinePieces(s string, opt Options, links bool, cves *int) []piece {
	p := &inl{s: s, opt: opt, links: links, cves: cves}
	p.scanRuns()
	p.run()
	p.flush()
	// unmatched openers stay literal (their pieces print "*"/"**")
	return p.pieces
}

func (p *inl) scanRuns() {
	s := p.s
	p.runAt = map[int]int{}
	for i := 0; i < len(s); {
		if s[i] != '`' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] == '`' {
			j++
		}
		p.runAt[i] = len(p.runStart)
		p.runStart = append(p.runStart, i)
		p.runLen = append(p.runLen, j-i)
		i = j
	}
	p.runNext = make([]int, len(p.runStart))
	last := map[int]int{}
	for k := len(p.runStart) - 1; k >= 0; k-- {
		if n, ok := last[p.runLen[k]]; ok {
			p.runNext[k] = n
		} else {
			p.runNext[k] = -1
		}
		last[p.runLen[k]] = k
	}
	if p.links && p.opt.Links {
		p.stop = make([]int, len(s)+1)
		p.stop[len(s)] = len(s)
		for i := len(s) - 1; i >= 0; i-- {
			switch s[i] {
			case ' ', '\t', '\n', ')':
				p.stop[i] = i
			default:
				p.stop[i] = p.stop[i+1]
			}
		}
	}
}

func (p *inl) flush() {
	if p.buf.Len() > 0 {
		p.pieces = append(p.pieces, piece{html: p.buf.String()})
		p.buf.Reset()
	}
}

func (p *inl) lit(s string) { escapeTo(&p.buf, s) }

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isASCIIPunct(c byte) bool {
	return c >= '!' && c <= '/' || c >= ':' && c <= '@' || c >= '[' && c <= '`' || c >= '{' && c <= '~'
}

func (p *inl) run() {
	s := p.s
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\n' {
			p.brs = 0
		}
		switch {
		case c == '\\' && i+1 < len(s) && isASCIIPunct(s[i+1]):
			p.lit(s[i+1 : i+2])
			i += 2
		case c == '\n':
			// never more than two consecutive breaks (Clean keeps lines
			// non-blank inside a paragraph; this is a second guard)
			if p.brs < 2 {
				p.buf.WriteString("<br>\n")
			}
			p.brs++
			i++
		case c == '`':
			k, ok := p.runAt[i]
			if !ok {
				// the rest of a run whose first backtick was escaped ("\``"):
				// literal
				j := i
				for j < len(s) && s[j] == '`' {
					j++
				}
				p.lit(s[i:j])
				i = j
				continue
			}
			n := p.runLen[k]
			if m := p.runNext[k]; m >= 0 {
				p.code(s[i+n : p.runStart[m]])
				i = p.runStart[m] + n
			} else {
				p.lit(s[i : i+n])
				i += n
			}
		case c == '*':
			j := i
			for j < len(s) && s[j] == '*' {
				j++
			}
			p.emph(i, j)
			i = j
		case c == '[' && p.links && p.opt.Links:
			if j, ok := p.link(i); ok {
				i = j
			} else {
				p.lit("[")
				i++
			}
		case (c == 'h' || c == 'H') && p.links && boundaryBefore(s, i, urlGlue):
			if j, ok := p.autolink(i); ok {
				i = j
			} else {
				p.lit(s[i : i+1])
				i++
			}
		case (c == 'c' || c == 'C') && p.links && boundaryBefore(s, i, cveGlue):
			if j, ok := p.cve(i); ok {
				i = j
			} else {
				p.lit(s[i : i+1])
				i++
			}
		case (c == 'g' || c == 'G') && p.links && boundaryBefore(s, i, cveGlue):
			if j, ok := p.ghsa(i); ok {
				i = j
			} else {
				p.lit(s[i : i+1])
				i++
			}
		default:
			// copy a run of ordinary bytes at once
			j := i + 1
			for j < len(s) && !special(s[j]) {
				j++
			}
			p.lit(s[i:j])
			i = j
		}
	}
}

func special(c byte) bool {
	switch c {
	case '\\', '\n', '`', '*', '[', 'h', 'H', 'c', 'C', 'g', 'G':
		return true
	}
	return false
}

const (
	urlGlue = "/:._-@%=&?#~+"
	cveGlue = "-_/.@#:%=&?~+"
)

// boundaryBefore: position i starts a word (start of text, or the previous
// byte is not an ASCII letter/digit nor one of glue).
func boundaryBefore(s string, i int, glue string) bool {
	if i == 0 {
		return true
	}
	c := s[i-1]
	return !isASCIIAlnum(c) && strings.IndexByte(glue, c) < 0
}

func (p *inl) code(content string) {
	content = strings.ReplaceAll(content, "\n", " ")
	if len(content) >= 2 && content[0] == ' ' && content[len(content)-1] == ' ' && strings.Trim(content, " ") != "" {
		content = content[1 : len(content)-1]
	}
	p.buf.WriteString("<code>")
	p.lit(content)
	p.buf.WriteString("</code>")
}

// emph handles the "*" run s[i:j].
func (p *inl) emph(i, j int) {
	s := p.s
	n := j - i
	if n > 2 {
		p.lit(s[i:j])
		return
	}
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[j:])
	canClose := i > 0 && !unicode.IsSpace(prev)
	canOpen := j < len(s) && !unicode.IsSpace(next)
	p.flush()
	idx := len(p.pieces)
	p.pieces = append(p.pieces, piece{kind: n})
	switch {
	case canClose && p.count[n] > 0:
		// pop to the nearest opener of this kind; openers above it can no
		// longer be matched (strict nesting) and stay literal
		for {
			top := p.stack[len(p.stack)-1]
			p.stack = p.stack[:len(p.stack)-1]
			k := p.pieces[top].kind
			p.count[k]--
			if k == n {
				p.pieces[top].open = true
				p.pieces[idx].close = true
				return
			}
		}
	case canOpen:
		p.stack = append(p.stack, idx)
		p.count[n]++
	}
}

// link tries "[text](url)" at s[i] == '['.
func (p *inl) link(i int) (int, bool) {
	s := p.s
	k := i + 1
	for k < len(s) && s[k] != '[' && s[k] != ']' && s[k] != '\n' {
		k++
	}
	if k+1 >= len(s) || s[k] != ']' || s[k+1] != '(' {
		return 0, false
	}
	u0 := k + 2
	end := p.stop[u0]
	if end >= len(s) || s[end] != ')' || end-u0 > MaxURLLen {
		return 0, false
	}
	href, ok := SafeURL(s[u0:end])
	if !ok {
		return 0, false
	}
	text := strings.TrimSpace(s[i+1 : k])
	p.flush()
	var b strings.Builder
	b.WriteString(`<a href="`)
	escapeTo(&b, href)
	b.WriteString(`" rel="` + Rel + `"` + p.opt.target(href) + `>`)
	if text == "" {
		escapeTo(&b, s[u0:end])
	} else {
		for _, q := range inlinePieces(text, p.opt, false, p.cves) {
			b.WriteString(pieceHTML(q))
		}
	}
	b.WriteString("</a>")
	p.pieces = append(p.pieces, piece{html: b.String()})
	return end + 1, true
}

func pieceHTML(q piece) string {
	switch {
	case q.kind == 0:
		return q.html
	case q.open && q.kind == 1:
		return "<em>"
	case q.close && q.kind == 1:
		return "</em>"
	case q.open:
		return "<strong>"
	case q.close:
		return "</strong>"
	}
	return strings.Repeat("*", q.kind)
}

// hasPrefixFold: ASCII case-insensitive prefix test (prefix is lower-case
// ASCII; no Unicode folding, so "ſ" or "K" never match "s" or "k").
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// urlByte: bytes an autolink may contain (printable ASCII except " < > \ `).
func urlByte(c byte) bool {
	return c > 0x20 && c < 0x7f && c != '"' && c != '<' && c != '>' && c != '\\' && c != '`'
}

// autolink tries a bare http(s) URL at s[i]. With links off it is consumed as
// plain text (so nothing inside it is parsed).
func (p *inl) autolink(i int) (int, bool) {
	s := p.s
	if !hasPrefixFold(s[i:], "http://") && !hasPrefixFold(s[i:], "https://") {
		return 0, false
	}
	j := i
	for j < len(s) && urlByte(s[j]) {
		j++
	}
	// trailing punctuation and unbalanced ")" are not part of the URL
	opens, closes := strings.Count(s[i:j], "("), strings.Count(s[i:j], ")")
	for j > i {
		c := s[j-1]
		if strings.IndexByte(".,:;!?'*", c) >= 0 {
			j--
			continue
		}
		if c == ')' && closes > opens {
			j--
			closes--
			continue
		}
		break
	}
	raw := s[i:j]
	if !p.opt.Links {
		p.lit(raw)
		return j, true
	}
	href, ok := SafeURL(raw)
	if !ok {
		p.lit(raw)
		return j, true
	}
	p.flush()
	var b strings.Builder
	b.WriteString(`<a href="`)
	escapeTo(&b, href)
	b.WriteString(`" rel="` + Rel + `"` + p.opt.target(href) + `>`)
	escapeTo(&b, raw)
	b.WriteString("</a>")
	p.pieces = append(p.pieces, piece{html: b.String()})
	return j, true
}

// cve tries a CVE id at s[i].
func (p *inl) cve(i int) (int, bool) {
	s := p.s
	if p.opt.CVELink == nil || !hasPrefixFold(s[i:], "cve-") {
		return 0, false
	}
	j := i + 4
	k := j
	for k < len(s) && k-j < 4 && s[k] >= '0' && s[k] <= '9' {
		k++
	}
	if k-j != 4 || k >= len(s) || s[k] != '-' {
		return 0, false
	}
	j = k + 1
	k = j
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		k++
		if k-j > 19 {
			return 0, false
		}
	}
	if k-j < 4 || (k < len(s) && (isASCIIAlnum(s[k]) || s[k] == '_')) {
		return 0, false
	}
	return p.idLink(i, k, "CVE-"+s[i+4:k])
}

// ghsaAlphabet is the alphabet of the groups of a GHSA id.
const ghsaAlphabet = "23456789cfghjmpqrvwx"

// ghsa tries a GHSA id ("GHSA-gpwc-27cw-rh9r", any case) at s[i].
func (p *inl) ghsa(i int) (int, bool) {
	s := p.s
	if p.opt.CVELink == nil || !hasPrefixFold(s[i:], "ghsa") {
		return 0, false
	}
	k := i + 4
	for g := 0; g < 3; g++ {
		if k+5 > len(s) || s[k] != '-' {
			return 0, false
		}
		for _, c := range []byte(s[k+1 : k+5]) {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if strings.IndexByte(ghsaAlphabet, c) < 0 {
				return 0, false
			}
		}
		k += 5
	}
	if k < len(s) && (isASCIIAlnum(s[k]) || s[k] == '_') {
		return 0, false
	}
	return p.idLink(i, k, "GHSA"+strings.ToLower(s[i+4:k]))
}

// idLink links the vulnerability id s[i:k] (canonical form id) to its page,
// within MaxCVELinks; ok=false leaves it to be rendered as text.
func (p *inl) idLink(i, k int, id string) (int, bool) {
	s := p.s
	if *p.cves >= MaxCVELinks {
		return 0, false
	}
	path := p.opt.CVELink(id)
	if !SafePath(path) {
		return 0, false
	}
	p.flush()
	var b strings.Builder
	b.WriteString(`<a href="`)
	b.WriteString(path) // SafePath: nothing to escape
	b.WriteString(`" rel="` + Rel + `">`)
	escapeTo(&b, s[i:k])
	b.WriteString("</a>")
	*p.cves++
	p.pieces = append(p.pieces, piece{html: b.String()})
	return k, true
}

// SafePath reports whether a generated link is a plain absolute site path:
// "/" followed by [A-Za-z0-9._~/-], not "//", at most MaxPathLen bytes, no
// "." or ".." segment.
func SafePath(path string) bool {
	if len(path) < 2 || len(path) > MaxPathLen || path[0] != '/' || path[1] == '/' {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if !isASCIIAlnum(c) && strings.IndexByte("._~/-", c) < 0 {
			return false
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// SafeURL validates an absolute http(s) URL for use as href: at most
// MaxURLLen bytes of printable ASCII without " < > \ ` or spaces, scheme
// http or https, parsed by net/url with a host and no user info. It returns
// the URL with the scheme in lower case.
func SafeURL(raw string) (string, bool) {
	if len(raw) > MaxURLLen {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if !urlByte(raw[i]) {
			return "", false
		}
	}
	var n int
	switch {
	case hasPrefixFold(raw, "http://"):
		n = len("http")
	case hasPrefixFold(raw, "https://"):
		n = len("https")
	default:
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Hostname() == "" {
		return "", false
	}
	return strings.ToLower(raw[:n]) + raw[n:], true
}
