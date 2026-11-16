package webui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestHiliteCorpus is the data run behind the rules of hilite.go. It reads
// a dump of descriptions (NDAY_HILITE_CORPUS: JSON lines {"id": CVE id,
// "d": description}, e.g. from
//
//	psql -At -c "select json_build_object('id',cve_id,'d',description) from vuln where description is not null"
//
// ), runs FormatText and Hilite over every code block, checks that the
// tokens give the block back, and logs the number of blocks per kind and
// the tokens per class and kind. With NDAY_HILITE_SAMPLES set it writes up
// to 40 (NDAY_HILITE_N) random blocks per kind there, tokens shown as «class|text».
func TestHiliteCorpus(t *testing.T) {
	in := os.Getenv("NDAY_HILITE_CORPUS")
	if in == "" {
		t.Skip("NDAY_HILITE_CORPUS not set")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type block struct{ id, text string }
	byKind := map[string][]block{}
	toks := map[string]map[string]int{}
	lines := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<24)
	n := 0
	for sc.Scan() {
		var r struct{ ID, D string }
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		for _, b := range FormatText(r.D) {
			if !b.Code {
				continue
			}
			n++
			k := hiliteKind(b.Text)
			byKind[k] = append(byKind[k], block{r.ID, b.Text})
			if toks[k] == nil {
				toks[k] = map[string]int{}
			}
			ls := Hilite(b.Text)
			lines[k] += len(ls)
			if got := joinCodeLines(ls); got != b.Text {
				t.Fatalf("%s: not lossless", r.ID)
			}
			for _, l := range ls {
				for _, tk := range l.Toks {
					if tk.Class != "" {
						toks[k][tk.Class]++
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d code blocks", n)
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return len(byKind[kinds[i]]) > len(byKind[kinds[j]]) })
	classes := []string{HlComment, HlString, HlNumber, HlKeyword, HlFunc, HlError, HlMeta, HlAdd, HlDel}
	for _, k := range kinds {
		var parts []string
		for _, c := range classes {
			if v := toks[k][c]; v > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", c, v))
			}
		}
		t.Logf("%-6s %5d blocks %6d lines  tokens: %s", k, len(byKind[k]), lines[k], strings.Join(parts, " "))
	}
	out := os.Getenv("NDAY_HILITE_SAMPLES")
	if out == "" {
		return
	}
	var w strings.Builder
	rnd := rand.New(rand.NewSource(1))
	for _, k := range kinds {
		bs := byKind[k]
		rnd.Shuffle(len(bs), func(i, j int) { bs[i], bs[j] = bs[j], bs[i] })
		max := 40
		if v, err := strconv.Atoi(os.Getenv("NDAY_HILITE_N")); err == nil {
			max = v
		}
		for _, b := range bs[:min(max, len(bs))] {
			fmt.Fprintf(&w, "===== %s %s\n", k, b.id)
			for _, l := range Hilite(b.text) {
				for _, tk := range l.Toks {
					if tk.Class == "" {
						w.WriteString(tk.Text)
					} else {
						fmt.Fprintf(&w, "«%s|%s»", tk.Class, tk.Text)
					}
				}
				w.WriteByte('\n')
			}
		}
	}
	if err := os.WriteFile(out, []byte(w.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// joinCodeLines is the text that the lines render: their tokens, lines
// joined by "\n".
func joinCodeLines(ls []CodeLine) string {
	var b strings.Builder
	for i, l := range ls {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, t := range l.Toks {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}
