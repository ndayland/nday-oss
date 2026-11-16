package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestScriptsDeclareEachFunctionOnce: a second `function name(` in a static
// script silently replaces the first (declarations are hoisted and
// `node --check` accepts it). That broke every comment write once, when a
// renderer named post() shadowed the HTTP helper post(). The check is a
// heuristic, not a parser: the scripts are consistently indented, so the
// scope of a declaration is taken to be the nearest earlier code line with
// less indentation (the line that opens the enclosing block); two
// declarations of one name with the same such line are reported.
func TestScriptsDeclareEachFunctionOnce(t *testing.T) {
	files, err := filepath.Glob("static/*.js")
	if err != nil || len(files) == 0 {
		t.Fatalf("no static scripts found: %v", err)
	}
	decl := regexp.MustCompile(`^(\s*)(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		type open struct{ indent, line int }
		var stack []open // lines that may enclose the current one, by rising indentation
		for i, ln := range strings.Split(string(src), "\n") {
			code := strings.TrimLeft(ln, " \t")
			if code == "" || strings.HasPrefix(code, "//") || strings.HasPrefix(code, "*") || strings.HasPrefix(code, "/*") {
				continue
			}
			indent := len(ln) - len(code)
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}
			parent := 0
			if len(stack) > 0 {
				parent = stack[len(stack)-1].line
			}
			stack = append(stack, open{indent, i + 1})
			m := decl.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			key := strconv.Itoa(parent) + "|" + m[2]
			if first, dup := seen[key]; dup {
				t.Errorf("%s: function %s declared at line %d and again at line %d", f, m[2], first, i+1)
				continue
			}
			seen[key] = i + 1
		}
	}
}
