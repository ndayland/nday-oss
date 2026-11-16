package admin_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/admin"
)

func day(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

func rec(level, msg string, i int) string {
	return fmt.Sprintf(`{"time":"2026-11-13T10:%02d:00.000+08:00","level":%q,"msg":%q,"path":"/x","n":%d}`, i%60, level, msg, i) + "\n"
}

// TestErrorLogReader: newest first, WARN/ERROR only, today before
// yesterday, garbled and oversized lines counted and skipped, and the
// read is bounded however big the file is.
func TestErrorLogReader(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var y strings.Builder
	for i := 0; i < 5; i++ {
		y.WriteString(rec("ERROR", fmt.Sprintf("yesterday %d", i), i))
	}
	write("error-2026-11-12.log", y.String())
	write("error-2026-11-13.log", rec("INFO", "skip me", 1)+rec("WARN", "w1", 2)+"not json\n"+"\xff\xfe\x00binary\n"+
		`{"level":"ERROR"`+"\n"+`{"time":1,"level":"ERROR","msg":"odd types"}`+"\n"+"{\"level\":\"ERROR\",\"msg\":\""+strings.Repeat("x", admin.MaxLine)+"\"}\n"+
		rec("ERROR", "e1", 3)+"\r\n"+rec("WARN", "last line without newline", 4)[:len(rec("WARN", "last line without newline", 4))-1])
	got := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-13"), day("2026-11-12")}, 100)
	var msgs []string
	for _, r := range got.Records {
		msgs = append(msgs, r.Level+":"+r.Msg)
	}
	want := "WARN:last line without newline ERROR:e1 ERROR:odd types WARN:w1 ERROR:yesterday 4 ERROR:yesterday 3 ERROR:yesterday 2 ERROR:yesterday 1 ERROR:yesterday 0"
	if strings.Join(msgs, " ") != want {
		t.Errorf("records:\n%s\nwant\n%s", strings.Join(msgs, " "), want)
	}
	if got.Unreadable != 4 || got.Cut || got.Missing || len(got.Files) != 2 {
		t.Errorf("tail: unreadable %d cut %v missing %v files %v", got.Unreadable, got.Cut, got.Missing, got.Files)
	}
	if r := got.Records[1]; r.File != "error-2026-11-13.log" || r.Time != "2026-11-13T10:03:00.000+08:00" || r.Attrs != `n=3 path="/x"` {
		t.Errorf("record fields: %+v", r)
	}
	// max is honoured across files
	if got := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-13"), day("2026-11-12")}, 3); len(got.Records) != 3 {
		t.Errorf("max 3: %d", len(got.Records))
	}

	// a huge file: only the tail is read, and quickly
	var big bytes.Buffer
	for i := 0; big.Len() < 3*admin.TailBytes; i++ {
		big.WriteString(rec("ERROR", fmt.Sprintf("big %d %s", i, strings.Repeat("y", 200)), i))
	}
	write("error-2026-11-14.log", big.String())
	start := time.Now()
	g := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-14")}, 100)
	if len(g.Records) != 100 || !g.Cut || g.Unreadable != 0 || time.Since(start) > 2*time.Second {
		t.Errorf("big file: %d records, cut %v, unreadable %d, %s", len(g.Records), g.Cut, g.Unreadable, time.Since(start))
	}
	var first, last int
	fmt.Sscanf(g.Records[0].Msg, "big %d", &first)
	fmt.Sscanf(g.Records[99].Msg, "big %d", &last)
	if first != last+99 || first < 10000 {
		t.Errorf("big file not the newest records, newest first: %d ... %d", first, last)
	}
	// one giant line without newlines: nothing but an unreadable count
	write("error-2026-11-15.log", strings.Repeat("z", 2*admin.TailBytes))
	if g := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-15")}, 100); len(g.Records) != 0 || !g.Cut {
		t.Errorf("giant line: %+v", g)
	}

	// symlinks and other non-regular files are not followed
	if err := os.Symlink("/etc/hosts", filepath.Join(dir, "error-2026-11-16.log")); err == nil {
		if g := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-16")}, 100); len(g.Records) != 0 || g.Unreadable != 1 {
			t.Errorf("symlink: %+v", g)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "error-2026-11-17.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	if g := admin.ReadErrorLogs(dir, []time.Time{day("2026-11-17")}, 100); len(g.Records) != 0 || g.Unreadable != 1 {
		t.Errorf("directory: %+v", g)
	}
	// missing files, missing or relative directories, not configured
	if g := admin.ReadErrorLogs(dir, []time.Time{day("2020-01-01")}, 100); len(g.Files) != 0 || g.Missing || !g.Configured {
		t.Errorf("no file: %+v", g)
	}
	if g := admin.ReadErrorLogs(filepath.Join(dir, "nope"), nil, 100); !g.Missing {
		t.Errorf("missing dir: %+v", g)
	}
	if g := admin.ReadErrorLogs("relative/dir", nil, 100); !g.Missing {
		t.Errorf("relative dir: %+v", g)
	}
	if g := admin.ReadErrorLogs("", nil, 100); g.Configured {
		t.Errorf("unset: %+v", g)
	}
}
