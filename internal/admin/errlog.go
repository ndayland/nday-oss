package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The error log reader of the system page: the newest WARN/ERROR records of
// the serve process's error-YYYY-MM-DD.log files (internal/web/logfiles.go,
// docs/logging.md: one slog JSON object per line). Read-only and bounded:
// at most TailBytes from the end of each file, lines longer than MaxLine
// are skipped, every field is shown as escaped text by the page.

// Bounds of the reader.
const (
	TailBytes  = 1 << 20  // read at most this much from the end of a file
	MaxLine    = 64 << 10 // longer lines are skipped (counted as unreadable)
	MaxRecords = 100
	maxText    = 2000 // runes of a record's attribute text
)

// LogRecord is one WARN/ERROR record.
type LogRecord struct {
	File  string // base name
	Time  string // as written (RFC 3339, local offset)
	Level string // WARN | ERROR
	Msg   string
	Attrs string // the other fields as key=value (JSON values), cut to maxText runes
}

// LogTail is what the system page shows of the error logs.
type LogTail struct {
	Configured bool     // NDAY_LOG_DIR is set
	Missing    bool     // ... but the directory cannot be read
	Files      []string // files read (base names)
	Records    []LogRecord
	Unreadable int  // lines that were not a JSON record (or too long)
	Cut        bool // a file was longer than TailBytes: older records were not read
}

// ReadErrorLogs reads the error logs of the given local dates (newest
// first) from dir and returns the newest max WARN/ERROR records, newest
// first. A missing file is skipped; dir must be absolute.
func ReadErrorLogs(dir string, days []time.Time, max int) LogTail {
	t := LogTail{Configured: dir != ""}
	if dir == "" {
		return t
	}
	if !filepath.IsAbs(dir) {
		t.Missing = true
		return t
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Missing = true
		return t
	}
	for _, d := range days {
		if len(t.Records) >= max {
			break
		}
		name := "error-" + d.Format("2006-01-02") + ".log" // fixed pattern: no input reaches the path
		recs, unreadable, cut, err := tailFile(filepath.Join(dir, name), max-len(t.Records))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		t.Files = append(t.Files, name)
		if err != nil {
			t.Unreadable++
			continue
		}
		for i := range recs {
			recs[i].File = name
		}
		t.Records = append(t.Records, recs...)
		t.Unreadable += unreadable
		t.Cut = t.Cut || cut
	}
	return t
}

// tailFile returns up to max WARN/ERROR records from the last TailBytes of
// a regular file, newest first.
func tailFile(path string, max int) (recs []LogRecord, unreadable int, cut bool, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, 0, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, false, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	size := st.Size()
	off := int64(0)
	if size > TailBytes {
		off, cut = size-TailBytes, true
	}
	buf := make([]byte, size-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, cut, err
	}
	buf = buf[:n]
	if off > 0 { // the first line is probably partial
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			buf = nil
		}
	}
	lines := bytes.Split(buf, []byte{'\n'})
	for i := len(lines) - 1; i >= 0 && len(recs) < max; i-- {
		line := bytes.TrimRight(lines[i], "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rec, ok := parseRecord(line)
		if !ok {
			unreadable++
			continue
		}
		if rec.Level == "WARN" || rec.Level == "ERROR" {
			recs = append(recs, rec)
		}
	}
	return recs, unreadable, cut, nil
}

func parseRecord(line []byte) (LogRecord, bool) {
	if len(line) > MaxLine || !utf8.Valid(line) {
		return LogRecord{}, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return LogRecord{}, false
	}
	str := func(k string) string {
		var s string
		if raw, ok := m[k]; ok && json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}
	r := LogRecord{Time: clipRunes(str("time"), 40), Level: strings.ToUpper(clipRunes(str("level"), 10)), Msg: clipRunes(str("msg"), 300)}
	if r.Level == "" {
		return LogRecord{}, false
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "time" && k != "level" && k != "msg" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		var c bytes.Buffer
		if json.Compact(&c, m[k]) == nil {
			b.Write(c.Bytes())
		}
		if b.Len() > 4*maxText {
			break
		}
	}
	r.Attrs = clipRunes(b.String(), maxText)
	return r, true
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
