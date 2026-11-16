package stats

import (
	"strings"
	"testing"
)

func scanAll(t *testing.T, in string) (scanResult, []Line) {
	t.Helper()
	var got []Line
	res, err := scanLines(strings.NewReader(in), func(l Line) { got = append(got, l) })
	if err != nil {
		t.Fatal(err)
	}
	return res, got
}

func TestScanLines(t *testing.T) {
	ok := `{"time":"2026-11-13T10:00:00.000+08:00","uri":"/","status":200}`
	tests := []struct {
		name        string
		in          string
		lines, good int
		bad, part   int64
	}{
		{"empty", "", 0, 0, 0, 0},
		{"one", ok + "\n", 1, 1, 0, 0},
		{"crlf", ok + "\r\n" + ok + "\r\n", 2, 2, 0, 0},
		{"unterminated but complete", ok + "\n" + ok, 2, 2, 0, 0},
		{"partial last line", ok + "\n" + ok[:30], 2, 1, 0, 1},
		{"blank and garbage", "\n" + "garbage\n" + "[1]\n" + "null\n" + ok + "\n", 5, 1, 4, 0},
		{"bad time", `{"time":"2026-13-01T00:00:00Z"}` + "\n" + `{"time":""}` + "\n", 2, 0, 2, 0},
		{"wrong type", `{"time":"2026-11-13T10:00:00Z","status":"200"}` + "\n", 1, 0, 1, 0},
		{"over-long line", `{"time":"2026-11-13T10:00:00Z","uri":"` + strings.Repeat("a", maxLine+10) + `"}` + "\n" + ok + "\n", 2, 1, 1, 0},
		{"over-long unterminated", strings.Repeat("x", 3*maxLine), 1, 0, 1, 0},
	}
	for _, tc := range tests {
		res, got := scanAll(t, tc.in)
		if res.Lines != int64(tc.lines) || len(got) != tc.good || res.Bad != tc.bad || res.Partial != tc.part {
			t.Errorf("%s: lines=%d good=%d bad=%d partial=%d, want %d %d %d %d", tc.name,
				res.Lines, len(got), res.Bad, res.Partial, tc.lines, tc.good, tc.bad, tc.part)
		}
	}
}

func TestParseLineDayUsesOwnOffset(t *testing.T) {
	for in, want := range map[string]string{
		"2026-11-13T00:30:00.000+08:00": "2026-11-13",
		"2026-11-12T20:30:00.000-05:00": "2026-11-12", // = 2026-11-13 09:30 +08:00, but its own date is the 12th
		"2026-11-13T01:00:00Z":          "2026-11-13",
	} {
		l, err := ParseLine([]byte(`{"time":"` + in + `"}`))
		if err != nil || l.Day != want {
			t.Errorf("%s: day %q err %v, want %s", in, l.Day, err, want)
		}
	}
	l, err := ParseLine([]byte(`{"time":"2026-11-13T10:00:00Z","user_agent":"a\"b\r\nc","uri":"/x"}`))
	if err != nil || l.UserAgent != "a\"b\r\nc" {
		t.Errorf("escaped fields: %q %v", l.UserAgent, err)
	}
}
