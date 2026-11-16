package stats

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Line is the subset of an access line (web.AccessLine) the rollup uses.
type Line struct {
	Time        string  `json:"time"`
	ClientIP    string  `json:"client_ip"`
	Domain      string  `json:"domain"`
	Method      string  `json:"method"`
	URI         string  `json:"uri"`
	Status      int     `json:"status"`
	Referer     string  `json:"referer"`
	RequestTime float64 `json:"request_time"`
	BytesSent   int64   `json:"bytes_sent"`
	UserAgent   string  `json:"user_agent"`
	Country     string  `json:"country"`

	// Day is the calendar date of Time in the offset it carries.
	Day string `json:"-"`
}

var errBadTime = errors.New("missing or invalid time")

// ParseLine decodes one access line (without its newline). The line is
// malformed unless it is a JSON object whose "time" is RFC 3339.
func ParseLine(b []byte) (Line, error) {
	var l Line
	if err := json.Unmarshal(b, &l); err != nil {
		return Line{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, l.Time)
	if err != nil {
		return Line{}, errBadTime
	}
	l.Day = t.Format("2006-01-02") // in the parsed (line's own) offset
	return l, nil
}

// maxLine bounds one line; real lines are below ~5 KB (docs/logging.md
// truncates every long field). A longer line is counted as malformed.
const maxLine = 64 << 10

// scanResult is what scanLines reports about a file.
type scanResult struct {
	Lines   int64 // complete lines plus a final unterminated one
	Bad     int64 // malformed complete lines (incl. over-long and blank)
	Partial int64 // 1 if the final unterminated line is not valid (a write in progress)
}

// scanLines streams r line by line, calling fn for every well-formed line.
// "\r\n" endings are accepted. A final line without "\n" is used if it
// parses (the file simply ended there) and counted as Partial otherwise.
func scanLines(r io.Reader, fn func(Line)) (scanResult, error) {
	var res scanResult
	br := bufio.NewReaderSize(r, 256<<10)
	var long []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			if !tooLong {
				long = append(long, chunk...)
				if len(long) > maxLine {
					tooLong, long = true, nil
				}
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return res, err
		}
		line := chunk
		if long != nil {
			line = append(long, chunk...)
			long = nil
		}
		terminated := len(line) > 0 && line[len(line)-1] == '\n'
		if len(line) > 0 || tooLong {
			res.Lines++
			body := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
			switch l, perr := ParseLine(body); {
			case tooLong || len(body) > maxLine:
				res.Bad++
			case perr == nil:
				fn(l)
			case !terminated:
				res.Partial++
			default:
				res.Bad++
			}
			tooLong = false
		}
		if err != nil { // io.EOF
			return res, nil
		}
	}
}
