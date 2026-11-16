package cvelist

import (
	"fmt"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/collector"
)

// pyTime is an AWARE Python datetime as produced by cvelist.parse_ts: wall
// clock fields plus the UTC offset (microseconds). Keeping the offset (rather
// than only the instant) is needed because Python's isoformat() renders it,
// e.g. for cursor.backfill_missing values read back from the cursor.
type pyTime struct {
	year, month, day, hour, minute, second, usec int
	offUS                                        int64 // utcoffset() in microseconds
}

// micro is the instant in microseconds since the Unix epoch (what Python
// compares when both datetimes are aware).
func (t pyTime) micro() int64 {
	wall := time.Date(t.year, time.Month(t.month), t.day, t.hour, t.minute, t.second, 0, time.UTC).UnixMicro()
	return wall + int64(t.usec) - t.offUS
}

// Time is the instant as a UTC time.Time.
func (t pyTime) Time() time.Time { return time.UnixMicro(t.micro()).UTC() }

// isoformat is Python's datetime.isoformat() for an aware datetime.
func (t pyTime) isoformat() string {
	s := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", t.year, t.month, t.day, t.hour, t.minute, t.second)
	if t.usec != 0 {
		s += fmt.Sprintf(".%06d", t.usec)
	}
	// _format_offset
	off, sign := t.offUS, "+"
	if off < 0 {
		sign, off = "-", -off
	}
	hh := off / 3_600_000_000
	off -= hh * 3_600_000_000
	mm := off / 60_000_000
	off -= mm * 60_000_000
	s += fmt.Sprintf("%s%02d:%02d", sign, hh, mm)
	if off != 0 {
		s += fmt.Sprintf(":%02d", off/1_000_000)
		if us := off % 1_000_000; us != 0 {
			s += fmt.Sprintf(".%06d", us)
		}
	}
	return s
}

// utcPyTime converts a Go time to Python's datetime.now(UTC) representation
// (microsecond precision, offset +00:00).
func utcPyTime(t time.Time) pyTime {
	t = t.UTC().Truncate(time.Microsecond)
	return pyTime{t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond() / 1000, 0}
}

// parseTS is cvelist.parse_ts: _text(value) -> datetime.fromisoformat ->
// UTC if naive. ok=false for absent / non-string / unparseable values.
func parseTS(v any) (pyTime, bool) {
	s := collector.Text(v)
	if s == nil {
		return pyTime{}, false
	}
	return fromISOFormat(*s)
}

// fromISOFormat ports CPython 3.13's C implementation of
// datetime.fromisoformat (Modules/_datetimemodule.c), operating on the UTF-8
// bytes like the C code does. Naive results get offset 0 (parse_ts's
// replace(tzinfo=UTC)). Verified against the real interpreter by
// TestFromISOFormatMatchesPython (testdata/fromisoformat_ref.json).
func fromISOFormat(s string) (pyTime, bool) {
	if utf8.RuneCountInString(s) < 7 { // _sanitize_isoformat_str
		return pyTime{}, false
	}
	n := len(s)
	at := func(i int) byte { // C reads the NUL terminator past the end
		if i >= 0 && i < n {
			return s[i]
		}
		return 0
	}
	sep := isoSeparator(s, at)
	if sep < 0 {
		return pyTime{}, false
	}
	var t pyTime
	if !isoDate(at, sep, &t) {
		return pyTime{}, false
	}
	hasTZ := false
	if n > sep {
		p := sep
		switch c := at(p); {
		case c&0x80 == 0:
			p++
		case c&0xf0 == 0xe0:
			p += 3
		case c&0xf0 == 0xf0:
			p += 4
		default:
			p += 2
		}
		var ok bool
		hasTZ, ok = isoTime(at, p, n, &t)
		if !ok {
			return pyTime{}, false
		}
	}
	_ = hasTZ
	// new_datetime: check_date_args / check_time_args
	if t.year < 1 || t.year > 9999 || t.month < 1 || t.month > 12 || t.day < 1 ||
		t.day > daysIn(t.year, t.month) {
		return pyTime{}, false
	}
	if t.hour < 0 || t.hour > 23 || t.minute < 0 || t.minute > 59 || t.second < 0 || t.second > 59 ||
		t.usec < 0 || t.usec > 999_999 {
		return pyTime{}, false
	}
	return t, true
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseDigits is the C parse_digits: exactly k ASCII digits at p.
func parseDigits(at func(int) byte, p, k int) (int, int, bool) {
	v := 0
	for i := 0; i < k; i++ {
		c := at(p + i)
		if !isDigit(c) {
			return 0, p, false
		}
		v = v*10 + int(c-'0')
	}
	return v, p + k, true
}

// isoSeparator is _find_isoformat_datetime_separator.
func isoSeparator(s string, at func(int) byte) int {
	n := len(s)
	if n == 7 {
		return 7
	}
	if at(4) == '-' {
		if at(5) == 'W' {
			if n < 8 {
				return -1
			}
			if n > 8 && at(8) == '-' {
				if n == 9 {
					return -1
				}
				if n > 10 && isDigit(at(10)) {
					return 8
				}
				return 10
			}
			return 8
		}
		return 10
	}
	if at(4) == 'W' {
		idx := 7
		for ; idx < n; idx++ {
			if !isDigit(at(idx)) {
				break
			}
		}
		if idx < 9 {
			return idx
		}
		if idx%2 == 0 {
			return 7
		}
		return 8
	}
	return 8
}

// isoDate is parse_isoformat_date (length = separator position).
func isoDate(at func(int) byte, length int, t *pyTime) bool {
	year, p, ok := parseDigits(at, 0, 4)
	if !ok {
		return false
	}
	usesSep := at(p) == '-'
	if usesSep {
		p++
	}
	if at(p) == 'W' {
		p++
		week, q, ok := parseDigits(at, p, 2)
		if !ok {
			return false
		}
		p = q
		day := 1
		if p < length {
			if usesSep {
				if at(p) != '-' {
					return false
				}
				p++
			}
			if day, _, ok = parseDigits(at, p, 1); !ok {
				return false
			}
		}
		y, m, d, ok := isoToYMD(year, week, day)
		if !ok {
			return false
		}
		t.year, t.month, t.day = y, m, d
		return true
	}
	month, p, ok := parseDigits(at, p, 2)
	if !ok {
		return false
	}
	if usesSep {
		if at(p) != '-' {
			return false
		}
		p++
	}
	day, _, ok := parseDigits(at, p, 2)
	if !ok {
		return false
	}
	t.year, t.month, t.day = year, month, day
	return true
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// isoToYMD is iso_to_ymd.
func isoToYMD(year, week, day int) (int, int, int, bool) {
	if year < 1 || year > 9999 {
		return 0, 0, 0, false
	}
	if week <= 0 || week >= 53 {
		ok := false
		if week == 53 {
			fw := int(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Weekday()) // ymd_to_ord % 7, 0 = Sunday
			ok = fw == 4 || (fw == 3 && isLeap(year))
		}
		if !ok {
			return 0, 0, 0, false
		}
	}
	if day <= 0 || day >= 8 {
		return 0, 0, 0, false
	}
	jan4 := time.Date(year, 1, 4, 0, 0, 0, 0, time.UTC)
	week1 := jan4.AddDate(0, 0, -((int(jan4.Weekday()) + 6) % 7))
	r := week1.AddDate(0, 0, (week-1)*7+day-1)
	return r.Year(), int(r.Month()), r.Day(), true
}

// hhmmssff is parse_hh_mm_ss_ff over [p, end). rv: 0 = consumed, 1 = more
// characters follow, <0 = error.
func hhmmssff(at func(int) byte, p, end int) (vals [4]int, rv int) {
	hasSep := true
	i := 0
	for ; i < 3; i++ {
		v, q, ok := parseDigits(at, p, 2)
		if !ok {
			return vals, -3
		}
		vals[i] = v
		p = q
		c := at(p)
		p++
		if i == 0 {
			hasSep = c == ':'
		}
		if p >= end {
			if c != 0 {
				return vals, 1
			}
			return vals, 0
		} else if hasSep && c == ':' {
			continue // CPython 3.13: also after SS, then parsed as a fraction
		} else if c == '.' || c == ',' {
			break // CPython 3.13 accepts a fraction after HH or MM too
		} else if !hasSep {
			p--
		} else {
			return vals, -4
		}
	}
	remains := end - p
	toParse := remains
	if remains >= 6 {
		toParse = 6
	}
	us, q, ok := parseDigits(at, p, toParse)
	if !ok {
		return vals, -3
	}
	p = q
	corr := [...]int{100000, 10000, 1000, 100, 10}
	if toParse < 6 {
		if toParse < 1 {
			return vals, -3
		}
		us *= corr[toParse-1]
	}
	vals[3] = us
	for isDigit(at(p)) {
		p++
	}
	if at(p) != 0 {
		return vals, 1
	}
	return vals, 0
}

// isoTime is parse_isoformat_time + tzinfo_from_isoformat_results.
func isoTime(at func(int) byte, p, end int, t *pyTime) (hasTZ, ok bool) {
	tz := p
	for {
		if c := at(tz); c == 'Z' || c == '+' || c == '-' {
			break
		}
		tz++
		if tz >= end {
			break
		}
	}
	vals, rv := hhmmssff(at, p, tz)
	if rv < 0 {
		return false, false
	}
	t.hour, t.minute, t.second, t.usec = vals[0], vals[1], vals[2], vals[3]
	if tz >= end {
		return false, rv != 1
	}
	if at(tz) == 'Z' {
		t.offUS = 0
		return true, at(tz+1) == 0
	}
	sign := int64(1)
	if at(tz) == '-' {
		sign = -1
	}
	tv, rv := hhmmssff(at, tz+1, end)
	if rv != 0 {
		return false, false
	}
	secs := sign * int64(tv[0]*3600+tv[1]*60+tv[2])
	if secs == 0 { // C: tzoffset == 0 -> timezone.utc (sub-second part ignored)
		t.offUS = 0
		return true, true
	}
	off := secs*1_000_000 + sign*int64(tv[3])
	if off <= -86_400_000_000 || off >= 86_400_000_000 {
		return false, false
	}
	t.offUS = off
	return true, true
}
