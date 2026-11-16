package ghsa

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/collector"
)

// parseTS is ghsa.py's parse_ts:
//
//	s = _text(value); datetime.fromisoformat(s.replace("Z", "+00:00"));
//	naive -> UTC; ValueError -> None
//
// The result is the instant (in UTC). Python keeps the parsed fixed offset,
// but every use (comparison, iso_z) depends only on the instant.
func parseTS(v any) (time.Time, bool) {
	s := collector.Text(v)
	if s == nil {
		return time.Time{}, false
	}
	return fromISOFormat(strings.ReplaceAll(*s, "Z", "+00:00"))
}

// isoZ is ghsa.py's iso_z: dt.astimezone(UTC).replace(microsecond=0)
// .strftime("%Y-%m-%dT%H:%M:%SZ"). astimezone raises OverflowError when the
// UTC instant falls outside years 1..9999; that is an error here too.
func isoZ(t time.Time) (string, error) {
	u := t.UTC()
	if u.Year() < 1 || u.Year() > 9999 {
		return "", errors.New("OverflowError: date value out of range")
	}
	return u.Format("2006-01-02T15:04:05Z"), nil
}

// fromISOFormat is CPython 3.13's C datetime.fromisoformat
// (Modules/_datetimemodule.c: datetime_fromisoformat and helpers), ported on
// the UTF-8 bytes with the same NUL-terminated reads, because the C code works
// on PyUnicode_AsUTF8AndSize() output. Verified against the interpreter with
// testdata/fromisoformat.json (see pytime_test.go).
func fromISOFormat(s string) (time.Time, bool) {
	// _sanitize_isoformat_str: fewer than 7 code points is invalid; the first
	// non-ASCII character at code point 7, 8 or 10 (a possible separator)
	// becomes 'T' (determined empirically against CPython 3.13.14).
	if utf8.RuneCountInString(s) < 7 {
		return time.Time{}, false
	}
	s = sanitizeSeparator(s)
	n := len(s)
	b := make([]byte, n+16) // NUL sentinel (and slack for the C reads past the end)
	copy(b, s)
	sep := findSeparator(b, n)
	if sep < 0 {
		return time.Time{}, false
	}
	year, month, day, rv := parseISODate(b, sep)
	var hour, minute, second, usec, tzoff, tzusec int
	if rv == 0 && n > sep {
		rv = parseISOTime(b[sep+1:], n-sep-1, &hour, &minute, &second, &usec, &tzoff, &tzusec)
	}
	if rv < 0 {
		return time.Time{}, false
	}
	// tzinfo_from_isoformat_results: rv == 1 -> offset (0 seconds -> UTC,
	// even with a non-zero microsecond part); timezone() requires
	// |offset| < 24 h.
	var offsetUS int64
	if rv == 1 && tzoff != 0 {
		offsetUS = int64(tzoff)*1_000_000 + int64(tzusec)
		if offsetUS <= -86_400_000_000 || offsetUS >= 86_400_000_000 {
			return time.Time{}, false
		}
	}
	// new_datetime_ex2 range checks.
	if year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) ||
		hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 ||
		usec < 0 || usec > 999999 {
		return time.Time{}, false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, usec*1000, time.UTC)
	return t.Add(-time.Duration(offsetUS) * time.Microsecond), true
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

// parseDigits is the C parse_digits: exactly k ASCII digits at b[p:].
func parseDigits(b []byte, p int, v *int, k int) (int, bool) {
	for i := 0; i < k; i++ {
		if p >= len(b) || !isDigitByte(b[p]) {
			return p, false
		}
		*v = *v*10 + int(b[p]-'0')
		p++
	}
	return p, true
}

func at(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}

// findSeparator is _find_isoformat_datetime_separator (-1 = invalid).
func findSeparator(b []byte, n int) int {
	if n == 7 {
		return 7
	}
	if at(b, 4) == '-' {
		if at(b, 5) == 'W' {
			if n < 8 {
				return -1
			}
			if n > 8 && at(b, 8) == '-' {
				if n == 9 {
					return -1
				}
				if n > 10 && isDigitByte(at(b, 10)) {
					return 8
				}
				return 10
			}
			return 8
		}
		return 10
	}
	if at(b, 4) == 'W' {
		idx := 7
		for ; idx < n; idx++ {
			if !isDigitByte(at(b, idx)) {
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

// parseISODate is the C parse_isoformat_date (0 = ok, < 0 = error).
func parseISODate(b []byte, length int) (year, month, day, rv int) {
	p, ok := parseDigits(b, 0, &year, 4)
	if !ok {
		return 0, 0, 0, -1
	}
	usesSep := at(b, p) == '-'
	if usesSep {
		p++
	}
	if at(b, p) == 'W' {
		p++
		week, isoDay := 0, 0
		if p, ok = parseDigits(b, p, &week, 2); !ok {
			return 0, 0, 0, -3
		}
		if p < length {
			if usesSep {
				c := at(b, p)
				p++
				if c != '-' {
					return 0, 0, 0, -2
				}
			}
			if _, ok = parseDigits(b, p, &isoDay, 1); !ok {
				return 0, 0, 0, -4
			}
		} else {
			isoDay = 1
		}
		y, m, d, ok := isoToYMD(year, week, isoDay)
		if !ok {
			return 0, 0, 0, -5
		}
		return y, m, d, 0
	}
	if p, ok = parseDigits(b, p, &month, 2); !ok {
		return 0, 0, 0, -1
	}
	if usesSep {
		c := at(b, p)
		p++
		if c != '-' {
			return 0, 0, 0, -2
		}
	}
	if _, ok = parseDigits(b, p, &day, 2); !ok {
		return 0, 0, 0, -1
	}
	return year, month, day, 0
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// isoToYMD is the C iso_to_ymd.
func isoToYMD(isoYear, week, isoDay int) (int, int, int, bool) {
	if isoYear < 1 || isoYear > 9999 {
		return 0, 0, 0, false
	}
	if week <= 0 || week >= 53 {
		ok := false
		if week == 53 {
			// first_weekday = (ymd_to_ord(y, 1, 1) + 6) % 7, 0 = Monday
			fw := (int(time.Date(isoYear, 1, 1, 0, 0, 0, 0, time.UTC).Weekday()) + 6) % 7
			ok = fw == 3 || (fw == 2 && isLeap(isoYear))
		}
		if !ok {
			return 0, 0, 0, false
		}
	}
	if isoDay <= 0 || isoDay >= 8 {
		return 0, 0, 0, false
	}
	jan4 := time.Date(isoYear, 1, 4, 0, 0, 0, 0, time.UTC)
	week1 := jan4.AddDate(0, 0, -((int(jan4.Weekday()) + 6) % 7))
	t := week1.AddDate(0, 0, (week-1)*7+isoDay-1)
	return t.Year(), int(t.Month()), t.Day(), true
}

// parseHHMMSSFF is the C parse_hh_mm_ss_ff over b[0:end]; reads past end
// stop at the NUL sentinel exactly like the C code. Returns 0 (consumed to
// the end of the string), 1 (more characters follow) or < 0.
func parseHHMMSSFF(b []byte, end int, vals *[4]int) int {
	*vals = [4]int{}
	p := 0
	hasSep := true
	i := 0
	for ; i < 3; i++ {
		var ok bool
		if p, ok = parseDigits(b, p, &vals[i], 2); !ok {
			return -3
		}
		c := at(b, p)
		p++
		if i == 0 {
			hasSep = c == ':'
		}
		if p >= end {
			if c != 0 {
				return 1
			}
			return 0
		} else if hasSep && c == ':' {
			continue
		} else if c == '.' || c == ',' {
			break
		} else if !hasSep {
			p--
		} else {
			return -4
		}
	}
	remains := end - p
	toParse := remains
	if remains >= 6 {
		toParse = 6
	}
	var ok bool
	if p, ok = parseDigits(b, p, &vals[3], toParse); !ok {
		return -3
	}
	correction := [...]int{100000, 10000, 1000, 100, 10}
	if toParse < 6 {
		if toParse < 1 {
			// unreachable (see the C code: p < end here); keep it safe
			return -3
		}
		vals[3] *= correction[toParse-1]
	}
	for isDigitByte(at(b, p)) {
		p++
	}
	if at(b, p) != 0 {
		return 1
	}
	return 0
}

// parseISOTime is the C parse_isoformat_time (0 = no tz, 1 = tz, < 0 error).
func parseISOTime(b []byte, length int, hour, minute, second, usec, tzoff, tzusec *int) int {
	tz := 0
	for {
		c := at(b, tz)
		if c == 'Z' || c == '+' || c == '-' {
			break
		}
		tz++
		if tz >= length {
			break
		}
	}
	var v [4]int
	rv := parseHHMMSSFF(b, tz, &v)
	*hour, *minute, *second, *usec = v[0], v[1], v[2], v[3]
	if rv < 0 {
		return rv
	}
	if tz == length {
		if rv == 1 {
			return -5
		}
		return 0
	}
	if at(b, tz) == 'Z' {
		*tzoff, *tzusec = 0, 0
		if at(b, tz+1) != 0 {
			return -5
		}
		return 1
	}
	sign := 1
	if at(b, tz) == '-' {
		sign = -1
	}
	tz++
	var t [4]int
	rv = parseHHMMSSFF(b[tz:], length-tz, &t)
	*tzoff = sign * (t[0]*3600 + t[1]*60 + t[2])
	*tzusec = sign * t[3]
	if rv != 0 {
		return -5
	}
	return 1
}

// sanitizeSeparator replaces the first non-ASCII code point found at index 7,
// 8 or 10 (checked in that order; stop at the first index > length) with 'T'.
func sanitizeSeparator(s string) string {
	rs := []rune(s)
	for _, pos := range []int{7, 8, 10} {
		if pos > len(rs) {
			break
		}
		if pos < len(rs) && rs[pos] >= 0x80 {
			rs[pos] = 'T'
			return string(rs)
		}
	}
	return s
}
