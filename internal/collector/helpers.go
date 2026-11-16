package collector

import (
	"time"

	"nday.land/nday/internal/pystr"
)

// Text is the `_text` helper every Python collector has: a JSON string,
// stripped with Python's str.strip(); nil for non-strings and empty results.
func Text(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	s = pystr.Strip(s)
	if s == "" {
		return nil
	}
	return &s
}

// ParseISODate is Python 3.11+'s date.fromisoformat (CPython C implementation):
// accepts exactly YYYY-MM-DD, YYYYMMDD, YYYY-Www, YYYYWww, YYYY-Www-D and
// YYYYWwwD with ASCII digits, year 1..9999, valid month/day, ISO week 1..52
// (53 when the year has one), weekday 1..7. Returns 00:00 UTC of that date.
func ParseISODate(s string) (time.Time, bool) {
	n := len(s)
	if n != 7 && n != 8 && n != 10 {
		return time.Time{}, false
	}
	p := 0
	digits := func(k int) (int, bool) {
		if p+k > n {
			return 0, false
		}
		v := 0
		for i := 0; i < k; i++ {
			c := s[p+i]
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		p += k
		return v, true
	}
	year, ok := digits(4)
	if !ok {
		return time.Time{}, false
	}
	sep := p < n && s[p] == '-'
	if sep {
		p++
	}
	if p < n && s[p] == 'W' {
		p++
		week, ok := digits(2)
		if !ok {
			return time.Time{}, false
		}
		day := 1
		if p < n {
			if sep {
				if s[p] != '-' {
					return time.Time{}, false
				}
				p++
			}
			if day, ok = digits(1); !ok {
				return time.Time{}, false
			}
		}
		if p != n {
			return time.Time{}, false
		}
		return isoWeekDate(year, week, day)
	}
	month, ok := digits(2)
	if !ok {
		return time.Time{}, false
	}
	if sep {
		if p >= n || s[p] != '-' {
			return time.Time{}, false
		}
		p++
	}
	day, ok := digits(2)
	if !ok || p != n {
		return time.Time{}, false
	}
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) {
		return time.Time{}, false
	}
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC), true
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// isoWeekDate mirrors CPython's _isoweek_to_gregorian.
func isoWeekDate(year, week, day int) (time.Time, bool) {
	if year < 1 || year > 9999 {
		return time.Time{}, false
	}
	if week <= 0 || week >= 53 {
		ok := false
		if week == 53 {
			// Python: first_weekday = _ymd2ord(year, 1, 1) % 7 (0 = Sunday)
			fw := int(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Weekday())
			ok = fw == 4 || (fw == 3 && isLeap(year))
		}
		if !ok {
			return time.Time{}, false
		}
	}
	if day <= 0 || day > 7 {
		return time.Time{}, false
	}
	// Monday of ISO week 1: the Monday on or before Jan 4.
	jan4 := time.Date(year, 1, 4, 0, 0, 0, 0, time.UTC)
	offset := (int(jan4.Weekday()) + 6) % 7 // days since Monday
	week1 := jan4.AddDate(0, 0, -offset)
	t := week1.AddDate(0, 0, (week-1)*7+(day-1))
	if t.Year() < 1 || t.Year() > 9999 {
		return time.Time{}, false
	}
	return t, true
}
