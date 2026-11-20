package researchsql

import (
	"testing"
	"time"
)

func TestWindowAndCeilDays(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want int
	}{{time.Hour, 1}, {24 * time.Hour, 1}, {36 * time.Hour, 2}, {72 * time.Hour, 3}, {73 * time.Hour, 4}, {168 * time.Hour, 7}, {0, 1}} {
		if got := CeilDays(c.d); got != c.want {
			t.Errorf("CeilDays(%v) = %d, want %d", c.d, got, c.want)
		}
	}
	for _, now := range []string{"2026-11-13T00:00:00Z", "2026-11-13T12:34:56Z", "2026-11-13T23:59:59.999Z"} {
		n, _ := time.Parse(time.RFC3339, now)
		if from, to := Window(n); !from.Equal(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)) || !to.Equal(n) {
			t.Errorf("Window(%s) = %v, %v", now, from, to)
		}
	}
}
