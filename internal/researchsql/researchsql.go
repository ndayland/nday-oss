// Package researchsql holds the SQL fragments that say what a "researcher
// post" is and which authors the public outline of a vulnerability page
// shows. internal/site (the outline, the counts) and internal/xavatar (which
// avatars are fetched and served) both use them, so the two can never
// disagree about who is public. It also holds the researcher window's
// bounds (Window), which internal/site and internal/ghrepo share. No
// imports beyond model: no cycles.
package researchsql

import (
	"strconv"
	"time"

	"nday.land/nday/internal/model"
)

// WindowDays is how many UTC days the public researcher window covers:
// today and the WindowDays-1 days before it.
const WindowDays = 7

// DayStart is 00:00 UTC of t's UTC day.
func DayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Window is the researcher window at now: from 00:00 UTC WindowDays-1 days
// before now's UTC day, up to now. Calendar days, so everything counted
// over it changes only at 00:00 UTC or when a post arrives.
func Window(now time.Time) (from, to time.Time) {
	return DayStart(now).AddDate(0, 0, -(WindowDays - 1)), now
}

// CeilDays is d rounded UP to whole days (at least 1): the pin rule's
// hour and day settings work on whole UTC days.
func CeilDays(d time.Duration) int {
	n := int((d + 24*time.Hour - 1) / (24 * time.Hour))
	if n < 1 {
		n = 1
	}
	return n
}

// Source is the collector of researcher posts.
const Source = "xposts"

// MaxOutline caps the researcher section of a vulnerability page (the
// signed-in list and the signed-out outline alike): the newest posts of a
// CVE, by occurred_at then id.
const MaxOutline = 50

// PostFrom is the FROM clause of every query over researcher posts (alias
// p): social_post events of the xposts collector whose author is an enabled
// allow-listed account (alias xa).
const PostFrom = "event p JOIN x_accounts xa ON xa.user_id = p.detail->>'author_id' AND xa.enabled"

// PostWhere restricts PostFrom to researcher posts.
const PostWhere = "p.type = '" + model.EventSocialPost + "' AND p.source = '" + Source + "'"

// ListedAuthor is the predicate "the X user whose id is in column userCol
// has a post in some vulnerability page's public outline at time now (a SQL
// expression, e.g. a $n parameter)": the outline query's own rules (PostFrom,
// PostWhere, occurred_at <= now, the MaxOutline newest posts of each CVE),
// looked at only for the CVEs that user posted about.
func ListedAuthor(userCol, now string) string {
	return `EXISTS (SELECT 1 FROM (
    SELECT p.detail->>'author_id' AS author,
           row_number() OVER (PARTITION BY p.cve_id ORDER BY p.occurred_at DESC, p.id DESC) AS k
    FROM ` + PostFrom + `
    WHERE ` + PostWhere + ` AND p.occurred_at <= ` + now + `
      AND p.cve_id IN (SELECT q.cve_id FROM event q
                       WHERE q.type = '` + model.EventSocialPost + `' AND q.source = '` + Source + `'
                         AND q.detail->>'author_id' = ` + userCol + `)
) o WHERE o.author = ` + userCol + ` AND o.k <= ` + strconv.Itoa(MaxOutline) + `)`
}
