package site

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/titles"
)

// TitleInfo is the effective title of a vulnerability (docs/titles.md):
// the staff title, else the record's title, else the title composed by
// internal/titles; with its origin. Embedded in every row and detail type
// that carries a title, so the JSON API gains effective_title and
// title_origin next to the unchanged title (the record's title or null).
// Both are null when the vulnerability stays untitled.
type TitleInfo struct {
	// EffectiveTitle: what a page shows as the title, in English for a
	// composed one (null = untitled).
	EffectiveTitle *string `json:"effective_title"`
	// TitleOrigin: staff | record | composed (null = untitled).
	TitleOrigin *string `json:"title_origin"`
	// Composed: the parts of a composed title, for a rendering in the
	// visitor's language (pages only); nil unless the origin is composed.
	Composed *titles.Parts `json:"-"`
}

// Origin is TitleOrigin ("" = untitled).
func (t TitleInfo) Origin() string {
	if t.TitleOrigin == nil {
		return ""
	}
	return *t.TitleOrigin
}

// titleCols are the vuln_title columns titleScan reads, from the alias vt
// (titleJoin, joined on the row's vulnerability id).
const titleCols = `vt.staff_title, vt.form, vt.product, vt.weakness, vt.component, vt.excerpt, vt.composed_en`

// titleJoin* join vuln_title as vt on the row's id column (s, v or m).
const (
	titleJoinS = "\nLEFT JOIN vuln_title vt ON vt.cve_id = s.cve_id"
	titleJoinV = "\nLEFT JOIN vuln_title vt ON vt.cve_id = v.cve_id"
	titleJoinM = "\nLEFT JOIN vuln_title vt ON vt.cve_id = m.cve_id"
)

// titleScan receives titleCols.
type titleScan struct{ staff, form, product, weakness, component, excerpt, en *string }

func (t *titleScan) dest() []any {
	return []any{&t.staff, &t.form, &t.product, &t.weakness, &t.component, &t.excerpt, &t.en}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// info is the effective title given the record's title.
func (t titleScan) info(record *string) TitleInfo {
	origin := func(o string) *string { return &o }
	switch {
	case t.staff != nil && *t.staff != "":
		s := *t.staff
		return TitleInfo{EffectiveTitle: &s, TitleOrigin: origin(titles.OriginStaff)}
	case record != nil && strings.TrimSpace(*record) != "":
		s := *record
		return TitleInfo{EffectiveTitle: &s, TitleOrigin: origin(titles.OriginRecord)}
	case t.form != nil && t.en != nil && *t.en != "":
		s := *t.en
		p := &titles.Parts{Form: *t.form, Product: deref(t.product), Weakness: deref(t.weakness),
			Component: deref(t.component), Excerpt: deref(t.excerpt)}
		return TitleInfo{EffectiveTitle: &s, TitleOrigin: origin(titles.OriginComposed), Composed: p}
	}
	return TitleInfo{}
}

// TitleQueueRow is one vulnerability of the back office's title queue
// (/admin/titles; internal/admin): what a staff member needs to set a
// better title by hand.
type TitleQueueRow struct {
	CVEID string
	// Record: the record's own title (nil = none).
	Record *string
	TitleInfo
	// Staff: the staff title (nil = none); StaffVersion its version
	// (optimistic concurrency of the edits; 0 = never set).
	Staff        *string
	StaffVersion int
	// ComposedEN: the composed title in English, whatever the origin
	// (nil = none).
	ComposedEN *string
	// Description: its first 300 characters, one line.
	Description string
	Stage       *string
	Researchers int // distinct researchers posting in the last 7 days
	Posts       int // their posts in the last 7 days
}

// TitleQueuePage is the number of rows of one page of the title queue.
const TitleQueuePage = 10

// titleQueueSQL: the researchers' posts of the window [$1, $2] per
// vulnerability (the discussed ranking's aggregate plus the post count),
// joined with the title data. $3: every vulnerability (true) or those
// whose record has no title. %s: the row source condition and paging.
var titleQueueSQL = `
WITH a AS (
    SELECT p.cve_id, count(DISTINCT p.detail->>'author_id')::int AS researchers, count(*)::int AS posts,
           max(p.occurred_at) AS last_at
    FROM ` + researcherPostFrom + `
    WHERE ` + researcherPostWhere + ` AND p.occurred_at >= $1 AND p.occurred_at <= $2
    GROUP BY p.cve_id)
SELECT v.cve_id, v.title, left(COALESCE(v.description, ''), 600), s.stage, COALESCE(a.researchers, 0), COALESCE(a.posts, 0),
       COALESCE(vt.staff_version, 0), ` + titleCols + `, count(*) OVER ()
FROM %s
JOIN vuln v ON v.cve_id = a.cve_id
LEFT JOIN vuln_state_mat s ON s.cve_id = v.cve_id` + titleJoinV + `
WHERE ($3 OR NULLIF(btrim(v.title), '') IS NULL)%s`

// TitleQueue returns one page (1-based, clamped) of the vulnerabilities
// researchers discuss (posts in the last ResearcherWindow), most
// researchers first, then most posts, then the latest post, then id; all
// = false keeps those whose record has no title. total is the number of
// rows of the whole queue.
func (s *Store) TitleQueue(ctx context.Context, now time.Time, all bool, page int) (rows []TitleQueueRow, total, pageOut int, err error) {
	from, to := researcherWindow(now)
	sql := fmt.Sprintf(titleQueueSQL, "a", `
ORDER BY a.researchers DESC, a.posts DESC, a.last_at DESC, v.cve_id
LIMIT $4 OFFSET $5`)
	page = max(page, 1)
	rows, total, err = s.titleRows(ctx, sql, from, to, all, TitleQueuePage, (page-1)*TitleQueuePage)
	if err != nil || len(rows) > 0 || page == 1 {
		return rows, total, page, err
	}
	// past the end: the total (a window count, taken before LIMIT), then the last page
	if _, total, err = s.titleRows(ctx, sql, from, to, all, 1, 0); err != nil || total == 0 {
		return nil, total, 1, err
	}
	page = (total + TitleQueuePage - 1) / TitleQueuePage
	rows, total, err = s.titleRows(ctx, sql, from, to, all, TitleQueuePage, (page-1)*TitleQueuePage)
	return rows, total, page, err
}

// TitleEntry is the title data of one vulnerability (id canonical), with
// its researcher counts; nil when there is no such vulnerability.
func (s *Store) TitleEntry(ctx context.Context, now time.Time, id string) (*TitleQueueRow, error) {
	from, to := researcherWindow(now)
	sql := fmt.Sprintf(strings.Replace(titleQueueSQL, "JOIN vuln v ON v.cve_id = a.cve_id", "", 1),
		"vuln v LEFT JOIN a ON a.cve_id = v.cve_id", " AND v.cve_id = $4")
	rows, _, err := s.titleRows(ctx, sql, from, to, true, id)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

func (s *Store) titleRows(ctx context.Context, sql string, args ...any) (out []TitleQueueRow, total int, err error) {
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TitleQueueRow, error) {
			var x TitleQueueRow
			var ts titleScan
			err := r.Scan(append(append([]any{&x.CVEID, &x.Record, &x.Description, &x.Stage, &x.Researchers, &x.Posts,
				&x.StaffVersion}, ts.dest()...), &total)...)
			x.TitleInfo = ts.info(x.Record)
			x.Staff, x.ComposedEN = ts.staff, ts.en
			x.Description = cutDescription(x.Description, 300)
			return x, err
		})
		return err
	})
	return out, total, err
}

// cutDescription is s as one line of at most n runes (an ellipsis when cut).
func cutDescription(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}
