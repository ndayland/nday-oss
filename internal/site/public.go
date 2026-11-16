package site

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlinks"
)

// Non-public data: the single place that says which collected data the
// public (unauthenticated) site and API may show and which they must never
// show. Every Store query that reads event, raw_record or collector_state for
// a public response filters with these (see publicEventSQL,
// publicSourceSQL), so new handlers built on Store inherit the exclusion.
//
// Today that is the X posts collector (docs/xposts.md): its events
// (social_post, source xposts) are "researcher posts". What is PUBLIC about
// them is exactly this, and every public query over them goes through the
// helpers below (researcherAggSQL, researcherCounts, ResearcherOutline):
//
//   - per CVE, the number of DISTINCT allow-listed authors whose post about
//     the CVE was posted within the last ResearcherWindow (7 days, both ends
//     inclusive: now-7d <= occurred_at <= now), as researchers_7d on /hot,
//     /discussed, the vulnerability page and their JSON;
//   - the ranking of CVEs by that count on /discussed (ties: most recent
//     post time, then CVE id), without the post times themselves;
//   - which CVEs the hot list pins (HotRow.Pinned, pin.go): derived from
//     the count and the post times (latest post, start of the current
//     wave), never returning those times; it tells no more than the
//     outline's post dates below;
//   - the outline of a vulnerability page's researcher section (owner's
//     decision of 2026-11-14): how many posts it lists (at most
//     MaxMemberPosts, newest first) and, per post, ONLY the author's
//     @username as stored with the post (when it passes
//     xconfig.ValidHandle; otherwise nothing, and pages show a neutral
//     name) with the link to that X profile, the UTC date it was posted and
//     a coarse size class (SizeClass of the text length). So which
//     researcher posted about which CVE on which day is public, and with it
//     the allowlist membership of everyone who posted about a listed CVE.
//     Names appear only there: the counts and the /discussed and /hot lists
//     (and their JSON) never carry names;
//   - the resources of a vulnerability page (owner's decision of
//     2026-11-15; Store.Resources, ResourcesFor): the links of the CVE's
//     researcher posts (table x_post_link, status 'ok', kind not media or
//     quote, an absolute http/https final URL without user info),
//     de-duplicated by final URL, at most MaxResources. Per link ONLY the
//     final URL, its host, its kind, the number of distinct researchers
//     who posted it and (since 2026-11-15, owner's request) the title of
//     the linked page: the link title X's API sent with a post
//     (x_post_link.title) when non-empty, else the title nday fetched
//     from the page itself (web_page.title, status 'ok';
//     internal/webpages), cleaned (pagefetch.CleanTitle). Titles are
//     third-party text and appear only in this panel. Never who posted
//     it, the post id, the post text or the post time: which author
//     posted which link stays signed-in only.
//
// Everything else about a post is NOT public: its text, post id, post URL,
// exact time, language, author numeric id, raw record and the collector's
// health. Those reach signed-in users only, through
// Store.MemberPosts (posts.go), which only the auth-class endpoint
// GET /api/posts/{cve} (internal/posts) calls (with each post's resolved
// links, MemberPost.Links). A post never changes a stage,
// event_count, tags, the feed or the sitemap.
//
// Posts count and show only while their author is an ENABLED row of
// x_accounts (researcherPostFrom): disabling an account removes its posts
// from the counts, the outline, the resources and the signed-in list at
// once.
//
// A stub vuln row that exists only because a post mentioned the CVE stays
// visible like any other vuln without events (and is listed on /discussed).
//
// TestPostsNotPublic and TestResearcherCounts (internal/webui/nonpublic_test.go) checks all of this
// against every public route on both hosts.
var (
	// NonPublicSources are registered collectors whose events, raw records
	// and health are not public. Disjoint from SourceNames; together they
	// equal internal/registry (checked by a test).
	NonPublicSources = []string{"xposts"}
	// NonPublicEventTypes are event types never shown or counted publicly,
	// whatever their source, except through the researcher helpers below.
	NonPublicEventTypes = []string{model.EventSocialPost}
)

// ResearcherWindow is the window of the public researcher count.
const ResearcherWindow = 7 * 24 * time.Hour

// MaxMemberPosts caps the researcher section of a vulnerability page (the
// signed-in list and the signed-out outline alike).
const MaxMemberPosts = 50

// Size classes of placeholder entries (SizeClass).
const (
	SizeShort  = "s"
	SizeMedium = "m"
	SizeLong   = "l"
)

// SizeClass coarsens a text length (characters) into a size class: up to
// short is SizeShort, up to medium SizeMedium, longer SizeLong.
func SizeClass(n, short, medium int) string {
	switch {
	case n <= short:
		return SizeShort
	case n <= medium:
		return SizeMedium
	}
	return SizeLong
}

// PostSizeClass is SizeClass for post texts (X's limit is 280 characters
// for ordinary posts).
func PostSizeClass(n int) string { return SizeClass(n, 80, 200) }

// IsPublicSource reports whether source's data may be shown publicly.
func IsPublicSource(source string) bool { return contains(SourceNames, source) }

// sqlList renders constant identifiers from this file as a SQL literal list
// ('a', 'b'). The values are compile-time constants, never input.
func sqlList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return "(" + strings.Join(q, ", ") + ")"
}

// publicEventSQL is the predicate "event row alias is public".
func publicEventSQL(alias string) string {
	return "(" + alias + ".type NOT IN " + sqlList(NonPublicEventTypes) +
		" AND " + alias + ".source NOT IN " + sqlList(NonPublicSources) + ")"
}

// publicSourceSQL is the predicate "column col names a public source".
func publicSourceSQL(col string) string {
	return col + " NOT IN " + sqlList(NonPublicSources)
}

// researcherPostFrom is the FROM clause of every query over researcher
// posts (alias p): social_post events of the xposts collector whose author
// is an enabled allow-listed account. $1/$2 in researcherPostWhere are the
// window bounds when used for counts.
var researcherPostFrom = "event p JOIN x_accounts xa ON xa.user_id = p.detail->>'author_id' AND xa.enabled"

// researcherPostWhere restricts researcherPostFrom to researcher posts.
// (Constants of this file; no input.)
var researcherPostWhere = "p.type = '" + model.EventSocialPost + "' AND p.source = '" + researcherSource + "'"

// researcherSource is the collector of researcher posts.
const researcherSource = "xposts"

// researcherAggSQL is the public aggregate: one row per CVE with at least
// one researcher post in [$1, $2] — cve_id, researchers (distinct authors),
// last_at (most recent post time; used for ordering only, never returned
// to a client). extra is appended to the WHERE clause (constant SQL from
// this package, parameters numbered from $3).
func researcherAggSQL(extra string) string {
	return `SELECT p.cve_id, count(DISTINCT p.detail->>'author_id')::int AS researchers, max(p.occurred_at) AS last_at
FROM ` + researcherPostFrom + `
WHERE ` + researcherPostWhere + ` AND p.occurred_at >= $1 AND p.occurred_at <= $2` + extra + `
GROUP BY p.cve_id`
}

// researcherWindow returns the window bounds for now.
func researcherWindow(now time.Time) (time.Time, time.Time) { return now.Add(-ResearcherWindow), now }

// researcherCounts is the public researcher count of each of ids (absent =
// 0), for list rows.
func researcherCounts(ctx context.Context, conn *pgx.Conn, now time.Time, ids []string) (map[string]int, error) {
	out := map[string]int{}
	if len(ids) == 0 {
		return out, nil
	}
	from, to := researcherWindow(now)
	rows, err := conn.Query(ctx, researcherAggSQL(" AND p.cve_id = ANY($3)"), from, to, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		var last time.Time
		if err := rows.Scan(&id, &n, &last); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// OutlineEntry is one post of the public outline: the author's public
// name, the UTC date and a coarse size class; never the text, the post id,
// its URL, the exact time, the language or the author's numeric id.
type OutlineEntry struct {
	// Author is the @username stored with the post when it passes
	// xconfig.ValidHandle, else "" (show a neutral name).
	Author string `json:"author"`
	// AuthorURL is https://x.com/<Author> (nil when Author is "").
	AuthorURL *string `json:"author_url"`
	Size      string  `json:"size"` // SizeShort | SizeMedium | SizeLong
	Day       string  `json:"day"`  // YYYY-MM-DD (UTC)
}

// PublicAuthor is the public form of a stored author handle: the handle and
// its profile URL when it passes xconfig.ValidHandle, else "" and nil.
func PublicAuthor(handle string) (string, *string) {
	if !xconfig.ValidHandle(handle) {
		return "", nil
	}
	u := "https://x.com/" + handle
	return handle, &u
}

// ResearcherOutline is what everyone may know about a vulnerability's
// researcher posts.
type ResearcherOutline struct {
	// Researchers is the public count (distinct authors, last 7 days).
	Researchers int
	// Entries: one per post the section lists (newest first, at most
	// MaxMemberPosts; the same posts MemberPosts returns).
	Entries []OutlineEntry
}

// ResearcherOutline returns the public count and outline (author, day,
// size class per post) of
// cve's researcher posts.
func (s *Store) ResearcherOutline(ctx context.Context, cve string) (*ResearcherOutline, error) {
	now := s.clock()
	o := &ResearcherOutline{Entries: []OutlineEntry{}}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		c, err := researcherCounts(ctx, conn, now, []string{cve})
		if err != nil {
			return err
		}
		o.Researchers = c[cve]
		rows, err := conn.Query(ctx, `SELECT COALESCE(p.detail->>'author_handle', ''), char_length(COALESCE(p.detail->>'text', '')), p.occurred_at
FROM `+researcherPostFrom+`
WHERE `+researcherPostWhere+` AND p.cve_id = $1 AND p.occurred_at <= $2
ORDER BY p.occurred_at DESC, p.id DESC
LIMIT $3`, cve, now, MaxMemberPosts)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h string
			var n int
			var at time.Time
			if err := rows.Scan(&h, &n, &at); err != nil {
				return err
			}
			e := OutlineEntry{Size: PostSizeClass(n), Day: at.UTC().Format(time.DateOnly)}
			e.Author, e.AuthorURL = PublicAuthor(h)
			o.Entries = append(o.Entries, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return o, nil
}

// MaxResources caps the resources of a vulnerability page.
const MaxResources = 30

// maxResourceURL is the longest final URL the resources show (longer ones
// are left out; ResourceKey).
const maxResourceURL = pagefetch.MaxURL

// ResourceKinds are the kinds the resources show, in display order (media
// and quote links are never shown: the post's own photos and other posts
// on X).
var ResourceKinds = []string{xlinks.KindPoC, xlinks.KindPatch, xlinks.KindAdvisory, xlinks.KindCode, xlinks.KindOther}

// Resource is one public link of a vulnerability's researcher posts: the
// URL, its host and kind, the linked page's title and how many distinct
// researchers posted it — never who, in which post or when (see the
// comment at the top).
type Resource struct {
	URL         string `json:"url"`  // the final URL as first seen (absolute http/https)
	Host        string `json:"host"` // lower case, leading "www." stripped
	Kind        string `json:"kind"` // one of ResourceKinds
	Researchers int    `json:"researchers"`
	// Title is the page title ("" = none): the first non-empty API link
	// title of the URL's rows, else the fetched page title. Untrusted
	// third-party text, cleaned (pagefetch.CleanTitle); escape on display.
	Title string `json:"title"`
}

// ResourceLink is one link row of a researcher post, as Resources reads it
// (oldest post first, then position in the post). Not public as such: the
// author id only counts researchers.
type ResourceLink struct {
	URL    string // x_post_link.final_url
	Host   string // x_post_link.host ("" = derive from URL)
	Kind   string
	Author string // author id
	Title  string // x_post_link.title (the API's link title; "" when absent)
}

// resourceRank is the display rank of a kind (-1 = not shown).
func resourceRank(kind string) int {
	for i, k := range ResourceKinds {
		if k == kind {
			return i
		}
	}
	return -1
}

// ResourceKey is the de-duplication key of a resource URL: scheme and host
// lower case, the fragment and one trailing slash of the path dropped; ok
// is false when u is longer than maxResourceURL or not an absolute
// http/https URL with a host and without user info (such links are never
// shown). It is pagefetch.URLKey, also the key of the web page queue
// (web_page.url_key), so fetched titles match resources.
func ResourceKey(u string) (key string, ok bool) { return pagefetch.URLKey(u) }

// ResourcesFor turns link rows (oldest post first) into the public
// resources: shown kinds and valid URLs only, de-duplicated by ResourceKey
// (the first-seen spelling, host and kind are kept; Title is the first
// non-empty cleaned API title of the key's rows), researchers = distinct
// authors; ordered by kind (ResourceKinds), researchers descending, then
// first seen; at most MaxResources.
func ResourcesFor(rows []ResourceLink) []Resource {
	type acc struct {
		r       Resource
		first   int
		authors map[string]bool
	}
	byKey := map[string]*acc{}
	var list []*acc
	for i, l := range rows {
		if resourceRank(l.Kind) < 0 {
			continue
		}
		u := strings.TrimSpace(l.URL)
		key, ok := ResourceKey(u)
		if !ok {
			continue
		}
		a := byKey[key]
		if a == nil {
			host := l.Host
			if host == "" {
				p, _ := url.Parse(u)
				host = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(p.Hostname()), "."), "www.")
			}
			a = &acc{r: Resource{URL: u, Host: host, Kind: l.Kind}, first: i, authors: map[string]bool{}}
			byKey[key] = a
			list = append(list, a)
		}
		if a.r.Title == "" && l.Title != "" {
			a.r.Title = pagefetch.CleanTitle(l.Title, "")
		}
		a.authors[l.Author] = true
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if ra, rb := resourceRank(a.r.Kind), resourceRank(b.r.Kind); ra != rb {
			return ra < rb
		}
		if len(a.authors) != len(b.authors) {
			return len(a.authors) > len(b.authors)
		}
		return a.first < b.first
	})
	out := []Resource{}
	for _, a := range list {
		if len(out) == MaxResources {
			break
		}
		a.r.Researchers = len(a.authors)
		out = append(out, a.r)
	}
	return out
}

// resourceScanCap bounds the link rows Resources reads for one CVE.
const resourceScanCap = 5000

// Resources returns the public resources of cve (ResourcesFor over the
// links of its researcher posts; see the comment at the top).
func (s *Store) Resources(ctx context.Context, cve string) ([]Resource, error) {
	now := s.clock()
	var rows []ResourceLink
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rs, err := conn.Query(ctx, `SELECT l.final_url, COALESCE(l.host, ''), l.kind, COALESCE(p.detail->>'author_id', ''), COALESCE(l.title, '')
FROM `+researcherPostFrom+`
JOIN x_post_link l ON l.post_id = p.dedupe_key
WHERE `+researcherPostWhere+` AND p.cve_id = $1 AND p.occurred_at <= $2
  AND l.status = 'ok' AND l.final_url IS NOT NULL AND l.final_url <> '' AND l.kind IN `+sqlList(ResourceKinds)+`
ORDER BY p.occurred_at ASC, p.id ASC, l.pos ASC
LIMIT $3`, cve, now, resourceScanCap)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var l ResourceLink
			if err := rs.Scan(&l.URL, &l.Host, &l.Kind, &l.Author, &l.Title); err != nil {
				return err
			}
			rows = append(rows, l)
		}
		return rs.Err()
	})
	if err != nil {
		return nil, err
	}
	out := ResourcesFor(rows)
	if err := s.pageTitles(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// pageTitles fills the Title of resources without an API title from the
// web page queue (web_page.title of the same key, status 'ok'; cleaned by
// pagefetch when stored, not again: entities are decoded once). Without migration
// 0020 (no web_page table) titles stay empty.
func (s *Store) pageTitles(ctx context.Context, rs []Resource) error {
	var keys []string
	idx := map[string][]int{}
	for i, r := range rs {
		if r.Title != "" {
			continue
		}
		if k, ok := ResourceKey(r.URL); ok {
			if _, seen := idx[k]; !seen {
				keys = append(keys, k)
			}
			idx[k] = append(idx[k], i)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, `SELECT url_key, title FROM web_page WHERE url_key = ANY($1) AND status = 'ok' AND title IS NOT NULL`, keys)
		if err != nil {
			var se interface{ SQLState() string }
			if errors.As(err, &se) && se.SQLState() == "42P01" {
				return nil
			}
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, t string
			if err := rows.Scan(&k, &t); err != nil {
				return err
			}
			for _, i := range idx[k] {
				rs[i].Title = t
			}
		}
		return rows.Err()
	})
}
