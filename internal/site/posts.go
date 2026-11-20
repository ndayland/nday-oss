package site

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/xavatar"
)

// NOT PUBLIC. MemberPosts returns the content of researcher posts (text,
// author, post id, URL). Only the signed-in branch of GET /api/posts/{cve}
// (internal/posts) may call it; every other caller is a leak (see the
// comment at the top of public.go, and TestPostsNotPublic).

// MemberPost is one researcher post as signed-in users see it. Every field
// is untrusted upstream data: render as text; build links only from values
// that pass the caller's validation.
type MemberPost struct {
	PostID       string
	AuthorID     string
	AuthorHandle string // as stored with the post ("" when unknown)
	AuthorName   string // X display name (x_user.name, cleaned), "" when unknown
	AuthorAvatar string // same-origin avatar path (xavatar.Path), "" when none
	Text         string
	Lang         string
	URL          string // event url ("" when none)
	PostedAt     time.Time
	// Links: the post's resolved links (x_post_link, status 'ok' with a
	// final URL), in the order they appear in the post; [] when none.
	Links []MemberLink
}

// MemberLink is one resolved link of a post: the t.co short link as it
// appears in the text and where it leads. Untrusted like the rest: the
// caller shows FinalURL only when it is an http/https URL.
type MemberLink struct {
	ShortURL string
	FinalURL string
	Host     string
	Kind     string
}

// MemberPosts returns cve's researcher posts, newest first, at most
// MaxMemberPosts: the same posts (in the same order) as the outline of
// ResearcherOutline.
func (s *Store) MemberPosts(ctx context.Context, cve string) ([]MemberPost, error) {
	now := s.clock()
	out := []MemberPost{}
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, `SELECT COALESCE(p.detail->>'post_id', p.dedupe_key, ''), COALESCE(p.detail->>'author_id', ''),
       COALESCE(p.detail->>'author_handle', ''), COALESCE(p.detail->>'text', ''), COALESCE(p.detail->>'lang', ''),
       COALESCE(p.url, ''), p.occurred_at, COALESCE(xu.name, ''), COALESCE(xu.avatar_hash, '')
FROM `+researcherPostFrom+` LEFT JOIN x_user xu ON xu.user_id = xa.user_id
WHERE `+researcherPostWhere+` AND p.cve_id = $1 AND p.occurred_at <= $2
ORDER BY p.occurred_at DESC, p.id DESC
LIMIT $3`, cve, now, MaxMemberPosts)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m MemberPost
			var hash string
			if err := rows.Scan(&m.PostID, &m.AuthorID, &m.AuthorHandle, &m.Text, &m.Lang, &m.URL, &m.PostedAt, &m.AuthorName, &hash); err != nil {
				return err
			}
			m.AuthorAvatar = xavatar.Path(hash)
			m.PostedAt = m.PostedAt.UTC()
			m.Links = []MemberLink{}
			out = append(out, m)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		return memberLinks(ctx, conn, out)
	})
	return out, err
}

// memberLinks fills the Links of ps with one query for all of them.
func memberLinks(ctx context.Context, conn *pgx.Conn, ps []MemberPost) error {
	if len(ps) == 0 {
		return nil
	}
	ids := make([]string, 0, len(ps))
	idx := map[string][]int{}
	for i, p := range ps {
		if _, ok := idx[p.PostID]; !ok {
			ids = append(ids, p.PostID)
		}
		idx[p.PostID] = append(idx[p.PostID], i)
	}
	rows, err := conn.Query(ctx, `SELECT post_id, short_url, final_url, COALESCE(host, ''), kind
FROM x_post_link
WHERE post_id = ANY($1) AND status = 'ok' AND final_url IS NOT NULL AND final_url <> ''
ORDER BY post_id, pos`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var l MemberLink
		if err := rows.Scan(&id, &l.ShortURL, &l.FinalURL, &l.Host, &l.Kind); err != nil {
			return err
		}
		for _, i := range idx[id] {
			ps[i].Links = append(ps[i].Links, l)
		}
	}
	return rows.Err()
}

// VulnExists reports whether cve has a vuln row (stubs included).
func (s *Store) VulnExists(ctx context.Context, cve string) (bool, error) {
	var ok bool
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln WHERE cve_id = $1)`, cve).Scan(&ok)
	})
	return ok, err
}
