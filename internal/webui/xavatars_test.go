package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/siteicon"
)

func avatarPNG(t *testing.T, w int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, w))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// putAvatar stores an x_user row for id with a fetched avatar (img nil:
// only the name) and returns the hash.
func putAvatar(t *testing.T, c *pgx.Conn, id string, name *string, img []byte, ct string) string {
	t.Helper()
	var h, typ *string
	var data []byte
	if img != nil {
		s := siteicon.Hash(img)
		h, typ, data = &s, &ct, img
	}
	status := map[bool]any{true: "ok", false: nil}[img != nil]
	if _, err := c.Exec(context.Background(), `INSERT INTO x_user (user_id, name, avatar_url, seen_at, avatar_status, avatar_type, avatar_image, avatar_hash)
VALUES ($1, $2, 'https://pbs.twimg.com/profile_images/1/a.png', now(), $3, $4, $5, $6)`, id, name, status, typ, data, h); err != nil {
		t.Fatal(err)
	}
	if h == nil {
		return ""
	}
	return *h
}

// TestXAvatarRoute: /avatar/{hash} serves exactly the stored bytes with the
// sniffed type, immutable (the path is the content hash) and locked down;
// an unknown or malformed hash, a disabled account's or one of an author no
// outline shows (only a post without a CVE) is a short-cached 404.
func TestXAvatarRoute(t *testing.T) {
	e, conn := newMemberEnv(t, false)
	img, off, nocve := avatarPNG(t, 48), avatarPNG(t, 40), avatarPNG(t, 36)
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('11', 'qzav', true), ('12', 'qzoff', false), ('13', 'qznocve', true)`,
		// 11 and 12 posted about a listed vulnerability; 13's only post names
		// no CVE, so no page shows 13 and neither may the avatar route
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key)
            SELECT '` + sitetest.GPU + `', 'social_post', $1, $1, 'xposts', jsonb_build_object('post_id', '9' || id, 'author_id', id), '9' || id
            FROM unnest(ARRAY['11', '12']) AS id`,
		`INSERT INTO x_post_no_cve (post_id, author_id, author_handle, text, posted_at, url, observed_at)
            VALUES ('913', '13', 'qznocve', 'no id here', $1, 'https://x.com/qznocve/status/913', $1)`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = append(args, sitetest.Now.Add(-time.Hour))
		}
		if _, err := conn.Exec(context.Background(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	hash := putAvatar(t, conn, "11", sitetest.P("Av"), img, "image/png")
	offHash := putAvatar(t, conn, "12", nil, off, "image/png")
	nocveHash := putAvatar(t, conn, "13", nil, nocve, "image/png")
	get := func(method, path string, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, e.ts.URL+path, nil)
		req.Host = wwwHost
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return resp, b.Bytes()
	}
	locked := func(path string, resp *http.Response) {
		t.Helper()
		h := resp.Header
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Security-Policy") != "default-src 'none'; sandbox" ||
			h.Get("Cross-Origin-Resource-Policy") != "same-origin" || h.Get("Set-Cookie") != "" {
			t.Errorf("%s: headers %v", path, h)
		}
	}
	resp, body := get(http.MethodGet, "/avatar/"+hash)
	locked("ok", resp)
	if resp.StatusCode != 200 || !bytes.Equal(body, img) || resp.Header.Get("Content-Type") != "image/png" ||
		resp.Header.Get("Cache-Control") != "public, max-age=604800, immutable" || resp.Header.Get("ETag") != `"`+hash+`"` {
		t.Errorf("ok: %d %v %d bytes", resp.StatusCode, resp.Header, len(body))
	}
	if resp, body := get(http.MethodGet, "/avatar/"+hash, "If-None-Match", `"`+hash+`"`); resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Errorf("conditional: %d", resp.StatusCode)
	}
	for _, p := range []string{"/avatar/0123456789abcdef", "/avatar/" + offHash, "/avatar/" + nocveHash, "/avatar/" + strings.ToUpper(hash), "/avatar/" + hash + "0",
		"/avatar/11", "/avatar/qzav", "/avatar/" + hash[:15], "/avatar/%2e%2e", "/avatar/" + hash + ".png"} {
		resp, body := get(http.MethodGet, p)
		locked(p, resp)
		if resp.StatusCode != 404 || len(body) > 0 && bytes.HasPrefix(body, []byte("\x89PNG")) || resp.Header.Get("Cache-Control") != "public, max-age=300" ||
			strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
			t.Errorf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
	// a row whose type is not one xavatar stores (written by hand) is never served
	if _, err := conn.Exec(context.Background(), `ALTER TABLE x_user DROP CONSTRAINT x_user_avatar_type_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(context.Background(), `UPDATE x_user SET avatar_type = 'image/svg+xml' WHERE user_id = '11'`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(http.MethodGet, "/avatar/"+hash); resp.StatusCode != 404 {
		t.Errorf("svg type served: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := get(http.MethodPost, "/avatar/"+hash); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}

// TestResearchCards: the researcher section draws each post as a card with
// the author's stored avatar (a same-origin /avatar/ path) or the handle's
// letter, the display name (escaped text) and @handle; the posts endpoint
// gives the same author_name / author_avatar to guests (outline) and to
// signed-in readers (posts). No X image URL reaches the page.
func TestResearchCards(t *testing.T) {
	e, conn := newMemberEnv(t, true)
	hash := putAvatar(t, conn, postAuthor, sitetest.P(`<b>Qz "Name"</b>`), avatarPNG(t, 48), "image/png")
	putAvatar(t, conn, post2Author, nil, nil, "")
	_, out := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	sec := researchSecRe.FindString(out)
	for _, w := range []string{
		`<li class="rp"><div class="rp-h"><img class="rp-av" src="/avatar/` + hash + `" width="28" height="28" loading="lazy" decoding="async" alt=""/><a class="rp-au" href="https://x.com/` + postHandle +
			`" target="_blank" rel="noopener noreferrer nofollow" data-fav=""><span class="fav" aria-hidden="true"></span><bdi class="rp-nm">&lt;b&gt;Qz &#34;Name&#34;&lt;/b&gt;</bdi> <span class="rp-hd">@` + postHandle + `</span></a><span class="rp-xm" aria-hidden="true"></span></div>`,
		`<span class="rp-av rp-mono" aria-hidden="true">Q</span><a class="rp-au" href="https://x.com/` + post2Handle + `" target="_blank" rel="noopener noreferrer nofollow" data-fav=""><span class="fav" aria-hidden="true"></span>@` + post2Handle + `</a>`,
		`<span class="rp-av rp-mono" aria-hidden="true"></span><span class="rp-au weak">researcher</span>`,
		`<span class="spk" data-size="s" aria-hidden="true"></span></a><p class="rp-f"><span class="rp-t">2026-11-13</span></p>`,
	} {
		if !strings.Contains(sec, w) {
			t.Errorf("research section lacks %q:\n%s", w, sec)
		}
	}
	if strings.Contains(out, "twimg") || strings.Contains(out, "<b>Qz") {
		t.Error("the page carries an X image URL or unescaped name")
	}

	type author struct {
		Name   string `json:"author_name"`
		Avatar string `json:"author_avatar"`
		Handle string `json:"author_handle"`
		Author string `json:"author"`
	}
	var guest struct {
		Outline []author `json:"outline"`
	}
	_, body := e.fetch(t, wwwHost, "/api/posts/"+sitetest.GPU, nil)
	if err := json.Unmarshal([]byte(body), &guest); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range guest.Outline {
		if o.Author == postHandle {
			found = o.Name == `<b>Qz "Name"</b>` && o.Avatar == "/avatar/"+hash
		}
		if o.Author == post2Handle && (o.Name != "" || o.Avatar != "") {
			t.Errorf("outline %s: %+v", post2Handle, o)
		}
	}
	if !found || strings.Contains(body, postAuthor) {
		t.Errorf("guest outline: %s", body)
	}
	cookies, _ := e.signIn(t, "9101", "qzreader")
	var member struct {
		Posts []author `json:"posts"`
	}
	_, body = e.fetch(t, wwwHost, "/api/posts/"+sitetest.GPU, cookies)
	if err := json.Unmarshal([]byte(body), &member); err != nil {
		t.Fatal(err)
	}
	found = false
	for _, p := range member.Posts {
		if p.Handle == postHandle {
			found = p.Name == `<b>Qz "Name"</b>` && p.Avatar == "/avatar/"+hash
		}
	}
	if !found {
		t.Errorf("member posts: %s", body)
	}
}
