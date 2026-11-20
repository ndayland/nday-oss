// Package xavatar keeps the X profile bits the researcher section shows next
// to a post: the author's display name and avatar (table x_user,
// migrations/0038_x_user.sql; docs/xposts.md "Author profiles and
// avatars").
//
// The collector stores what X sends with each post (CleanName, AvatarURL
// decide what is kept); Run, called by `nday site-icons`, fetches the
// avatar bytes through the same guarded https-only client as site icons
// (internal/pagefetch, pinned to pbs.twimg.com) and stores them, so the
// site serves them from its own origin and readers never contact X or
// twimg. Nothing here runs in a web request.
package xavatar

import (
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/xconfig"
)

// Profile limits.
const (
	// MaxName caps a display name, in runes.
	MaxName = 64
	// AvatarHost is the only host avatars are fetched from.
	AvatarHost = "pbs.twimg.com"
	// avatarPath is the path prefix of a profile image on AvatarHost.
	avatarPath = "/profile_images/"
	// maxURL caps a stored avatar URL (x_user.avatar_url CHECK).
	maxURL = 2048
)

// CleanName makes a display name from X safe to store and show as text:
// invalid UTF-8, control characters and invisible characters (format
// characters such as bidi overrides and isolates and zero-width marks,
// other default-ignorable code points, Hangul fillers, the braille blank;
// the zero-width joiner of emoji sequences stays) are dropped, combining
// marks are kept at most maxMarks a base character (none without a base),
// any run of whitespace becomes one space, the ends are trimmed, and the
// result is cut to MaxName runes. ok is false when nothing visible is left
// (only joiners, marks or blanks would render as an empty name).
func CleanName(s string) (string, bool) {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space, marks, base := false, 0, false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || r == '\u2028' || r == '\u2029':
			space, base = true, false
			continue
		case invisible(r):
			continue
		case unicode.Is(unicode.M, r):
			if !base || marks >= maxMarks {
				continue
			}
			marks++
		case r == '\u200d':
			// a joiner glues emoji: it neither starts nor ends a base
		default:
			marks, base = 0, true
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) > MaxName {
		out = strings.TrimRightFunc(string([]rune(out)[:MaxName]), unicode.IsSpace)
	}
	for _, r := range out {
		if r != '\u200d' && r != ' ' && !unicode.Is(unicode.M, r) {
			return out, true
		}
	}
	return "", false
}

// maxMarks caps the combining marks kept on one base character (a stack of
// hundreds of them draws over the rest of the page).
const maxMarks = 2

// invisible reports the code points CleanName always drops: controls,
// format characters other than the zero-width joiner, the other
// default-ignorable code points and the blanks that render as nothing.
func invisible(r rune) bool {
	switch r {
	case '\u200d':
		return false
	case '\u115f', '\u1160', '\u3164', '\uffa0', '\u2800', '\u034f':
		return true
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Variation_Selector, r) && !emojiVS(r)
}

// emojiVS keeps VS15/VS16 (text / emoji presentation), which pick how an
// emoji draws; the other variation selectors are dropped.
func emojiVS(r rune) bool { return r == '\ufe0e' || r == '\ufe0f' }

// AvatarURL accepts a profile_image_url from X only when it is
// https://pbs.twimg.com/profile_images/... : https, exactly that host, no
// user info, no port, no dot segments, no query or fragment, at most 2048
// bytes. It returns the URL as parsed back to a string; ok false means
// "no avatar".
func AvatarURL(raw string) (string, bool) {
	if raw == "" || len(raw) > maxURL || strings.ContainsAny(raw, "\\ \t\r\n") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host != AvatarHost ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", false
	}
	// the escaped and the decoded path must both be plain: no dot segments,
	// no encoded slashes or dots sneaking past the prefix check
	p := u.EscapedPath()
	if !strings.HasPrefix(p, avatarPath) || len(p) == len(avatarPath) || p != u.Path {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return u.String(), true
}

// SameHost is the redirect rule of the avatar client: a redirect may only
// stay on AvatarHost, https, under the profile image path.
func SameHost(u *url.URL) bool {
	_, ok := AvatarURL(u.String())
	return ok
}

// Profile is the x_user row of what X says about user id at seen: the name
// cleaned (CleanName), the avatar URL kept only when AvatarURL accepts it
// (rejected reports a non-empty URL that was refused). ok is false when id
// is not one x_user takes (xconfig.ValidUserID, its CHECK). The xposts
// collector and `nday x-profiles` both build their rows here.
func Profile(id, name, imageURL string, seen time.Time) (u model.XUser, rejected, ok bool) {
	if !xconfig.ValidUserID(id) {
		return model.XUser{}, false, false
	}
	u = model.XUser{UserID: id, SeenAt: seen}
	if n, ok := CleanName(name); ok {
		u.Name = &n
	}
	if v, ok := AvatarURL(imageURL); ok {
		u.AvatarURL = &v
	} else if imageURL != "" {
		rejected = true
	}
	return u, rejected, true
}
