package discuss

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/discuss/md"
)

// LinkFunc returns the site path of a vulnerability page for a canonical CVE
// id (with the caller's locale prefix), e.g. "/zh-hans/vuln/CVE-2026-1234".
type LinkFunc func(cve string) string

// Comment is one comment as shown to a viewer (JSON of GET /api/discuss/{cve}
// and the value Stream returns). See docs/discuss.md §3.1 for every field.
type Comment struct {
	ID        string     `json:"id"`
	ParentID  *string    `json:"parent_id"`
	Author    *Author    `json:"author"`
	Lang      string     `json:"lang"`
	CreatedAt time.Time  `json:"created_at"`
	EditedAt  *time.Time `json:"edited_at"`
	Status    string     `json:"status"`
	// Purpose is what a top-level comment is for (one of Purposes; null:
	// not given, a reply, or a placeholder).
	Purpose *string `json:"purpose"`
	// BodyHTML is the rendered body ("" for placeholders). It is built only
	// from the md allowlist and is safe to insert as HTML.
	BodyHTML string `json:"body_html"`
	// BodyNodes is BodyHTML as a node tree (md.Nodes) for scripts that build
	// the DOM without parsing HTML; absent for placeholders.
	BodyNodes []any `json:"body_nodes,omitempty"`
	// Body is the Markdown source, only for the author and moderators.
	Body *string `json:"body,omitempty"`
	// Links: links in this comment are clickable (false: written while the
	// author's account was new).
	Links      bool        `json:"links"`
	CanEdit    bool        `json:"can_edit"`
	CanDelete  bool        `json:"can_delete"`
	CanHide    bool        `json:"can_hide"`
	CanUnhide  bool        `json:"can_unhide"`
	CanReport  bool        `json:"can_report"`
	CanReply   bool        `json:"can_reply"`
	Reported   bool        `json:"reported"`
	Moderation *Moderation `json:"moderation,omitempty"`
	// Replies: oldest first; [] for a top-level comment without replies,
	// null for a reply (replies never have replies).
	Replies []Comment `json:"replies"`
	// RepliesTruncated: this thread alone exceeded the page byte budget and
	// Replies holds only its first replies; fetch the rest with
	// GET /api/discuss/{cve}?thread={id}&cursor={RepliesNextCursor} (or
	// Service.StreamThread), repeatedly while the result is truncated again.
	RepliesTruncated  bool    `json:"replies_truncated"`
	RepliesNextCursor *string `json:"replies_next_cursor"`
}

// Moderation is extra information: everything for moderators; for the
// author of a hidden comment only HiddenAt and HiddenReason.
type Moderation struct {
	HiddenAt     *time.Time `json:"hidden_at"`
	HiddenBy     *Author    `json:"hidden_by,omitempty"`
	HiddenReason *string    `json:"hidden_reason"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
	OpenReports  *int       `json:"open_reports,omitempty"`
	// Revisions: how many earlier bodies are stored (moderators only; read
	// them with GET /api/mod/comment/{id}/revisions).
	Revisions *int   `json:"revisions,omitempty"`
	CVE       string `json:"cve,omitempty"`
}

// Viewer is who is looking (nil = anonymous).
type Viewer struct {
	ID        string
	Active    bool // not suspended
	HasHandle bool
	TermsOK   bool // current rules accepted (or none configured)
	Moderator bool // role moderator or admin, and active
}

// CanWrite: may create comments (and edit own).
func (v *Viewer) CanWrite() bool { return v != nil && v.Active && v.HasHandle && v.TermsOK }

func (v *Viewer) idPtr() *string {
	if v == nil {
		return nil
	}
	return &v.ID
}

func (v *Viewer) isAuthor(r *Row) bool {
	return v != nil && r.AuthorID != nil && *r.AuthorID == v.ID
}

// view turns a row into what viewer may see. link builds CVE links.
func view(r *Row, v *Viewer, link LinkFunc, withCVE bool) Comment {
	c := Comment{ID: r.ID, ParentID: r.ParentID, CreatedAt: r.CreatedAt.UTC(), Status: r.Status, Reported: r.Reported}
	if r.ParentID == nil {
		c.Replies = []Comment{}
	}
	author := v.isAuthor(r)
	mod := v != nil && v.Moderator
	full := r.Status == StatusVisible || mod || (author && r.Status == StatusHidden)
	if full { // otherwise a placeholder: id, parent_id, created_at, status only
		c.Author, c.Links = r.Author, r.Links
		if !mod && r.Author != nil {
			// Only moderators get the display name. It is copied from the
			// sign-in provider's profile (a legal name, often) and the page
			// never shows it; the handle is the public name.
			a := *r.Author
			a.DisplayName = nil
			c.Author = &a
		}
		c.Lang = r.Lang
		c.EditedAt = utc(r.EditedAt)
		if r.ParentID == nil && r.Purpose != nil {
			p := *r.Purpose
			c.Purpose = &p
		}
		c.BodyHTML = md.Render(r.Body, md.Options{Links: r.Links, CVELink: link})
		if n, err := md.Nodes(c.BodyHTML); err == nil {
			c.BodyNodes = n
		} else {
			c.BodyNodes = []any{r.Body} // unreachable (fuzz-tested); the source as text
		}
		if author || mod {
			b := r.Body
			c.Body = &b
		}
	}
	switch {
	case mod:
		n, revs := r.OpenReports, r.Revisions
		c.Moderation = &Moderation{HiddenAt: utc(r.HiddenAt), HiddenBy: r.HiddenBy, HiddenReason: r.HiddenReason,
			DeletedAt: utc(r.DeletedAt), OpenReports: &n, Revisions: &revs}
		if withCVE {
			c.Moderation.CVE = r.CVE
		}
	case author && r.Status == StatusHidden:
		c.Moderation = &Moderation{HiddenAt: utc(r.HiddenAt), HiddenReason: r.HiddenReason}
	}
	c.CanEdit = author && v.CanWrite() && r.Status == StatusVisible
	c.CanDelete = author && (r.Status == StatusVisible || r.Status == StatusHidden)
	c.CanHide = mod && r.Status == StatusVisible
	c.CanUnhide = mod && r.Status == StatusHidden
	c.CanReport = v != nil && v.Active && !author && r.Status == StatusVisible
	c.CanReply = r.ParentID == nil && r.Status == StatusVisible && v.CanWrite() && r.Replies < MaxReplies
	return c
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// NormalizeBody is the stored form of a body: md.Clean (CR/CRLF -> LF,
// controls, bidi embeddings/overrides/isolates and invisible characters
// removed, combining-mark runs cut, blank-line runs collapsed, invalid
// UTF-8 -> U+FFFD), then surrounding white space trimmed. ok is false when
// the result has no visible character (only white space, ZWJ/ZWNJ, marks or
// format characters) or more than MaxBodyChars characters.
func NormalizeBody(s string) (string, bool) {
	s = strings.TrimSpace(md.Clean(s))
	n := utf8.RuneCountInString(s)
	return s, n >= 1 && n <= MaxBodyChars && hasVisible(s)
}

func hasVisible(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf) {
			return true
		}
	}
	return false
}

// normalizeLine cleans a short single-line text (report note, hide reason):
// md.Clean, line breaks and tabs become spaces, trimmed.
func normalizeLine(s string) string {
	s = md.Clean(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}
