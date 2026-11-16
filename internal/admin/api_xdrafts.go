package admin

import (
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xdraft"
)

// The draft post endpoints (docs/admin.md section 4.2), behind the same
// checks as every /api/admin/* action (admin, POST, same origin, CSRF, rate
// limit, recent sign-in). {id} is the draft id; version is the version the
// page was rendered with (a newer one answers 409 stale_version).
//
//	POST /api/admin/x/drafts/{id}/save     {"version":N,"body":"…"}
//	POST /api/admin/x/drafts/{id}/posted   {"version":N,"post_url":"https://x.com/<handle>/status/<id>"|""}
//	POST /api/admin/x/drafts/{id}/discard  {"version":N}
//	POST /api/admin/x/drafts/{id}/restore  {"version":N}

var draftIDRe = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)

// ValidDraftID reports whether s is a draft id in text form.
func ValidDraftID(s string) bool { return draftIDRe.MatchString(s) }

// maxDraftRequest bounds a draft request body (a body of MaxBodyRunes
// runes, JSON-escaped).
const maxDraftRequest = 16 << 10

// CleanDraftBody is an edited body as stored: CR LF and CR become LF, white
// space at the ends of the text and of each line removed. ok false when it
// is empty, holds a control character other than LF (tab included), or is
// longer than xdraft.MaxBodyRunes runes.
func CleanDraftBody(s string) (string, bool) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRightFunc(l, unicode.IsSpace)
	}
	s = strings.TrimSpace(strings.Join(lines, "\n"))
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > xdraft.MaxBodyRunes {
		return "", false
	}
	for _, r := range s {
		if r != '\n' && unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

type draftIn struct {
	Version *int    `json:"version"`
	Body    *string `json:"body"`
	PostURL *string `json:"post_url"`
}

// readDraft decodes the body and checks the fields an action needs.
func readDraft(w http.ResponseWriter, r *http.Request, body, postURL bool) (*draftIn, bool) {
	var in draftIn
	if !readBodyN(w, r, &in, maxDraftRequest) {
		return nil, false
	}
	switch {
	case in.Version == nil || *in.Version < 1 || *in.Version > math.MaxInt32:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "version must be a positive 32-bit integer", "version")
	case !body && in.Body != nil:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "this endpoint takes no body text", "body")
	case !postURL && in.PostURL != nil:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "this endpoint takes no post_url", "post_url")
	case body && in.Body == nil:
		web.WriteError(w, http.StatusBadRequest, "bad_body", "the text is required", "body")
	default:
		return &in, true
	}
	return nil, false
}

func (s *Service) draftDone(w http.ResponseWriter, op, actor, id string, version int, err error) {
	switch {
	case err == nil:
		s.log.Info("admin: x draft "+op, "actor", actor, "draft", id)
		n, _ := strconv.ParseInt(id, 10, 64)
		writeOK(w, map[string]any{"ok": true, "id": n, "version": version})
	case errors.Is(err, ErrDraftNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such draft", "")
	case errors.Is(err, ErrDraftStale):
		web.WriteError(w, http.StatusConflict, "stale_version", "the draft was changed since the page was loaded", "version")
	case errors.Is(err, ErrDraftState):
		web.WriteError(w, http.StatusConflict, "wrong_status", "the draft is not in a state that allows this", "")
	case errors.Is(err, ErrNoXChange):
		web.WriteError(w, http.StatusConflict, "no_change", "nothing to change", "")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	default:
		s.log.Error("admin: internal error", "op", "x_draft_"+op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

func draftID(id string) int64 { n, _ := strconv.ParseInt(id, 10, 64); return n }

func (s *Service) xDraftSave(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	in, ok := readDraft(w, r, true, false)
	if !ok {
		return
	}
	body, ok := CleanDraftBody(*in.Body)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_body", "the text must be 1 to 1000 characters without control characters", "body")
		return
	}
	if n := xdraft.WeightedLength(body); n > xdraft.BodyBudget {
		writeErrorWith(w, http.StatusBadRequest, "too_long", "the text with the link is longer than X allows", "body",
			map[string]any{"weighted_length": n, "max": xdraft.BodyBudget})
		return
	}
	v, err := s.XDraftSave(r.Context(), u.ID, draftID(id), *in.Version, body)
	s.draftDone(w, "saved", u.ID, id, v, err)
}

func (s *Service) xDraftPosted(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	in, ok := readDraft(w, r, false, true)
	if !ok {
		return
	}
	var pu *string
	if in.PostURL != nil && strings.TrimSpace(*in.PostURL) != "" {
		n, ok := xdraft.NormalizePostURL(*in.PostURL)
		if !ok {
			web.WriteError(w, http.StatusBadRequest, "bad_post_url", "the post URL must be https://x.com/<handle>/status/<id>", "post_url")
			return
		}
		pu = &n
	}
	v, err := s.XDraftPosted(r.Context(), u.ID, draftID(id), *in.Version, pu)
	s.draftDone(w, "posted", u.ID, id, v, err)
}

func (s *Service) xDraftDiscard(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	in, ok := readDraft(w, r, false, false)
	if !ok {
		return
	}
	v, err := s.XDraftDiscard(r.Context(), u.ID, draftID(id), *in.Version)
	s.draftDone(w, "discarded", u.ID, id, v, err)
}

func (s *Service) xDraftRestore(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	in, ok := readDraft(w, r, false, false)
	if !ok {
		return
	}
	v, err := s.XDraftRestore(r.Context(), u.ID, draftID(id), *in.Version)
	s.draftDone(w, "restored", u.ID, id, v, err)
}
