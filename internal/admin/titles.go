package admin

import (
	"context"
	"errors"
	"math"
	"net/http"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/titles"
	"nday.land/nday/internal/web"
)

// Staff titles (/admin/titles; docs/titles.md, docs/admin.md): an admin
// sets a better title by hand for a vulnerability (meant for the ones
// researchers discuss), or clears it so the record's or the composed title
// shows again. The staff title is stored in vuln_title (migration 0031)
// next to the composed parts, which only the tag pass writes. Each action
// is one transaction on AuthDB (writeTx: the actor is re-checked) that
// locks the vulnerability's vuln_title row, checks the version the page was
// rendered with (staff_version; 409 stale_version otherwise), writes and
// records one audit row (target vuln, the old and the new title). Public
// pages show the change once their cache entries expire (the server's
// cache TTL; nothing is invalidated, as for every other staff edit).
//
//	POST /api/admin/titles/{id}/set    {"version":N,"title":"…"}
//	POST /api/admin/titles/{id}/clear  {"version":N}
//
// {id} is a vulnerability id (CVE or GHSA, any case); version the
// staff_version the page showed (0 before the first staff title).

// Refusals of the staff title actions.
var (
	ErrTitleNotFound = errors.New("no such vulnerability")
	ErrTitleStale    = errors.New("the title was changed since the page was loaded")
	ErrTitleNoChange = errors.New("nothing to change")
)

// TitleQueue is one page (1-based, clamped) of the title queue: the
// vulnerabilities researchers discuss, most researchers first, then most
// posts; all = false keeps those whose record has no title.
func (s *Service) TitleQueue(ctx context.Context, all bool, page int) ([]site.TitleQueueRow, Window, error) {
	if s.o.Site == nil {
		return nil, Window{Page: 1, Pages: 1}, nil
	}
	rows, total, p, err := s.o.Site.TitleQueue(ctx, s.now(), all, page)
	w := window(total, p)
	return rows, w, err
}

// TitleLookup is the title data of one vulnerability (nil: unknown id).
func (s *Service) TitleLookup(ctx context.Context, id string) (*site.TitleQueueRow, error) {
	cve, ok := site.ParseVulnID(id)
	if !ok || s.o.Site == nil {
		return nil, nil
	}
	return s.o.Site.TitleEntry(ctx, s.now(), cve)
}

// staffTitle runs one staff title change of cve (canonical) in a
// transaction: the row is created if missing and locked, the version
// checked; change returns the new title (nil = cleared) or
// ErrTitleNoChange.
func (s *Service) staffTitle(ctx context.Context, actor, cve string, version int, action string,
	change func(old *string) (*string, error)) (int, error) {
	var newVersion int
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		// Hold the vulnerability against the GHSA merge (it deletes the
		// row, and this table's rows with it) until this edit commits.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM vuln WHERE cve_id = $1 FOR KEY SHARE`, cve); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vuln_title (cve_id) SELECT cve_id FROM vuln WHERE cve_id = $1
			ON CONFLICT (cve_id) DO NOTHING`, cve); err != nil {
			return err
		}
		var old *string
		var v int
		err := tx.QueryRow(ctx, `SELECT staff_title, staff_version FROM vuln_title WHERE cve_id = $1 FOR UPDATE`, cve).Scan(&old, &v)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrTitleNotFound
		case err != nil:
			return err
		case v != version:
			return ErrTitleStale
		}
		next, err := change(old)
		if err != nil {
			return err
		}
		if next == nil {
			err = tx.QueryRow(ctx, `UPDATE vuln_title SET staff_title = NULL, staff_by = NULL, staff_at = NULL,
				staff_version = staff_version + 1 WHERE cve_id = $1 RETURNING staff_version`, cve).Scan(&newVersion)
		} else {
			err = tx.QueryRow(ctx, `UPDATE vuln_title SET staff_title = $2, staff_by = $3::uuid, staff_at = now(),
				staff_version = staff_version + 1 WHERE cve_id = $1 RETURNING staff_version`, cve, *next, actor).Scan(&newVersion)
		}
		if err != nil {
			return err
		}
		d := map[string]any{"cve": cve, "old": old, "version": newVersion}
		if next != nil {
			d["new"] = *next
		}
		return audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: action, TargetType: audit.TargetVuln,
			TargetID: cve, TargetLabel: cve, Details: d})
	})
	return newVersion, err
}

// SetStaffTitle sets the staff title of cve (canonical; title validated
// by titles.CleanStaff); ErrTitleNoChange when it is the same.
func (s *Service) SetStaffTitle(ctx context.Context, actor, cve string, version int, title string) (int, error) {
	return s.staffTitle(ctx, actor, cve, version, audit.VulnTitleSet, func(old *string) (*string, error) {
		if old != nil && *old == title {
			return nil, ErrTitleNoChange
		}
		return &title, nil
	})
}

// ClearStaffTitle removes the staff title of cve; ErrTitleNoChange when it
// has none.
func (s *Service) ClearStaffTitle(ctx context.Context, actor, cve string, version int) (int, error) {
	return s.staffTitle(ctx, actor, cve, version, audit.VulnTitleClear, func(old *string) (*string, error) {
		if old == nil {
			return nil, ErrTitleNoChange
		}
		return nil, nil
	})
}

// ---- endpoints

// validVulnID reports whether s is a vulnerability id (any case).
func validVulnID(s string) bool { _, ok := site.ParseVulnID(s); return ok }

type titleIn struct {
	Version *int    `json:"version"`
	Title   *string `json:"title"`
}

func readTitle(w http.ResponseWriter, r *http.Request, withTitle bool) (*titleIn, bool) {
	var in titleIn
	if !readBody(w, r, &in) {
		return nil, false
	}
	switch {
	case in.Version == nil || *in.Version < 0 || *in.Version > math.MaxInt32:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "version must be a 32-bit integer of at least 0", "version")
	case !withTitle && in.Title != nil:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "this endpoint takes no title", "title")
	case withTitle && in.Title == nil:
		web.WriteError(w, http.StatusBadRequest, "bad_title", titles.ErrStaffTitle.Error(), "title")
	default:
		return &in, true
	}
	return nil, false
}

func (s *Service) titleDone(w http.ResponseWriter, op, actor, cve string, version int, err error) {
	switch {
	case err == nil:
		s.log.Info("admin: staff title "+op, "actor", actor, "cve", cve)
		writeOK(w, map[string]any{"ok": true, "cve_id": cve, "version": version})
	case errors.Is(err, ErrTitleNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such vulnerability", "")
	case errors.Is(err, ErrTitleStale):
		web.WriteError(w, http.StatusConflict, "stale_version", ErrTitleStale.Error(), "version")
	case errors.Is(err, ErrTitleNoChange):
		web.WriteError(w, http.StatusConflict, "no_change", "nothing to change", "")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	default:
		s.log.Error("admin: internal error", "op", "title_"+op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

func (s *Service) titleSet(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	cve, _ := site.ParseVulnID(id)
	in, ok := readTitle(w, r, true)
	if !ok {
		return
	}
	title, err := titles.CleanStaff(*in.Title)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, "bad_title", err.Error(), "title")
		return
	}
	v, err := s.SetStaffTitle(r.Context(), u.ID, cve, *in.Version, title)
	s.titleDone(w, "set", u.ID, cve, v, err)
}

func (s *Service) titleClear(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	cve, _ := site.ParseVulnID(id)
	in, ok := readTitle(w, r, false)
	if !ok {
		return
	}
	v, err := s.ClearStaffTitle(r.Context(), u.ID, cve, *in.Version)
	s.titleDone(w, "cleared", u.ID, cve, v, err)
}
