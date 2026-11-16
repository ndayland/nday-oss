package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/site"
)

// Draft posts for the brand X account (/admin/x/drafts; docs/admin.md,
// docs/xposts.md). The generator (internal/xdraft) writes them; staff edit,
// mark posted, discard or restore them here. Reads use ReadDB; every action
// is one transaction on AuthDB (writeTx: the actor is re-checked) with one
// conditional UPDATE whose WHERE repeats the rule (status) and the version
// the page was rendered with, and its audit row.

// Draft statuses.
const (
	DraftPending   = "draft"
	DraftPosted    = "posted"
	DraftDiscarded = "discarded"
)

// Page sizes of /admin/x/drafts (hard caps, newest first).
const (
	XDraftsPage  = 50
	XHistoryPage = 20 // decided drafts per page
)

// XDraftHistory is one page of the decided drafts (posted and discarded,
// newest decision first).
type XDraftHistory struct {
	Rows  []XDraft
	Total int // decided drafts in all
	Page  int // 1-based, after clamping to [1, Pages]
	Pages int // ≥ 1
}

// XDraft is one draft as the page shows it.
type XDraft struct {
	ID         int64
	CVE        string
	Stage      string // event type
	Body       string
	Status     string
	PostURL    string
	Version    int
	DecidedBy  string // handle ("" when none or the account is gone)
	DecidedAt  *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	EventID    int64
	DecidedUID string
}

// XDraftRun is the generator's last run (x_draft_state).
type XDraftRun struct {
	LastEventID *int64
	LastRunAt   *time.Time
	Summary     map[string]any
}

// XDraftList reads the pending drafts (newest first, at most XDraftsPage),
// their total, one page of the history (posted and discarded, newest
// decision first, XHistoryPage per page) and the generator's state. hpage
// is the 1-based history page; a page below 1 or past the end is clamped.
func (s *Service) XDraftList(ctx context.Context, hpage int) (pending []XDraft, total int, history XDraftHistory, run *XDraftRun, err error) {
	scan := func(rows pgx.Rows) ([]XDraft, error) {
		return pgx.CollectRows(rows, func(r pgx.CollectableRow) (XDraft, error) {
			var d XDraft
			var url, by, uid *string
			err := r.Scan(&d.ID, &d.CVE, &d.Stage, &d.EventID, &d.Body, &d.Status, &url, &d.Version, &uid, &by, &d.DecidedAt,
				&d.CreatedAt, &d.UpdatedAt)
			if url != nil {
				d.PostURL = *url
			}
			if by != nil {
				d.DecidedBy = *by
			}
			if uid != nil {
				d.DecidedUID = *uid
			}
			return d, err
		})
	}
	const cols = `d.id, d.cve_id, d.stage, d.event_id, d.body, d.status, d.post_url, d.version, d.decided_by::text, u.handle,
		d.decided_at, d.created_at, d.updated_at FROM x_draft d LEFT JOIN users u ON u.id = d.decided_by`
	run = &XDraftRun{}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT `+cols+` WHERE d.status = 'draft' ORDER BY d.created_at DESC, d.id DESC LIMIT $1`, XDraftsPage)
		if err != nil {
			return err
		}
		if pending, err = scan(rows); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM x_draft WHERE status = 'draft'`).Scan(&total); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM x_draft WHERE status <> 'draft'`).Scan(&history.Total); err != nil {
			return err
		}
		history.Pages = max(1, (history.Total+XHistoryPage-1)/XHistoryPage)
		history.Page = min(max(hpage, 1), history.Pages)
		rows, err = c.Query(ctx, `SELECT `+cols+` WHERE d.status <> 'draft' ORDER BY d.decided_at DESC, d.id DESC LIMIT $1 OFFSET $2`,
			XHistoryPage, (history.Page-1)*XHistoryPage)
		if err != nil {
			return err
		}
		if history.Rows, err = scan(rows); err != nil {
			return err
		}
		var raw []byte
		err = c.QueryRow(ctx, `SELECT last_event_id, last_run_at, last_run FROM x_draft_state WHERE id = 1`).Scan(&run.LastEventID, &run.LastRunAt, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			_ = json.Unmarshal(raw, &run.Summary)
		}
		return err
	})
	return pending, total, history, run, err
}

// Refusals of the draft actions.
var (
	ErrDraftNotFound = errors.New("no such draft")
	ErrDraftState    = errors.New("the draft is not in a state that allows this")
	ErrDraftStale    = errors.New("the draft was changed since the page was loaded")
)

// draftLabel is the audit label: "CVE-2026-1234 +KEV".
func draftLabel(cve, stage string) string { return cve + " +" + site.StageCode(stage) }

// draftAction runs one conditional UPDATE (set, with $1 = id, $2 = version,
// further arguments after) that applies only WHERE status = from AND
// version = $2, bumps the version and writes the audit row. When no row
// changes it tells why: not found, wrong status, stale version.
func (s *Service) draftAction(ctx context.Context, actor string, id int64, version int, from, set, extra, action string,
	details func(cve, stage string) map[string]any, args ...any) (int, error) {
	var newVersion int
	err := s.writeTx(ctx, actor, func(tx pgx.Tx) error {
		var cve, stage string
		err := tx.QueryRow(ctx, `UPDATE x_draft SET `+set+`, version = version + 1, updated_at = now()
			WHERE id = $1 AND version = $2 AND status = '`+from+`'`+extra+`
			RETURNING cve_id, stage, version`, append([]any{id, version}, args...)...).Scan(&cve, &stage, &newVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			var st string
			var v int
			err := tx.QueryRow(ctx, `SELECT status, version FROM x_draft WHERE id = $1`, id).Scan(&st, &v)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return ErrDraftNotFound
			case err != nil:
				return err
			case v != version:
				return ErrDraftStale
			case st == from && extra != "":
				return ErrNoXChange // the extra condition (a change) failed
			default:
				return ErrDraftState
			}
		}
		if err != nil {
			return err
		}
		d := details(cve, stage)
		d["cve"], d["version"] = cve, newVersion
		return audit.Write(ctx, tx, audit.Entry{ActorID: &actor, Action: action, TargetType: audit.TargetXDraft,
			TargetID: itoa(id), TargetLabel: draftLabel(cve, stage), Details: d})
	})
	return newVersion, err
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// XDraftSave replaces the text of a pending draft (validated by the
// caller); ErrNoXChange when it is the same text.
func (s *Service) XDraftSave(ctx context.Context, actor string, id int64, version int, body string) (int, error) {
	return s.draftAction(ctx, actor, id, version, DraftPending, `body = $3`, ` AND body <> $3`, audit.XDraftSave, func(string, string) map[string]any { return map[string]any{"length": len([]rune(body))} }, body)
}

// XDraftPosted marks a pending draft posted, with the post's URL (already
// normalised) or none.
func (s *Service) XDraftPosted(ctx context.Context, actor string, id int64, version int, postURL *string) (int, error) {
	return s.draftAction(ctx, actor, id, version, DraftPending,
		`status = 'posted', post_url = $3, decided_by = $4::uuid, decided_at = now()`, "", audit.XDraftPosted,
		func(string, string) map[string]any {
			d := map[string]any{}
			if postURL != nil {
				d["post_url"] = *postURL
			}
			return d
		}, postURL, actor)
}

// XDraftDiscard discards a pending draft.
func (s *Service) XDraftDiscard(ctx context.Context, actor string, id int64, version int) (int, error) {
	return s.draftAction(ctx, actor, id, version, DraftPending,
		`status = 'discarded', decided_by = $3::uuid, decided_at = now()`, "", audit.XDraftDiscard,
		func(string, string) map[string]any { return map[string]any{} }, actor)
}

// XDraftRestore puts a discarded draft back into the queue.
func (s *Service) XDraftRestore(ctx context.Context, actor string, id int64, version int) (int, error) {
	return s.draftAction(ctx, actor, id, version, DraftDiscarded,
		`status = 'draft', decided_by = NULL, decided_at = NULL`, "", audit.XDraftRestore,
		func(string, string) map[string]any { return map[string]any{} })
}
