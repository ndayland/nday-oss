// Package audit writes and reads the append-only log of staff actions
// (table admin_audit, migrations/0007_admin.sql; docs/admin.md).
//
// Write takes the caller's pgx.Tx: every staff action records its row in
// the SAME transaction as the change, so a failed insert rolls the action
// back and a rolled-back action leaves no row. The package never updates or
// deletes rows (and the table's trigger refuses it).
//
// Who acted: Entry.ActorID is the signed-in staff member (handle and role
// are snapshotted from users inside the same transaction), or nil for a
// command run on the server (actor "cli", source "cli"). For web actions the
// client address and Cloudflare request id come from the request context
// (WithClient), set once by the HTTP layer.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Action codes.
const (
	CommentHide   = "comment.hide"
	CommentUnhide = "comment.unhide"
	ReportResolve = "report.resolve"
	UserSuspend   = "user.suspend"
	UserUnsuspend = "user.unsuspend"
	UserRole      = "user.role"
	UserSignOut   = "user.signout_all"
)

// Action codes of the xposts collector's configuration (internal/xconfig).
const (
	XSettingsUpdate = "x.settings.update"
	XAccountAdd     = "x.account.add"
	XAccountUpdate  = "x.account.update"
	XAccountEnable  = "x.account.enable"
	XAccountDisable = "x.account.disable"
	XAccountsImport = "x.accounts.import"
	// XAccountProfiles: a bounded refresh of the accounts' names and bios
	// from X (target id "profiles").
	XAccountProfiles = "x.account.profiles"
	// allowlist candidates (target x_account, target id = the candidate's
	// numeric user id); adding one is x.account.add with "candidate": true
	XCandidateDismiss = "x.candidate.dismiss"
	XCandidateRestore = "x.candidate.restore"
)

// Action codes of the draft posts for the brand X account (internal/xdraft,
// /admin/x/drafts): target x_draft, target id = draft id.
const (
	XDraftSave    = "x.draft.save"
	XDraftPosted  = "x.draft.posted"
	XDraftDiscard = "x.draft.discard"
	XDraftRestore = "x.draft.restore"
)

// Action codes of the database settings (internal/settings): target
// setting, target id = the key (NDAY_*), or for a change of several keys
// on /admin/settings their group (discuss, collectors, auth) or
// "settings"; details hold only key names ({"keys": [...]} from the
// command line, {"set": [...], "unset": [...]} from /admin/settings),
// never values. A secret is stored (secret_set) or cleared (secret_clear)
// with one row per key.
const (
	SettingsUpdate      = "settings.update"
	SettingsUnset       = "settings.unset"
	SettingsSecretSet   = "settings.secret_set"
	SettingsSecretClear = "settings.secret_clear"
)

// Action codes of readers' corrections of vulnerability pages
// (internal/corrections, /admin/corrections): target correction, target id
// = the correction id; details hold the CVE and the category, and for an
// accept the whole public note (public_note); reason is the public note
// (accept; cut to MaxReason like every reason) or the internal note
// (reject, if any).
const (
	CorrectionAccept = "correction.accept"
	CorrectionReject = "correction.reject"
)

// Action codes of the review of GitHub repositories (internal/ghrepo
// SetStatus, /admin/github): target type TargetXAccount (the table's CHECK
// has no GitHub target type, and adding one needs a migration), target id
// GitHubRepoTarget + the github_repo id, label the full name; details hold
// the repository id, the full name and the status before (from, from_by)
// and after (to).
const (
	GitHubRepoTrust  = "github.repo.trust"
	GitHubRepoReject = "github.repo.reject"
	GitHubRepoReset  = "github.repo.reset"
	// GitHubRepoTarget prefixes the target id of a github.repo.* row, so it
	// never equals an X user id.
	GitHubRepoTarget = "github_repo:"
)

// Action codes of the trusted GitHub accounts (internal/admin ghowners.go,
// /admin/github): target type TargetXAccount as above, target id
// GitHubOwnerTarget + github_trusted_owner.id, label the login; details
// hold the account id ("owner"), the login, what changed, and how many
// repositories became trusted or went back ("trusted", "untrusted").
// link / unlink: the account's link to an allow-listed X account was set
// or changed / cleared (details "from" and "to": x_user_id, x_handle).
const (
	GitHubOwnerAdd     = "github.owner.add"
	GitHubOwnerUpdate  = "github.owner.update"
	GitHubOwnerEnable  = "github.owner.enable"
	GitHubOwnerDisable = "github.owner.disable"
	GitHubOwnerLink    = "github.owner.link"
	GitHubOwnerUnlink  = "github.owner.unlink"
	// GitHubOwnerTarget prefixes the target id of a github.owner.* row.
	GitHubOwnerTarget = "github_owner:"
)

// Action codes of the staff titles of vulnerabilities (internal/admin
// titles.go, /admin/titles; docs/titles.md): target vuln, target id and
// label = the vulnerability id; details hold the CVE ("cve"), the title
// before ("old", null when none), after a set the new one ("new") and the
// new staff version ("version").
const (
	VulnTitleSet   = "vuln.title_set"
	VulnTitleClear = "vuln.title_clear"
)

// Actions lists every action code (filters, docs).
var Actions = []string{CommentHide, CommentUnhide, ReportResolve, UserSuspend, UserUnsuspend, UserRole, UserSignOut,
	XSettingsUpdate, XAccountAdd, XAccountUpdate, XAccountEnable, XAccountDisable, XAccountsImport, XAccountProfiles,
	XCandidateDismiss, XCandidateRestore, XDraftSave, XDraftPosted, XDraftDiscard, XDraftRestore, SettingsUpdate, SettingsUnset, SettingsSecretSet, SettingsSecretClear,
	CorrectionAccept, CorrectionReject, GitHubRepoTrust, GitHubRepoReject, GitHubRepoReset,
	GitHubOwnerAdd, GitHubOwnerUpdate, GitHubOwnerEnable, GitHubOwnerDisable, GitHubOwnerLink, GitHubOwnerUnlink,
	VulnTitleSet, VulnTitleClear}

// Target types.
const (
	TargetComment    = "comment"
	TargetReport     = "report"
	TargetUser       = "user"
	TargetXSettings  = "x_settings" // target id "1"
	TargetXAccount   = "x_account"  // target id = numeric X user id, or "import"
	TargetXDraft     = "x_draft"    // target id = x_draft.id
	TargetSetting    = "setting"    // target id = the setting's key (NDAY_*)
	TargetCorrection = "correction" // target id = vuln_corrections.id
	TargetVuln       = "vuln"       // target id = the vulnerability id (migration 0031)
)

// Limits of the stored text (runes), as in the table's CHECKs.
const (
	MaxLabel   = 200
	MaxReason  = 500
	MaxDetails = 2048 // bytes of the JSON object
	// MaxCorrectionDetails: bytes of the JSON object of a row with target
	// TargetCorrection (migrations/0018): correction.accept keeps the whole
	// public note (up to 1000 characters, 6 bytes each at most as JSON).
	MaxCorrectionDetails = 8192
	maxClient            = 64
)

// Entry is one staff action.
type Entry struct {
	// ActorID is the acting user, nil for a command run on the server.
	ActorID     *string
	Action      string
	TargetType  string
	TargetID    string
	TargetLabel string // plain text; cut to MaxLabel runes
	Reason      string // "" = none; cut to MaxReason runes
	Details     map[string]any
}

type clientKey struct{}

type client struct{ addr, ray string }

// WithClient returns ctx carrying the client address and Cloudflare ray id
// of a web request (recorded with web actions).
func WithClient(ctx context.Context, addr, ray string) context.Context {
	return context.WithValue(ctx, clientKey{}, client{addr: token(addr, ".:/"), ray: token(ray, "-")})
}

// token keeps ASCII letters and digits plus the characters in extra, and
// cuts the result to maxClient: the address and the ray id come from request
// headers and are shown on the audit page, so no control, bidi or other
// free-form character may be stored.
func token(s, extra string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxClient; i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte(extra, c) >= 0 {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// Excerpt is s as one line of plain text of at most n runes: control and
// format characters removed, runs of white space collapsed, an ellipsis
// when cut.
func Excerpt(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var out []rune
	space := false
	for _, r := range strings.ToValidUTF8(s, "�") {
		if unicode.IsSpace(r) {
			space = len(out) > 0
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, r)
		if len(out) > n {
			out = []rune(strings.TrimRight(string(out[:n-1]), " "))
			return string(append(out, '…'))
		}
	}
	return string(out)
}

// ErrInvalid: an entry that does not fit the table (programming error).
var ErrInvalid = errors.New("audit: invalid entry")

// Write appends e in tx. The actor's handle and role are read from users in
// the same transaction; an unknown actor fails the insert.
func Write(ctx context.Context, tx pgx.Tx, e Entry) error {
	if e.Action == "" || e.TargetType == "" || e.TargetID == "" {
		return ErrInvalid
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	dj, err := json.Marshal(details)
	limit := MaxDetails
	if e.TargetType == TargetCorrection {
		limit = MaxCorrectionDetails
	}
	if err != nil || len(dj) > limit {
		return ErrInvalid
	}
	var reason, label *string
	if e.Reason != "" {
		r := clip(e.Reason, MaxReason)
		reason = &r
	}
	if e.TargetLabel != "" {
		l := clip(e.TargetLabel, MaxLabel)
		label = &l
	}
	if e.ActorID == nil {
		_, err = tx.Exec(ctx, `INSERT INTO admin_audit (actor_role, action, target_type, target_id, target_label, reason, details, source)
			VALUES ('cli', $1, $2, $3, $4, $5, $6::jsonb, 'cli')`,
			e.Action, e.TargetType, e.TargetID, label, reason, string(dj))
		return err
	}
	c, _ := ctx.Value(clientKey{}).(client)
	var addr, ray *string
	if c.addr != "" {
		addr = &c.addr
	}
	if c.ray != "" {
		ray = &c.ray
	}
	tag, err := tx.Exec(ctx, `INSERT INTO admin_audit (actor_id, actor_handle, actor_role, action, target_type, target_id,
			target_label, reason, details, source, client_addr, cf_ray)
		SELECT u.id, u.handle, u.role, $2, $3, $4, $5, $6, $7::jsonb, 'web', $8, $9 FROM users u WHERE u.id = $1::uuid`,
		*e.ActorID, e.Action, e.TargetType, e.TargetID, label, reason, string(dj), addr, ray)
	if err == nil && tag.RowsAffected() != 1 {
		return errors.New("audit: the acting account does not exist")
	}
	return err
}
