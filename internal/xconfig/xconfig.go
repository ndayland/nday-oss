// Package xconfig is the database-backed configuration of the xposts
// collector (internal/collector/xposts): the account allowlist (table
// x_accounts) and the runtime knobs (table x_settings), both created by
// migrations/0008_xposts.sql; and the allowlist candidates (candidates.go,
// migrations/0019_xposts_links_candidates.sql).
//
// These plain functions are the only SQL for those tables. The CLI
// (nday x-accounts-*, nday x-settings) and the collector use them, and the
// admin backend should call them too instead of writing its own SQL. Every
// function takes a DB, satisfied by *pgx.Conn and pgx.Tx, so a caller can
// run them inside its own transaction (e.g. together with an audit row).
//
// Secrets never live here: the bearer token (NDAY_X_BEARER_TOKEN) is a
// database setting (internal/settings, sealed in app_settings) or an
// environment variable; see docs/settings.md.
package xconfig

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrNotFound: no account with that user id.
var ErrNotFound = errors.New("xconfig: account not found")

// ------------------------------------------------------------------ accounts

// MaxNoteLen is the x_accounts.note limit in characters.
const MaxNoteLen = 500

var (
	userIDRe = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	handleRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`)
)

// ValidUserID reports whether s is a numeric X user id as stored (decimal,
// no leading zero, at most 19 digits) — the x_accounts.user_id CHECK.
func ValidUserID(s string) bool { return userIDRe.MatchString(s) }

// ValidHandle reports whether s is an X handle without '@' (1..15 of
// A-Z a-z 0-9 _) — the x_accounts.handle CHECK.
func ValidHandle(s string) bool { return handleRe.MatchString(s) }

// Account is one x_accounts row.
type Account struct {
	UserID    string
	Handle    string
	Note      string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
	// Name and Description are the display name and the profile
	// description on X as last looked up (nil: not known).
	Name, Description *string
}

const accountCols = `user_id, handle, note, enabled, created_at, updated_at, name, description`

// numeric order of decimal ids without leading zeros
const accountOrder = ` ORDER BY char_length(user_id), user_id`

func scanAccounts(rows pgx.Rows) ([]Account, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Account, error) {
		var a Account
		err := r.Scan(&a.UserID, &a.Handle, &a.Note, &a.Enabled, &a.CreatedAt, &a.UpdatedAt, &a.Name, &a.Description)
		a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
		return a, err
	})
}

// ListAccounts returns every account (enabled or not), by numeric user id.
func ListAccounts(ctx context.Context, db DB) ([]Account, error) {
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts`+accountOrder)
	if err != nil {
		return nil, err
	}
	return scanAccounts(rows)
}

// handleContains is the search condition on $1: true for every row when $1
// is empty, else a case-insensitive substring match on the handle.
// strpos compares literally, so % _ and \ in the term are plain characters
// (no LIKE pattern, nothing to escape).
const handleContains = ` WHERE ($1 = '' OR strpos(lower(handle), lower($1)) > 0)`

// CountAccounts returns how many accounts have a handle containing q
// (case-insensitive, literal); q == "" counts every account.
func CountAccounts(ctx context.Context, db DB, q string) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM x_accounts`+handleContains, q).Scan(&n)
	return n, err
}

// SearchAccounts returns at most limit accounts whose handle contains q
// (as CountAccounts), skipping the first offset, in ListAccounts' order.
func SearchAccounts(ctx context.Context, db DB, q string, limit, offset int) ([]Account, error) {
	if limit < 0 || offset < 0 {
		return nil, fmt.Errorf("xconfig: negative limit %d or offset %d", limit, offset)
	}
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts`+handleContains+accountOrder+` LIMIT $2 OFFSET $3`,
		q, limit, offset)
	if err != nil {
		return nil, err
	}
	return scanAccounts(rows)
}

// ListEnabledAccounts returns the enabled accounts, by numeric user id
// (what the collector searches).
func ListEnabledAccounts(ctx context.Context, db DB) ([]Account, error) {
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts WHERE enabled`+accountOrder)
	if err != nil {
		return nil, err
	}
	return scanAccounts(rows)
}

// GetAccount returns one account or ErrNotFound.
func GetAccount(ctx context.Context, db DB, userID string) (Account, error) {
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts WHERE user_id = $1`, userID)
	if err != nil {
		return Account{}, err
	}
	as, err := scanAccounts(rows)
	if err != nil {
		return Account{}, err
	}
	if len(as) == 0 {
		return Account{}, ErrNotFound
	}
	return as[0], nil
}

// UpsertResult says what UpsertAccount did.
type UpsertResult string

const (
	Inserted  UpsertResult = "inserted"
	Updated   UpsertResult = "updated"
	Unchanged UpsertResult = "unchanged"
)

func validateAccount(userID, handle, note string) error {
	if !ValidUserID(userID) {
		return fmt.Errorf("invalid X user id %q (decimal digits, no leading zero, at most 19)", userID)
	}
	return validateHandleNote(userID, handle, note)
}

// validateHandleNote checks the handle and the note (label names the line's
// account in the error).
func validateHandleNote(label, handle, note string) error {
	if !ValidHandle(handle) {
		return fmt.Errorf("invalid X handle %q (1-15 of A-Z a-z 0-9 _ , without @)", handle)
	}
	if !utf8.ValidString(note) || utf8.RuneCountInString(note) > MaxNoteLen || strings.ContainsAny(note, "\x00\r\n") {
		return fmt.Errorf("invalid note for %s: at most %d characters, one line", label, MaxNoteLen)
	}
	return nil
}

// UpsertAccount inserts the account (enabled) or, if the user id exists,
// sets its handle and — only when note is non-empty — its note. It never
// changes `enabled` of an existing row (a disabled account stays disabled
// when a file is re-imported) and never deletes anything.
func UpsertAccount(ctx context.Context, db DB, userID, handle, note string) (UpsertResult, error) {
	if err := validateAccount(userID, handle, note); err != nil {
		return "", err
	}
	var inserted bool
	err := db.QueryRow(ctx, `INSERT INTO x_accounts (user_id, handle, note) VALUES ($1, $2, $3)
        ON CONFLICT (user_id) DO UPDATE SET
            handle = EXCLUDED.handle,
            note = CASE WHEN EXCLUDED.note = '' THEN x_accounts.note ELSE EXCLUDED.note END,
            updated_at = now()
        WHERE x_accounts.handle IS DISTINCT FROM EXCLUDED.handle
           OR (EXCLUDED.note <> '' AND x_accounts.note IS DISTINCT FROM EXCLUDED.note)
        RETURNING (xmax = 0)`, userID, handle, note).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return Unchanged, nil
	}
	if err != nil {
		return "", err
	}
	if inserted {
		return Inserted, nil
	}
	return Updated, nil
}

// SetAccountEnabled enables or disables an account; ErrNotFound if absent.
func SetAccountEnabled(ctx context.Context, db DB, userID string, enabled bool) error {
	tag, err := db.Exec(ctx, `UPDATE x_accounts SET enabled = $2,
            updated_at = CASE WHEN enabled = $2 THEN updated_at ELSE now() END
        WHERE user_id = $1`, userID, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FileAccount is one line of an import file. UserID is "" on a
// handle-only line until the caller resolves it (internal/xlookup).
type FileAccount struct {
	Line   int
	UserID string
	Handle string
	Note   string
	// Profile is set when the id was looked up on X (never parsed).
	Profile *Profile
}

// Profile is an account's display name and profile description on X.
type Profile struct {
	Name, Description string
}

// Profile limits as stored (runes): X allows 50 and 160.
const (
	MaxProfileName = 200
	MaxProfileDesc = 2000
)

// SetProfile stores the profile of a listed account (p nil: looked up, not
// found under that id: the stored profile is kept) and marks it looked up
// now. Text is cut to the stored limits. ErrNotFound if not listed. It
// does not change updated_at (the account's own fields did not change).
func SetProfile(ctx context.Context, db DB, userID string, p *Profile) error {
	var tag pgconn.CommandTag
	var err error
	if p == nil {
		tag, err = db.Exec(ctx, `UPDATE x_accounts SET profile_at = now() WHERE user_id = $1`, userID)
	} else {
		tag, err = db.Exec(ctx, `UPDATE x_accounts SET name = $2, description = $3, profile_at = now() WHERE user_id = $1`,
			userID, cutRunes(p.Name, MaxProfileName), cutRunes(p.Description, MaxProfileDesc))
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ProfileMaxAge is how long a looked-up profile is left alone: only
// accounts never looked up or looked up longer ago are due again.
const ProfileMaxAge = 24 * time.Hour

// ProfileTodo lists up to limit listed accounts due for a profile lookup
// (never looked up, or longer ago than ProfileMaxAge): never looked up
// first, then the oldest lookup, by id.
func ProfileTodo(ctx context.Context, db DB, limit int) ([]Account, error) {
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts
		WHERE profile_at IS NULL OR profile_at < now() - $2::interval
		ORDER BY profile_at NULLS FIRST, char_length(user_id), user_id LIMIT $1`, limit, ProfileMaxAge.String())
	if err != nil {
		return nil, err
	}
	return scanAccounts(rows)
}

// CountProfileMissing is the number of listed accounts never looked up for
// their profile.
func CountProfileMissing(ctx context.Context, db DB) (n int, err error) {
	err = db.QueryRow(ctx, `SELECT count(*)::int FROM x_accounts WHERE profile_at IS NULL`).Scan(&n)
	return n, err
}

// cutRunes is profile text as stored: valid UTF-8, without NUL and the
// other C0 controls, DEL, C1 controls and the bidi embedding, override,
// isolate and mark characters (tab and line breaks become spaces: the
// pages show the text on one line or as one paragraph), then at most n
// runes. PostgreSQL text cannot hold NUL, so one hostile profile would
// otherwise fail every write of it.
func cutRunes(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return -1
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// ParseAccountsFile reads the import format (deploy/x-accounts.example.txt):
//
//	<numeric user id> <handle>   # optional note
//	@<handle>                    # optional note: the id is looked up
//	<handle>                     # the same, when the handle has a letter or _
//
// A line with two fields is an id and a handle, exactly as before. A line
// with one field is a handle whose id the importer looks up; because
// handles can be all digits, a one-field line made only of digits is
// refused as ambiguous and must be written @<digits> (an id alone is never
// accepted: an id always comes with its handle). Blank lines and lines
// starting with '#' are ignored; a leading '@' on the handle is accepted and
// dropped. Any malformed line, a user id listed twice or a handle-only
// handle listed twice (in any case) is an error naming the line (nothing is
// imported then).
func ParseAccountsFile(r io.Reader) ([]FileAccount, error) {
	out, errs := ParseAccounts(r)
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return out, nil
}

// LineError is one invalid line of an import file (Line 0: the input as a
// whole, e.g. a line longer than 64 KiB).
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string {
	if e.Line == 0 {
		return e.Err.Error()
	}
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e *LineError) Unwrap() error { return e.Err }

// ParseAccounts is ParseAccountsFile reporting every invalid line (the
// admin page shows them all); the accounts are only meaningful when there
// is no error.
func ParseAccounts(r io.Reader) ([]FileAccount, []*LineError) {
	var out []FileAccount
	var errs []*LineError
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		body, note, _ := strings.Cut(line, "#")
		body, note = strings.TrimSpace(body), strings.TrimSpace(note)
		if body == "" {
			continue
		}
		f := strings.Fields(body)
		if len(f) == 1 {
			h := strings.TrimPrefix(f[0], "@")
			if h == f[0] && allDigits(h) {
				errs = append(errs, &LineError{n, fmt.Errorf("%q alone is ambiguous: write \"<numeric user id> <handle>\", or @%s for a handle that is all digits", h, h)})
				continue
			}
			if err := validateHandleNote("@"+h, h, note); err != nil {
				errs = append(errs, &LineError{n, err})
				continue
			}
			k := "@" + strings.ToLower(h)
			if prev, dup := seen[k]; dup {
				errs = append(errs, &LineError{n, fmt.Errorf("handle @%s already on line %d", h, prev)})
				continue
			}
			seen[k] = n
			out = append(out, FileAccount{Line: n, Handle: h, Note: note})
			continue
		}
		if len(f) != 2 {
			errs = append(errs, &LineError{n, fmt.Errorf("want \"<numeric user id> <handle>  # note\" or \"@<handle>  # note\", got %q", line)})
			continue
		}
		a := FileAccount{Line: n, UserID: f[0], Handle: strings.TrimPrefix(f[1], "@"), Note: note}
		if err := validateAccount(a.UserID, a.Handle, a.Note); err != nil {
			errs = append(errs, &LineError{n, err})
			continue
		}
		if prev, dup := seen[a.UserID]; dup {
			errs = append(errs, &LineError{n, fmt.Errorf("user id %s already on line %d", a.UserID, prev)})
			continue
		}
		seen[a.UserID] = n
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, &LineError{0, err})
	}
	return out, errs
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// ErrExists: InsertAccount found the user id already listed.
var ErrExists = errors.New("xconfig: account already listed")

// InsertAccount adds a new (enabled) account; ErrExists when the user id is
// already listed (nothing is changed then).
func InsertAccount(ctx context.Context, db DB, userID, handle, note string) error {
	if err := validateAccount(userID, handle, note); err != nil {
		return err
	}
	tag, err := db.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, note) VALUES ($1, $2, $3)
        ON CONFLICT (user_id) DO NOTHING`, userID, handle, note)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExists
	}
	return nil
}

// GetAccountForUpdate is GetAccount that also locks the row until the end
// of the caller's transaction (db must be a pgx.Tx).
func GetAccountForUpdate(ctx context.Context, db DB, userID string) (Account, error) {
	rows, err := db.Query(ctx, `SELECT `+accountCols+` FROM x_accounts WHERE user_id = $1 FOR UPDATE`, userID)
	if err != nil {
		return Account{}, err
	}
	as, err := scanAccounts(rows)
	if err != nil {
		return Account{}, err
	}
	if len(as) == 0 {
		return Account{}, ErrNotFound
	}
	return as[0], nil
}

// UpdateAccount sets the handle and the note exactly (an empty note clears
// it, unlike UpsertAccount); it never changes `enabled`. changed is false
// when both were already as given; ErrNotFound if the id is absent.
func UpdateAccount(ctx context.Context, db DB, userID, handle, note string) (changed bool, err error) {
	if err := validateAccount(userID, handle, note); err != nil {
		return false, err
	}
	var exists bool
	err = db.QueryRow(ctx, `WITH u AS (
            UPDATE x_accounts SET handle = $2, note = $3, updated_at = now()
            WHERE user_id = $1 AND (handle <> $2 OR note <> $3) RETURNING 1)
        SELECT EXISTS (SELECT 1 FROM u), EXISTS (SELECT 1 FROM x_accounts WHERE user_id = $1)`,
		userID, handle, note).Scan(&changed, &exists)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrNotFound
	}
	return changed, nil
}

// LockSettings serialises read-modify-write of x_settings until the end of
// the caller's transaction (db must be a pgx.Tx): LoadSettings after it sees
// the latest committed row.
func LockSettings(ctx context.Context, db DB) error {
	_, err := db.Exec(ctx, `LOCK TABLE x_settings IN SHARE ROW EXCLUSIVE MODE`)
	return err
}

// Equal reports whether two stored rows hold the same values (UpdatedAt
// ignored).
func (s Stored) Equal(o Stored) bool {
	eqB := func(a, b *bool) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	eqI := func(a, b *int) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return eqB(s.Enabled, o.Enabled) && eqI(s.MaxPosts, o.MaxPosts) && eqI(s.MaxRequests, o.MaxRequests) &&
		eqI(s.BootstrapDays, o.BootstrapDays) && eqI(s.MaxQueryLength, o.MaxQueryLength)
}

// Bound is the inclusive hard range of a numeric setting.
type Bound struct {
	Name     string
	Min, Max int
	Default  int
}

// Bounds lists the numeric settings with their ranges and defaults, in
// display order (for forms and documentation).
var Bounds = []Bound{
	{"max_posts", MinMaxPosts, MaxMaxPosts, Defaults.MaxPosts},
	{"max_requests", MinMaxRequests, MaxMaxRequests, Defaults.MaxRequests},
	{"bootstrap_days", MinBootstrapDays, MaxBootstrapDays, Defaults.BootstrapDays},
	{"max_query_length", MinMaxQueryLength, MaxMaxQueryLength, Defaults.MaxQueryLength},
}

// ------------------------------------------------------------------ settings

// Settings are the effective runtime knobs of one run.
type Settings struct {
	Enabled        bool
	MaxPosts       int // posts returned (billed) per run
	MaxRequests    int // HTTP requests per run
	BootstrapDays  int // first-run window
	MaxQueryLength int // characters per search query
}

// Defaults apply to every column that is NULL (or when there is no row).
var Defaults = Settings{Enabled: true, MaxPosts: 500, MaxRequests: 20, BootstrapDays: 7, MaxQueryLength: 512}

// Hard bounds (inclusive), identical to the x_settings CHECKs. Values read
// from the database are clamped into them even if the CHECKs were dropped.
const (
	MinMaxPosts, MaxMaxPosts             = 10, 5000 // max_results is 10..100 per page
	MinMaxRequests, MaxMaxRequests       = 1, 100
	MinBootstrapDays, MaxBootstrapDays   = 1, 7 // recent search covers 7 days
	MinMaxQueryLength, MaxMaxQueryLength = 64, 4096
)

// Stored is the x_settings row as stored: nil = default.
type Stored struct {
	Enabled        *bool
	MaxPosts       *int
	MaxRequests    *int
	BootstrapDays  *int
	MaxQueryLength *int
	UpdatedAt      *time.Time // nil when there is no row
}

// LoadSettings reads the stored row (all nil when absent).
func LoadSettings(ctx context.Context, db DB) (Stored, error) {
	var s Stored
	var at time.Time
	err := db.QueryRow(ctx, `SELECT enabled, max_posts, max_requests, bootstrap_days, max_query_length, updated_at
        FROM x_settings WHERE id = 1`).Scan(&s.Enabled, &s.MaxPosts, &s.MaxRequests, &s.BootstrapDays, &s.MaxQueryLength, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return Stored{}, nil
	}
	if err != nil {
		return Stored{}, err
	}
	at = at.UTC()
	s.UpdatedAt = &at
	return s, nil
}

type bound struct {
	name     string
	min, max int
}

var (
	bMaxPosts       = bound{"max_posts", MinMaxPosts, MaxMaxPosts}
	bMaxRequests    = bound{"max_requests", MinMaxRequests, MaxMaxRequests}
	bBootstrapDays  = bound{"bootstrap_days", MinBootstrapDays, MaxBootstrapDays}
	bMaxQueryLength = bound{"max_query_length", MinMaxQueryLength, MaxMaxQueryLength}
)

func (b bound) clamp(v *int, def int, warn *[]string) int {
	if v == nil {
		return def
	}
	switch {
	case *v < b.min:
		*warn = append(*warn, fmt.Sprintf("x_settings.%s=%d is below %d; using %d", b.name, *v, b.min, b.min))
		return b.min
	case *v > b.max:
		*warn = append(*warn, fmt.Sprintf("x_settings.%s=%d is above %d; using %d", b.name, *v, b.max, b.max))
		return b.max
	}
	return *v
}

func (b bound) check(v *int) error {
	if v != nil && (*v < b.min || *v > b.max) {
		return fmt.Errorf("%s must be %d..%d, got %d", b.name, b.min, b.max, *v)
	}
	return nil
}

// Effective applies defaults and clamps out-of-range values into the hard
// bounds; each clamp is reported in warnings.
func (s Stored) Effective() (Settings, []string) {
	var w []string
	e := Defaults
	if s.Enabled != nil {
		e.Enabled = *s.Enabled
	}
	e.MaxPosts = bMaxPosts.clamp(s.MaxPosts, Defaults.MaxPosts, &w)
	e.MaxRequests = bMaxRequests.clamp(s.MaxRequests, Defaults.MaxRequests, &w)
	e.BootstrapDays = bBootstrapDays.clamp(s.BootstrapDays, Defaults.BootstrapDays, &w)
	e.MaxQueryLength = bMaxQueryLength.clamp(s.MaxQueryLength, Defaults.MaxQueryLength, &w)
	return e, w
}

// Validate rejects out-of-range values (what SaveSettings writes).
func (s Stored) Validate() error {
	for _, c := range []struct {
		b bound
		v *int
	}{{bMaxPosts, s.MaxPosts}, {bMaxRequests, s.MaxRequests}, {bBootstrapDays, s.BootstrapDays}, {bMaxQueryLength, s.MaxQueryLength}} {
		if err := c.b.check(c.v); err != nil {
			return err
		}
	}
	return nil
}

// GetSettings is LoadSettings + Effective.
func GetSettings(ctx context.Context, db DB) (Settings, []string, error) {
	s, err := LoadSettings(ctx, db)
	if err != nil {
		return Settings{}, nil, err
	}
	e, w := s.Effective()
	return e, w, nil
}

// SaveSettings validates s and replaces the stored row with it (nil fields
// are stored as NULL = default; UpdatedAt is ignored and set to now()).
// Callers that change one knob should LoadSettings, modify, SaveSettings,
// inside one transaction if they race with other writers.
func SaveSettings(ctx context.Context, db DB, s Stored) error {
	if err := s.Validate(); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `INSERT INTO x_settings (id, enabled, max_posts, max_requests, bootstrap_days, max_query_length, updated_at)
        VALUES (1, $1, $2, $3, $4, $5, now())
        ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, max_posts = EXCLUDED.max_posts,
            max_requests = EXCLUDED.max_requests, bootstrap_days = EXCLUDED.bootstrap_days,
            max_query_length = EXCLUDED.max_query_length, updated_at = now()`,
		s.Enabled, s.MaxPosts, s.MaxRequests, s.BootstrapDays, s.MaxQueryLength)
	return err
}
