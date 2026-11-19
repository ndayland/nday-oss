package site

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/model"
)

// Stage codes, in lifecycle order. Index i of Slots/StageInfos is stage
// rank i+1.
var StageInfos = []StageInfo{
	{Type: model.EventDisclosed, Code: "DIS", Rank: 1, Alias: "disclosed"},
	{Type: model.EventPatchReleased, Code: "PAT", Rank: 2, Alias: "patch"},
	{Type: model.EventAnalysisPublished, Code: "ANA", Rank: 3, Alias: "analysis"},
	{Type: model.EventPocPublished, Code: "POC", Rank: 4, Alias: "poc"},
	{Type: model.EventExploitedInWild, Code: "ITW", Rank: 5, Alias: "exploited"},
	{Type: model.EventKevAdded, Code: "KEV", Rank: 6, Alias: "kev"},
}

// StageInfo describes one lifecycle stage (= event type).
type StageInfo struct {
	Type  string // event type, e.g. "patch_released"
	Code  string // three-letter code, e.g. "PAT"
	Rank  int    // 1..6
	Alias string // short name accepted by ParseStage, e.g. "patch"
}

// StageCode returns the three-letter code of an event type ("" if unknown).
func StageCode(eventType string) string {
	if i := stageIndex(eventType); i >= 0 {
		return StageInfos[i].Code
	}
	return ""
}

func stageIndex(eventType string) int {
	for i, s := range StageInfos {
		if s.Type == eventType {
			return i
		}
	}
	return -1
}

// ParseStage accepts a full event type ("patch_released"), a short alias
// ("patch", "analysis", "poc", "exploited", "kev", "disclosed") or a code
// ("PAT"), case-insensitively, and returns the event type.
func ParseStage(s string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	for _, st := range StageInfos {
		if t == st.Type || t == st.Alias || t == strings.ToLower(st.Code) {
			return st.Type, nil
		}
	}
	return "", &InputError{Param: "min_stage", Msg: fmt.Sprintf("unknown stage %q (use disclosed, patch, analysis, poc, exploited, kev or the full event type)", s)}
}

// Slot states.
const (
	SlotNone    = "none"    // no event of this type
	SlotKnown   = "known"   // happened; earliest effective time known
	SlotUnknown = "unknown" // happened; all its events have unknown time
	SlotImplied = "implied" // ITW only: no exploited_in_wild event but in KEV
)

// Time precisions of an event (and of a transition).
const (
	PrecisionDay      = "day"      // detail.precision = "day": only the UTC date is meaningful
	PrecisionExact    = "exact"    // occurred_at given by the source
	PrecisionObserved = "observed" // no source time; observed live by nday (effective time = observed_at)
	PrecisionUnknown  = "unknown"  // no source time and bulk-imported: time unknown
)

// EventPrecision is the precision rule: "day" when detail.precision is
// "day"; else "exact" when occurred_at is set; else "observed" when the
// event was observed live (is_backfill false); else "unknown".
func EventPrecision(occurredAt *time.Time, isBackfill bool, detailPrecision *string) string {
	switch {
	case detailPrecision != nil && *detailPrecision == "day":
		return PrecisionDay
	case occurredAt != nil:
		return PrecisionExact
	case !isBackfill:
		return PrecisionObserved
	default:
		return PrecisionUnknown
	}
}

// Slot is one of the six lifecycle positions of a vulnerability.
type Slot struct {
	Code  string `json:"code"`  // DIS PAT ANA POC ITW KEV
	Type  string `json:"type"`  // event type
	State string `json:"state"` // none | known | unknown | implied
	// At: earliest effective time of the type's events (state known only).
	At *time.Time `json:"at"`
	// NotAfter: upper bound of an implied slot = the KEV time (null if the
	// KEV time is unknown or the slot is not implied).
	NotAfter *time.Time `json:"not_after"`
	// ImpliedBy: event type the implied state is derived from ("kev_added").
	ImpliedBy *string `json:"implied_by"`
	// Latest: this slot is the vulnerability's last transition (at most one).
	Latest bool `json:"latest"`
}

// SlotInput is what the slot rules need per event type (index = rank-1).
type SlotInput struct {
	Exists  [6]bool
	FirstAt [6]*time.Time // MIN(effective_at) over the type's events; nil if all unknown
	Latest  string        // last_transition_type, "" if none
}

// ComputeSlots applies the slot rules: none / known / unknown, and ITW
// "implied" when there is no exploited_in_wild event but a kev_added event
// exists (its upper bound is the KEV time).
func ComputeSlots(in SlotInput) []Slot {
	out := make([]Slot, 6)
	for i, st := range StageInfos {
		s := Slot{Code: st.Code, Type: st.Type, State: SlotNone, Latest: in.Latest == st.Type}
		switch {
		case in.Exists[i] && in.FirstAt[i] != nil:
			s.State = SlotKnown
			s.At = utcPtr(in.FirstAt[i])
		case in.Exists[i]:
			s.State = SlotUnknown
		}
		out[i] = s
	}
	const itw, kev = 4, 5
	if !in.Exists[itw] && in.Exists[kev] {
		out[itw].State = SlotImplied
		out[itw].NotAfter = utcPtr(in.FirstAt[kev])
		out[itw].ImpliedBy = strPtr(model.EventKevAdded)
	}
	return out
}

// CalendarDays is the whole number of calendar days (UTC dates) from a to
// b; nil if either is nil. 2026-11-04T21:16Z -> 2026-11-09T00:00Z is 5.
func CalendarDays(a, b *time.Time) *int {
	if a == nil || b == nil {
		return nil
	}
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	da := time.Date(ay, am, ad, 0, 0, 0, 0, time.UTC)
	db := time.Date(by, bm, bd, 0, 0, 0, 0, time.UTC)
	n := int(db.Sub(da).Hours() / 24)
	return &n
}

// Bounds of the hot-list window.
const (
	MinSince = time.Hour
	MaxSince = 366 * 24 * time.Hour
)

var sinceRe = regexp.MustCompile(`^([0-9]{1,4})([hd])$`)

// ParseSince parses "24h", "7d", "30d"-style windows (hours or days, 1h to
// 366d).
func ParseSince(s string) (time.Duration, error) {
	m := sinceRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, &InputError{Param: "since", Msg: fmt.Sprintf("bad duration %q, use e.g. 24h, 7d or 30d", s)}
	}
	n, _ := strconv.Atoi(m[1])
	unit := time.Hour
	if m[2] == "d" {
		unit = 24 * time.Hour
	}
	d := time.Duration(n) * unit
	if d < MinSince || d > MaxSince {
		return 0, &InputError{Param: "since", Msg: fmt.Sprintf("duration %q out of range (1h to 366d)", s)}
	}
	return d, nil
}

// FormatSince renders a window as ParseSince accepts it ("30d", "36h").
func FormatSince(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
}

var cveInputRe = regexp.MustCompile(`^(?i)cve-([0-9]{4})-([0-9]{4,19})$`)

// ParseCVEID canonicalises a CVE id given in any case ("cve-2026-102895"
// -> "CVE-2026-102895"). ok is false if s is not a CVE id.
func ParseCVEID(s string) (string, bool) {
	m := cveInputRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return "CVE-" + m[1] + "-" + m[2], true
}

// ghsaIDRe is a GitHub advisory id in any case, with the alphabet GitHub
// uses for them (no vowels, no 0, 1, 2 lookalikes besides 2..9).
var ghsaIDRe = regexp.MustCompile(`^(?i)ghsa(-[23456789cfghjmpqrvwx]{4}){3}$`)

// ParseGHSAID canonicalises a GitHub advisory id given in any case
// ("ghsa-GPWC-27cw-rh9r" -> "GHSA-gpwc-27cw-rh9r", the form vuln and
// vuln_alias store). ok is false if s is not a GHSA id.
func ParseGHSAID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !ghsaIDRe.MatchString(s) {
		return "", false
	}
	return "GHSA" + strings.ToLower(s[4:]), true
}

// ParseVulnID canonicalises a vulnerability id: a CVE id (ParseCVEID) or,
// for an advisory without a CVE, its GHSA id (ParseGHSAID). The CVE id is
// the main id; a GHSA id names a vulnerability only until it gets a CVE, and
// after that is an alias of it. ok is false if s is neither.
func ParseVulnID(s string) (string, bool) {
	if id, ok := ParseCVEID(s); ok {
		return id, true
	}
	return ParseGHSAID(s)
}

// BadVulnIDMsg is the *InputError message for an id ParseVulnID rejects.
const BadVulnIDMsg = "not a vulnerability id (expected CVE-YYYY-NNNN... or GHSA-xxxx-xxxx-xxxx)"

// IsGHSAID reports whether id (canonical, from ParseVulnID) is a GHSA id.
func IsGHSAID(id string) bool { return strings.HasPrefix(id, "GHSA-") }

// InputError is a caller error (bad parameter); HTTP maps it to 400.
type InputError struct {
	Param string
	Msg   string
}

func (e *InputError) Error() string { return e.Param + ": " + e.Msg }

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func strPtr(s string) *string { return &s }
