// Package model holds the plain data types shared by collectors and the
// pipeline (Go port of src/nday/models.py). No ORM, no I/O.
package model

import (
	"fmt"
	"regexp"
	"time"

	"nday.land/nday/internal/pyjson"
)

// cveIDRe is Python's CVE_ID_RE = r"CVE-\d{4}-\d{4,}" used with fullmatch.
// Python's \d on str patterns matches any Unicode decimal digit (category Nd),
// so \p{Nd} is used here to keep the exact same acceptance (see
// docs/go.md "Python quirks kept": such ids then fail the DB CHECK).
var cveIDRe = regexp.MustCompile(`^CVE-\p{Nd}{4}-\p{Nd}{4,}$`)

// IsValidCVEID is Python's is_valid_cve_id. Sources whose records are CVE
// records (cvelist, nvd, kev) keep using it: only GitHub advisories key a
// vulnerability by something else.
func IsValidCVEID(s string) bool { return cveIDRe.MatchString(s) }

// ghsaIDRe is the canonical GHSA id: "GHSA-" in upper case, then three groups
// of four characters from GitHub's alphabet, in lower case (the form GitHub's
// API sends and vuln_alias stores; migrations/0026_vuln_id_ghsa.sql checks
// the same form on vuln.cve_id). ASCII only, like Python's GHSA_ID_RE.
var ghsaIDRe = regexp.MustCompile(`^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$`)

// IsGHSAID reports whether s is a GHSA id in its canonical form.
func IsGHSAID(s string) bool { return ghsaIDRe.MatchString(s) }

// IsValidVulnID reports whether s can key a vulnerability: a CVE id (the
// main id) or, for a GitHub advisory that has no CVE yet, its GHSA id
// (docs/ghsa.md). Python's is_valid_vuln_id.
func IsValidVulnID(s string) bool { return IsValidCVEID(s) || IsGHSAID(s) }

// Event types, in lifecycle order (must match migrations/0002_vuln_state.sql).
const (
	EventDisclosed         = "disclosed"
	EventPatchReleased     = "patch_released"
	EventAnalysisPublished = "analysis_published"
	EventPocPublished      = "poc_published"
	EventExploitedInWild   = "exploited_in_wild"
	EventKevAdded          = "kev_added"
)

// EventSocialPost is a post on X mentioning the CVE (collector xposts). It is
// a discussion event, NOT a lifecycle stage: it is not in Stages, and
// vuln_state ignores it (migrations/0008_xposts.sql).
const EventSocialPost = "social_post"

// Stages lists the event types in rank order (state.STAGES in Python).
var Stages = []string{
	EventDisclosed, EventPatchReleased, EventAnalysisPublished,
	EventPocPublished, EventExploitedInWild, EventKevAdded,
}

// IsEventType reports whether t is one of the known event types.
func IsEventType(t string) bool {
	for _, s := range Stages {
		if s == t {
			return true
		}
	}
	return false
}

// RawRecord is one upstream record, verbatim.
//
// Payload is the decoded upstream JSON in the pyjson value model (decode
// upstream bytes with pyjson.Decode, never encoding/json: the content hash
// must equal Python's). SourceKey identifies it within Source.
//
// IsBackfill: set by a collector when the record was fetched on demand for a
// CVE we already knew about (NOT observed live). Events derived from it are
// stored with is_backfill=true even on an incremental run. It is not part of
// Payload, so the content hash and raw storage are unaffected.
type RawRecord struct {
	Source     string
	SourceKey  string
	Payload    any
	IsBackfill bool
}

// ContentHash is Python's content_hash(payload).
func (r RawRecord) ContentHash() (string, error) { return pyjson.ContentHash(r.Payload) }

// VulnUpsert holds the vuln fields a collector knows.
//
// Authoritative=false (stub): only fills fields that are currently NULL or
// empty; never overwrites existing non-empty values (e.g. KEV).
// Authoritative=true: non-nil values overwrite existing ones (CVE list).
// nil never erases existing data in either mode.
type VulnUpsert struct {
	CVEID         string
	Title         *string
	Description   *string
	PublishedAt   *time.Time
	ModifiedAt    *time.Time
	Authoritative bool
}

// Alias is a vuln_alias row.
type Alias struct {
	CVEID     string
	Alias     string
	AliasType string
}

// Affected is an affected row.
type Affected struct {
	CVEID   string
	Vendor  string
	Product string
}

// Event is a lifecycle event. observed_at and is_backfill are set by the
// pipeline, not the collector, so Normalize stays pure.
//
// OccurredAt: the time the SOURCE claims; nil if unknown. Never invent it.
// Detail: stored as jsonb; values must be pyjson values (pass upstream values
// through unchanged; a missing upstream key that Python reads with dict.get
// must be nil, i.e. JSON null — jsonb distinguishes null from absent).
// nil Detail is stored as {}.
// DedupeKey distinguishes several events of the same (cve, type, source);
// "" when there is one per (cve, type, source).
type Event struct {
	CVEID      string
	Type       string
	Source     string
	OccurredAt *time.Time
	URL        *string
	Detail     map[string]any
	DedupeKey  string
}

// PostNoCVE is an allowlisted X post whose text names no CVE id (collector
// xposts, Go only; table x_post_no_cve, migrations/0015_xposts_no_cve.sql).
// It references no vuln. Like Event, observed_at and is_backfill are set by
// the pipeline. AuthorHandle and Lang are nil when upstream had none.
type PostNoCVE struct {
	PostID       string
	AuthorID     string
	AuthorHandle *string
	Text         string
	Lang         *string
	PostedAt     time.Time
	URL          string
}

// PostLink is one link of a stored X post (collector xposts, Go only; table
// x_post_link, migrations/0019_xposts_links_candidates.sql). Pos is the order
// of the link in the post. A link from the API's entities has Origin "api",
// Status "ok"; a t.co link found only in the text (raw records stored before
// the collector asked for entities) has Status "pending" and nil
// ExpandedURL / FinalURL / Host, Kind "other" (the resolver fills them).
type PostLink struct {
	PostID      string
	Pos         int
	ShortURL    string
	ExpandedURL *string
	FinalURL    *string
	Host        *string
	Kind        string
	Title       *string
	Origin      string
	Status      string
}

// CandidateRef says that a stored post (PostID, by the allowlisted ReferrerID,
// posted at PostedAt) quotes, replies to or mentions UserID (Kind "quoted",
// "replied_to" or "mentioned"); table x_account_candidate_ref (Go only).
// Handle is the username the API sent, nil when absent or not a valid handle;
// display code must still check it with xconfig.ValidHandle.
type CandidateRef struct {
	UserID     string
	Handle     *string
	PostID     string
	ReferrerID string
	Kind       string
	PostedAt   time.Time
}

// Normalized is everything derived from one RawRecord.
type Normalized struct {
	Vulns    []VulnUpsert
	Aliases  []Alias
	Affected []Affected
	Events   []Event
	// PostsNoCVE, PostLinks, CandidateRefs: Go only (xposts); always empty
	// for the Python ports.
	PostsNoCVE    []PostNoCVE
	PostLinks     []PostLink
	CandidateRefs []CandidateRef
}

// Validate applies the checks Python performs in the dataclass constructors
// (__post_init__). Python raises a plain ValueError there, which is NOT a
// NormalizeError, so the pipeline treats a Validate failure as a run failure,
// exactly like Python does. Every id must be a vuln id (IsValidVulnID): a
// CVE id, or a GHSA id for an advisory that has no CVE.
func (n *Normalized) Validate() error {
	req := func(id string) error {
		if !IsValidVulnID(id) {
			return fmt.Errorf("invalid vuln id: %s", pyjson.StrRepr(id))
		}
		return nil
	}
	for _, v := range n.Vulns {
		if err := req(v.CVEID); err != nil {
			return err
		}
	}
	for _, a := range n.Aliases {
		if err := req(a.CVEID); err != nil {
			return err
		}
	}
	for _, a := range n.Affected {
		if err := req(a.CVEID); err != nil {
			return err
		}
	}
	for _, e := range n.Events {
		if err := req(e.CVEID); err != nil {
			return err
		}
		if !IsEventType(e.Type) && e.Type != EventSocialPost {
			return fmt.Errorf("invalid event type: %s", pyjson.StrRepr(e.Type))
		}
	}
	return nil
}

// CollectorState is the stored collector_state row (plus Wanted).
type CollectorState struct {
	Source        string
	Cursor        any // pyjson value decoded from the stored jsonb, nil if NULL
	LastRunAt     *time.Time
	LastStatus    *string
	LastError     *string
	LastSuccessAt *time.Time
	// Wanted is filled by the pipeline (never stored) only for collectors that
	// implement collector.WantsMissingCVEs: CVE ids present in vuln for which
	// this source has never stored a raw record, newest first, at most
	// WantedLimit(). Empty for every other collector.
	Wanted []string
}

// IsFirstRun is true until the collector has completed one successful run.
func (s CollectorState) IsFirstRun() bool { return s.LastSuccessAt == nil }

// FetchResult is what Collector.Fetch returns.
type FetchResult struct {
	Records []RawRecord
	Cursor  any // pyjson value persisted as jsonb only if the whole run succeeds; nil = SQL NULL
}

// Ptr returns a pointer to v (convenience for optional fields).
func Ptr[T any](v T) *T { return &v }
