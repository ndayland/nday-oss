package ghrepo

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/pagefetch"
)

// MinForkStars: a fork with fewer stars than this is not collected
// (docs/github.md "Skipped forks"). Search doesn't store it at all; a row
// that already exists for it (a post link, or anything asked by id or
// name) stays as it is but is left out of the review queue and the public
// pages while nobody decided about it (skippedForkSQL). A fork that gets
// to this many stars comes in normally on its next refresh or search hit.
const MinForkStars = 10

// SkippedFork reports whether r is a fork with fewer than MinForkStars
// stars. Unknown stars never skip.
func (r *Repo) SkippedFork() bool {
	return r.Fork && r.StarsKnown && r.Stars < MinForkStars
}

// skippedForkSQL: row r is a skipped fork nobody decided about (status
// unverified, status_by NULL; an admin's, the post rule's or a trusted
// account's decision always wins). A NULL is_fork or stars never skips.
// Read-time only: the row keeps its state and refresh cadence, so when its
// stars reach MinForkStars it shows up again with no write. The 10 is
// MinForkStars (a const string has to spell it; a test checks they match).
const skippedForkSQL = `COALESCE(r.status = 'unverified' AND r.status_by IS NULL AND r.is_fork AND r.stars < 10, false)`

// SkippedForkSQL is skippedForkSQL for internal/site (the row must be
// aliased r).
const SkippedForkSQL = skippedForkSQL

// Field caps (runes), as the CHECKs of migrations/0023_github_repo.sql.
const (
	maxDescription = 500
	maxLanguage    = 64
	maxTopics      = 20
	maxETag        = 200
)

// Repo is the cleaned metadata of a repository from GET /repos/{owner}/{repo}.
type Repo struct {
	ID          int64
	FullName    string // as GitHub returns it
	OwnerLogin  string
	OwnerID     int64  // the owner's numeric GitHub id; 0 = unknown
	OwnerType   string // "User", "Organization", "Bot" or "" (anything else)
	Description string // cleaned, cut; "" = none
	Stars       int
	StarsKnown  bool // stargazers_count was in the answer (false: Stars is 0 and stored as NULL)
	Forks       int
	Language    string
	Topics      []string
	Fork        bool
	Archived    bool
	CreatedAt   *time.Time
	PushedAt    *time.Time
	// Public is false for a private or internal repository (never stored).
	Public bool
}

// apiRepo is the part of the API response that is read. Pointers tell an
// absent field from a zero one; json decoding rejects wrong types.
type apiRepo struct {
	ID       *int64  `json:"id"`
	FullName *string `json:"full_name"`
	Owner    *struct {
		Login *string         `json:"login"`
		ID    json.RawMessage `json:"id"` // optional: a wrong type only drops the id
		Type  *string         `json:"type"`
	} `json:"owner"`
	Private     *bool           `json:"private"`
	Visibility  *string         `json:"visibility"`
	Description *string         `json:"description"`
	Stars       *int64          `json:"stargazers_count"`
	Forks       *int64          `json:"forks_count"`
	Language    *string         `json:"language"`
	Topics      json.RawMessage `json:"topics"`
	Fork        *bool           `json:"fork"`
	Archived    *bool           `json:"archived"`
	CreatedAt   *string         `json:"created_at"`
	PushedAt    *string         `json:"pushed_at"`
}

// errMalformed is a response body that is not a usable repository.
var errMalformed = errors.New("ghrepo: malformed repository response")

var topicRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)

// DecodeRepo parses and cleans a repository response. Required: id > 0, a
// valid full_name, fork and archived booleans; optional fields with the
// wrong type, or text that does not survive cleaning, are dropped; a
// structurally wrong body is errMalformed.
func DecodeRepo(body []byte) (*Repo, error) {
	var a apiRepo
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, errors.Join(errMalformed, err)
	}
	if a.ID == nil || *a.ID <= 0 || a.FullName == nil || !ValidFullName(*a.FullName) || a.Fork == nil || a.Archived == nil {
		return nil, errMalformed
	}
	r := &Repo{ID: *a.ID, FullName: *a.FullName, Fork: *a.Fork, Archived: *a.Archived}
	r.Public = a.Private != nil && !*a.Private && (a.Visibility == nil || *a.Visibility == "public")
	if a.Owner != nil && a.Owner.Login != nil && ownerRe.MatchString(*a.Owner.Login) {
		r.OwnerLogin = *a.Owner.Login
		// the id only goes with a login we kept: it's what the login is matched by
		var id int64
		if len(a.Owner.ID) > 0 && json.Unmarshal(a.Owner.ID, &id) == nil && id > 0 {
			r.OwnerID = id
		}
	}
	if a.Owner != nil && a.Owner.Type != nil {
		switch *a.Owner.Type {
		case "User", "Organization", "Bot":
			r.OwnerType = *a.Owner.Type
		}
	}
	if a.Description != nil {
		r.Description = pagefetch.Cut(pagefetch.CleanText(*a.Description), maxDescription)
	}
	if a.Language != nil {
		r.Language = pagefetch.Cut(pagefetch.CleanText(*a.Language), maxLanguage)
	}
	r.Stars, r.Forks = clampCount(a.Stars), clampCount(a.Forks)
	r.StarsKnown = a.Stars != nil
	var topics []string
	if len(a.Topics) > 0 && json.Unmarshal(a.Topics, &topics) == nil {
		seen := map[string]bool{}
		for _, t := range topics {
			if topicRe.MatchString(t) && !seen[t] && len(r.Topics) < maxTopics {
				seen[t] = true
				r.Topics = append(r.Topics, t)
			}
		}
	}
	r.CreatedAt, r.PushedAt = parseTime(a.CreatedAt), parseTime(a.PushedAt)
	return r, nil
}

func clampCount(p *int64) int {
	switch {
	case p == nil || *p < 0:
		return 0
	case *p > math.MaxInt32:
		return math.MaxInt32
	}
	return int(*p)
}

func parseTime(p *string) *time.Time {
	if p == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *p)
	if err != nil || t.Year() < 2007 || t.Year() > 9999 {
		return nil
	}
	t = t.UTC()
	return &t
}

// CVE association bases (github_repo_cve.basis).
const (
	BasisName        = "name"
	BasisDescription = "description"
	BasisTopic       = "topic"
	BasisPost        = "post"
)

// cveText prepares a field for xposts.ExtractCVEs / ExtractGHSAs
// (word-bounded): '_' is a word character, so "CVE-2024-1234_poc" would not
// match; it becomes a space.
func cveText(s string) string { return strings.ReplaceAll(s, "_", " ") }

// Associations returns the vulnerability ids in the repository's name,
// description and topics, by basis (the same id may appear under several
// bases): CVE ids (xposts.ExtractCVEs, upper case) and GHSA ids
// (xposts.ExtractGHSAs: whatever the case they are written in, in the
// site's canonical form "GHSA-" plus three lower-case groups, the form
// vuln.cve_id and vuln_alias use). Ids are returned as found: which
// vulnerability a GHSA id belongs to is resolved when read.
func (r *Repo) Associations() map[string][]string {
	out := map[string][]string{}
	_, name, _ := strings.Cut(r.FullName, "/")
	for basis, text := range map[string]string{BasisName: name, BasisDescription: r.Description, BasisTopic: strings.Join(r.Topics, " ")} {
		text = cveText(text)
		if ids := append(xposts.ExtractCVEs(text), xposts.ExtractGHSAs(text)...); len(ids) > 0 {
			out[basis] = ids
		}
	}
	return out
}

// cleanETag keeps an ETag header that is short printable ASCII; "" otherwise.
func cleanETag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxETag {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}
