package site

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/tags"
)

// PocSourceNames are the PoC sources counted in "n/4": the three curated
// feeds and trusted GitHub repositories (ghrepo.PoCSource, migration 0032).
var PocSourceNames = []string{"exploitdb", "metasploit", "nuclei", "github"}

// VulnDetail is everything the vulnerability page shows.
type VulnDetail struct {
	CVEID   string  `json:"cve_id"`
	Title   *string `json:"title"`
	TitleZh *string `json:"title_zh"`
	// the effective title and its origin (titles.go)
	TitleInfo
	Description *string    `json:"description"`
	SummaryZh   *string    `json:"summary_zh"`
	PublishedAt *time.Time `json:"published_at"` // CVE record datePublished
	ModifiedAt  *time.Time `json:"modified_at"`
	FirstSeenAt time.Time  `json:"first_seen_at"` // when any nday collector first saw it
	// Assigner: CNA short name from the CVE record (e.g. "GitHub_M").
	Assigner   *string    `json:"assigner"`
	IsRejected bool       `json:"is_rejected"`
	Rejection  *Rejection `json:"rejection"`
	Aliases    []Alias    `json:"aliases"`
	// Products: all affected vendor/product pairs, deduplicated
	// case-insensitively, first reported first.
	Products []Product `json:"products"`

	// Stage/StageCode: highest stage reached (from events); nil without events.
	Stage     *string `json:"stage"`
	StageCode *string `json:"stage_code"`
	// Slots computed from Events (always 6: DIS PAT ANA POC ITW KEV).
	Slots []DetailSlot `json:"slots"`
	// Transition: last arrival of a new event type (nil if no known time).
	Transition          *Transition `json:"transition"`
	DisclosedAt         *time.Time  `json:"disclosed_at"`
	DaysSinceDisclosure *int        `json:"days_since_disclosure"` // to Transition
	// State is the materialized vuln_state_mat row (what lists show; may lag
	// Events by one refresh). nil if the vuln has no events or is not yet
	// materialized.
	State *State `json:"state"`

	// Events: all events; known effective time ascending, then the ones with
	// unknown time (by stage, then id).
	Events []Event `json:"events"`

	Patches    []Patch     `json:"patches"`
	Poc        []PocSource `json:"poc"`         // always 4: exploitdb, metasploit, nuclei, github
	PocSources int         `json:"poc_sources"` // how many of the 4 have it
	KEV        *KEVFacts   `json:"kev"`
	CVSS       *CVSS       `json:"cvss"`
	SSVC       *SSVC       `json:"ssvc"`
	CWEs       []CWE       `json:"cwes"`
	RawRecords []RawLink   `json:"raw_records"`
	// Classification: CWE ids and CVSS vectors with provenance from the
	// classification layer (vuln_cwe / vuln_cvss, internal/classify; docs/nvd.md).
	// Always an object; empty lists when nothing is classified. Additive:
	// CVSS and CWEs above keep their own (event-derived) rules.
	Classification *classify.Classification `json:"classification"`
	// Tags: nday's own tags (internal/tags; docs/tags.md), each with the
	// basis it rests on; suppressed rule tags are left out. Always an array.
	Tags []tags.View `json:"tags"`
	// Credits: people, organisations and tools credited by the latest CVE
	// record (CNA container) and GitHub advisories, as written there
	// (credits.go). Always an array.
	Credits []Credit `json:"credits"`
	// DescriptionSource: the upstream record whose text Description is
	// (descsource.go); nil when no current record has that text. Not part
	// of the API.
	DescriptionSource *DescSource `json:"-"`
}

// Alias is another identifier of the vulnerability.
type Alias struct {
	Alias string `json:"alias"`
	Type  string `json:"type"` // "ghsa", ...
}

// Rejection: facts from a REJECTED CVE record, or from a withdrawn GitHub
// advisory for a vulnerability keyed by its GHSA id (DateRejected is then
// withdrawn_at; no reasons, no replacement).
type Rejection struct {
	DateRejected *string  `json:"date_rejected"` // as given by the record
	Reasons      []string `json:"reasons"`
	ReplacedBy   []string `json:"replaced_by"`
}

// DetailSlot is a Slot plus what the detail timeline needs.
type DetailSlot struct {
	Slot
	// Precision of the event giving the slot's time (known) or "unknown";
	// nil for none/implied.
	Precision *string `json:"precision"`
	// DaysSinceDisclosure: calendar days from disclosure to At (known only).
	DaysSinceDisclosure *int     `json:"days_since_disclosure"`
	EventIDs            []int64  `json:"event_ids"`
	Sources             []string `json:"sources"`
}

// State is a vuln_state_mat row.
type State struct {
	Stage              string     `json:"stage"`
	StageCode          string     `json:"stage_code"`
	StageRank          int        `json:"stage_rank"`
	HasPatch           bool       `json:"has_patch"`
	HasAnalysis        bool       `json:"has_analysis"`
	HasPoc             bool       `json:"has_poc"`
	Exploited          bool       `json:"exploited"` // exploited_in_wild or kev_added
	InKEV              bool       `json:"in_kev"`
	IsRejected         bool       `json:"is_rejected"`
	DisclosedAt        *time.Time `json:"disclosed_at"`
	PatchAt            *time.Time `json:"patch_at"`
	AnalysisAt         *time.Time `json:"analysis_at"`
	PocAt              *time.Time `json:"poc_at"`
	ExploitedAt        *time.Time `json:"exploited_at"`
	KEVAt              *time.Time `json:"kev_at"`
	LastTransitionAt   *time.Time `json:"last_transition_at"`
	LastTransitionType *string    `json:"last_transition_type"`
	EventCount         int        `json:"event_count"`
	PocSources         int        `json:"poc_sources"`
}

// Event is one lifecycle event, verbatim plus derived fields.
type Event struct {
	ID     int64   `json:"id"`
	Type   string  `json:"type"`
	Code   string  `json:"code"`
	Source string  `json:"source"`
	URL    *string `json:"url"`
	// OccurredAt: time claimed by the source (nil = not given).
	OccurredAt *time.Time `json:"occurred_at"`
	// ObservedAt: when nday first stored it (bulk import time if IsBackfill).
	ObservedAt time.Time `json:"observed_at"`
	// EffectiveAt: OccurredAt, else ObservedAt if observed live, else nil.
	EffectiveAt *time.Time      `json:"effective_at"`
	IsBackfill  bool            `json:"is_backfill"`
	Precision   string          `json:"precision"`
	DedupeKey   string          `json:"dedupe_key"`
	Detail      json.RawMessage `json:"detail"` // raw jsonb, source-specific
}

// Patch is a fix advisory (from a patch_released event; today GHSA).
type Patch struct {
	EventID             int64      `json:"event_id"`
	Source              string     `json:"source"`
	AdvisoryID          *string    `json:"advisory_id"`
	URL                 *string    `json:"url"`
	Severity            *string    `json:"severity"`
	AdvisoryPublishedAt *time.Time `json:"advisory_published_at"`
	Packages            []Package  `json:"packages"`
	FixCommitURLs       []string   `json:"fix_commit_urls"`
	SourceCodeLocation  *string    `json:"source_code_location"`
}

// Package is one affected package of an advisory.
type Package struct {
	Ecosystem     *string `json:"ecosystem"`
	Name          *string `json:"name"`
	AffectedRange *string `json:"affected_range"` // e.g. "< 2.2.0"
	FixedVersion  *string `json:"fixed_version"`  // first patched version; nil = no fix
}

// PocSource is PoC presence in one curated source.
type PocSource struct {
	Source  string    `json:"source"`
	Present bool      `json:"present"`
	Items   []PocItem `json:"items"`
}

// PocItem is one PoC / module / template.
type PocItem struct {
	EventID    int64      `json:"event_id"`
	Key        string     `json:"key"` // EDB id, module fullname, template id
	Title      *string    `json:"title"`
	URL        *string    `json:"url"`
	Kind       *string    `json:"kind"` // exploit | msf_module | detection_template
	OccurredAt *time.Time `json:"occurred_at"`
	Precision  string     `json:"precision"`
}

// KEVFacts are the CISA KEV catalog facts.
type KEVFacts struct {
	EventID                    int64      `json:"event_id"`
	AddedAt                    *time.Time `json:"added_at"`
	Precision                  string     `json:"precision"`
	DateAdded                  *string    `json:"date_added"` // YYYY-MM-DD
	DueDate                    *string    `json:"due_date"`   // YYYY-MM-DD
	KnownRansomwareCampaignUse *string    `json:"known_ransomware_campaign_use"`
	ForensicTriage             *string    `json:"forensic_triage"`
	RequiredAction             *string    `json:"required_action"`
	Notes                      *string    `json:"notes"`
	VulnerabilityName          *string    `json:"vulnerability_name"`
	VendorProject              *string    `json:"vendor_project"`
	Product                    *string    `json:"product"`
	URL                        *string    `json:"url"`
}

// CVSS is the base score shown on the page.
type CVSS struct {
	Score    *float64 `json:"score"`
	Severity *string  `json:"severity"` // upper case, e.g. CRITICAL
	Vector   *string  `json:"vector"`
	Version  *string  `json:"version"`
	// Source: "cvelist:cna", "cvelist:adp:<provider>" or "ghsa".
	Source string `json:"source"`
	// EventID: the event whose detail delivered this score and vector (the
	// cvelist disclosure or the GHSA patch event); not part of the API.
	EventID int64 `json:"-"`
}

// SSVC is CISA-ADP's SSVC assessment from the CVE record.
type SSVC struct {
	Exploitation    *string `json:"exploitation"` // none | poc | active
	Automatable     *string `json:"automatable"`
	TechnicalImpact *string `json:"technical_impact"`
	Timestamp       *string `json:"timestamp"`
	Source          string  `json:"source"` // "cvelist:CISA-ADP"
}

// CWE is a weakness id with an English name when a source provides one.
type CWE struct {
	ID      string   `json:"id"`
	Name    *string  `json:"name"`
	Sources []string `json:"sources"`
}

// RawLink points to a stored raw record (served at Path).
type RawLink struct {
	Source    string    `json:"source"`
	Key       string    `json:"key"`
	Path      string    `json:"path"` // "/raw/<source>/<key>.json"
	FetchedAt time.Time `json:"fetched_at"`
}

// RawPath is the URL path of a raw record.
func RawPath(source, key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/raw/" + url.PathEscape(source) + "/" + strings.Join(segs, "/") + ".json"
}

const (
	vulnSQL = `
SELECT v.cve_id, v.title, v.title_zh, v.description, v.summary_zh, v.published_at, v.modified_at, v.first_seen_at,
       m.cve_id IS NOT NULL, m.stage, m.stage_rank, m.has_patch, m.has_analysis, m.has_poc, m.exploited, m.in_kev,
       m.is_rejected, m.disclosed_at, m.patch_at, m.analysis_at, m.poc_at, m.exploited_at, m.kev_at,
       m.last_transition_at, m.last_transition_type, m.event_count, m.poc_sources, ` + titleCols + `
FROM vuln v LEFT JOIN vuln_state_mat m USING (cve_id)` + titleJoinV + `
WHERE v.cve_id = $1`
	aliasSQL    = `SELECT alias, alias_type FROM vuln_alias WHERE cve_id = $1 ORDER BY alias_type, alias`
	affectedSQL = `
SELECT vendor, product FROM (
    SELECT DISTINCT ON (lower(vendor), lower(product)) vendor, product, id
    FROM affected WHERE cve_id = $1
    ORDER BY lower(vendor), lower(product), id) d
ORDER BY id`
)

var (
	// Public events only (public.go).
	eventsSQL = `
SELECT e.id, e.type, e.source, e.url, e.occurred_at, e.observed_at, ee.effective_at, e.is_backfill,
       e.dedupe_key, e.detail::text
FROM event e JOIN event_effective ee ON ee.id = e.id
WHERE e.cve_id = $1 AND ee.cve_id = $1 AND ` + publicEventSQL("e")
	// Raw records that belong to this vulnerability: keyed by its id (cvelist,
	// kev), by a GHSA alias, or by an event's dedupe key (ghsa advisory id,
	// EDB id, Metasploit module, Nuclei template). Public sources and
	// events only (public.go).
	rawLinksSQL = `
SELECT r.source, r.source_key, max(r.fetched_at)
FROM raw_record r
WHERE (r.source, r.source_key) IN (
    SELECT 'cvelist', $1::text UNION ALL SELECT 'kev', $1::text
    UNION ALL SELECT 'ghsa', alias FROM vuln_alias WHERE cve_id = $1 AND alias_type = 'ghsa'
    UNION ALL SELECT e.source, e.dedupe_key FROM event e
              WHERE e.cve_id = $1 AND e.dedupe_key <> '' AND ` + publicEventSQL("e") + `)
  AND ` + publicSourceSQL("r.source") + `
GROUP BY r.source, r.source_key
ORDER BY r.source, r.source_key`
)

// Vuln returns the detail of one vulnerability. id is a CVE id or the GHSA id
// of an advisory without a CVE (ParseVulnID), case-insensitive
// ("cve-2026-102895"); a malformed id is an *InputError; an unknown one
// returns found=false and no error. A GHSA id that is only an alias of a CVE
// is unknown here (VulnsByGHSA finds the CVE).
func (s *Store) Vuln(ctx context.Context, id string) (v *VulnDetail, found bool, err error) {
	cve, ok := ParseVulnID(id)
	if !ok {
		return nil, false, &InputError{Param: "cve", Msg: BadVulnIDMsg}
	}
	v = &VulnDetail{CVEID: cve, Aliases: []Alias{}, Products: []Product{}, Events: []Event{},
		Patches: []Patch{}, CWEs: []CWE{}, RawRecords: []RawLink{}, Credits: []Credit{}}
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		b := &pgx.Batch{}
		b.Queue(vulnSQL, cve)
		b.Queue(aliasSQL, cve)
		b.Queue(affectedSQL, cve)
		b.Queue(eventsSQL, cve)
		b.Queue(rawLinksSQL, cve)
		b.Queue(creditsSQL, cve)
		b.Queue(descSourceSQL, cve)
		br := conn.SendBatch(ctx, b)
		defer br.Close()

		var st State
		var hasState bool
		var stage, lastType *string
		var rank, evCount, pocN *int
		var hp, ha, hpoc, ex, kev, rej *bool
		var ts titleScan
		err := br.QueryRow().Scan(append([]any{&v.CVEID, &v.Title, &v.TitleZh, &v.Description, &v.SummaryZh,
			&v.PublishedAt, &v.ModifiedAt, &v.FirstSeenAt,
			&hasState, &stage, &rank, &hp, &ha, &hpoc, &ex, &kev, &rej,
			&st.DisclosedAt, &st.PatchAt, &st.AnalysisAt, &st.PocAt, &st.ExploitedAt, &st.KEVAt,
			&st.LastTransitionAt, &lastType, &evCount, &pocN}, ts.dest()...)...)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		v.TitleInfo = ts.info(v.Title)
		found = true
		if hasState {
			st.Stage, st.StageRank, st.EventCount, st.PocSources = *stage, *rank, *evCount, *pocN
			st.StageCode = StageCode(st.Stage)
			st.HasPatch, st.HasAnalysis, st.HasPoc, st.Exploited, st.InKEV, st.IsRejected = *hp, *ha, *hpoc, *ex, *kev, *rej
			st.LastTransitionType = lastType
			for _, t := range []**time.Time{&st.DisclosedAt, &st.PatchAt, &st.AnalysisAt, &st.PocAt, &st.ExploitedAt, &st.KEVAt, &st.LastTransitionAt} {
				*t = utcPtr(*t)
			}
			v.State = &st
		}
		rows, _ := br.Query()
		v.Aliases, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alias, error) {
			var a Alias
			return a, r.Scan(&a.Alias, &a.Type)
		})
		if err != nil {
			return err
		}
		rows, _ = br.Query()
		v.Products, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Product, error) {
			var p Product
			return p, r.Scan(&p.Vendor, &p.Product)
		})
		if err != nil {
			return err
		}
		rows, _ = br.Query()
		v.Events, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
			var e Event
			var detail string
			err := r.Scan(&e.ID, &e.Type, &e.Source, &e.URL, &e.OccurredAt, &e.ObservedAt, &e.EffectiveAt,
				&e.IsBackfill, &e.DedupeKey, &detail)
			e.Detail = json.RawMessage(detail)
			return e, err
		})
		if err != nil {
			return err
		}
		rows, _ = br.Query()
		v.RawRecords, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (RawLink, error) {
			var l RawLink
			err := r.Scan(&l.Source, &l.Key, &l.FetchedAt)
			l.Path = RawPath(l.Source, l.Key)
			l.FetchedAt = l.FetchedAt.UTC()
			return l, err
		})
		if err != nil {
			return err
		}
		rows, _ = br.Query()
		recs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (creditRecord, error) {
			var c creditRecord
			var js string
			err := r.Scan(&c.Source, &c.Key, &js)
			c.JSON = []byte(js)
			return c, err
		})
		if err != nil {
			return err
		}
		v.Credits = buildCredits(recs)
		rows, _ = br.Query()
		texts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (descText, error) {
			var d descText
			return d, r.Scan(&d.Source, &d.Key, &d.Text)
		})
		if err != nil {
			return err
		}
		v.DescriptionSource = matchDescSource(v.Description, texts)
		br.Close()
		v.Classification, err = classify.For(ctx, conn, cve)
		if err != nil {
			return err
		}
		tv, err := tags.ForMany(ctx, conn, []string{cve})
		v.Tags = tv[cve]
		if v.Tags == nil {
			v.Tags = []tags.View{}
		}
		return err
	})
	if err != nil || !found {
		return nil, found, err
	}
	v.PublishedAt, v.ModifiedAt = utcPtr(v.PublishedAt), utcPtr(v.ModifiedAt)
	v.FirstSeenAt = v.FirstSeenAt.UTC()
	assemble(v)
	return v, true, nil
}

// assemble derives everything computed from v.Events (pure; tested).
func assemble(v *VulnDetail) {
	details := make([]map[string]any, len(v.Events))
	for i := range v.Events {
		e := &v.Events[i]
		e.OccurredAt, e.EffectiveAt = utcPtr(e.OccurredAt), utcPtr(e.EffectiveAt)
		e.ObservedAt = e.ObservedAt.UTC()
		e.Code = StageCode(e.Type)
		var m map[string]any
		if err := json.Unmarshal(e.Detail, &m); err != nil || m == nil {
			m = map[string]any{}
		}
		details[i] = m
		e.Precision = EventPrecision(e.OccurredAt, e.IsBackfill, jstr(m, "precision"))
	}
	// Order: known effective time asc; unknown last; ties by stage then id.
	idx := make([]int, len(v.Events))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ea, eb := v.Events[idx[a]], v.Events[idx[b]]
		if (ea.EffectiveAt == nil) != (eb.EffectiveAt == nil) {
			return ea.EffectiveAt != nil
		}
		if ea.EffectiveAt != nil && !ea.EffectiveAt.Equal(*eb.EffectiveAt) {
			return ea.EffectiveAt.Before(*eb.EffectiveAt)
		}
		if ra, rb := stageIndex(ea.Type), stageIndex(eb.Type); ra != rb {
			return ra < rb
		}
		return ea.ID < eb.ID
	})
	evs := make([]Event, len(idx))
	dts := make([]map[string]any, len(idx))
	for i, j := range idx {
		evs[i], dts[i] = v.Events[j], details[j]
	}
	v.Events, details = evs, dts

	// Slots and transition (same rules as vuln_state / vuln_state_mat).
	var in SlotInput
	first := [6]*Event{}   // event defining FirstAt per type
	firstTr := [6]*Event{} // the same over sources that count as a transition
	slots := make([]DetailSlot, 6)
	for i := range v.Events {
		e := &v.Events[i]
		k := stageIndex(e.Type)
		if k < 0 {
			continue
		}
		in.Exists[k] = true
		slots[k].EventIDs = append(slots[k].EventIDs, e.ID)
		if !contains(slots[k].Sources, e.Source) {
			slots[k].Sources = append(slots[k].Sources, e.Source)
		}
		if e.EffectiveAt != nil {
			f := first[k]
			if f == nil || e.EffectiveAt.Before(*f.EffectiveAt) ||
				(e.EffectiveAt.Equal(*f.EffectiveAt) && betterTransitionEvent(e, f)) {
				first[k] = e
				in.FirstAt[k] = e.EffectiveAt
			}
			if f := firstTr[k]; !contains(NoTransitionSources, e.Source) && (f == nil || e.EffectiveAt.Before(*f.EffectiveAt) ||
				(e.EffectiveAt.Equal(*f.EffectiveAt) && betterTransitionEvent(e, f))) {
				firstTr[k] = e
			}
		}
	}
	latest := -1
	for k := 0; k < 6; k++ {
		if firstTr[k] != nil && (latest < 0 || !firstTr[k].EffectiveAt.Before(*firstTr[latest].EffectiveAt)) {
			latest = k // later time wins; equal time -> higher rank (k ascending)
		}
	}
	if latest >= 0 {
		in.Latest = StageInfos[latest].Type
		e := firstTr[latest]
		src, id := e.Source, e.ID
		v.Transition = &Transition{Type: e.Type, Code: StageCode(e.Type), At: *e.EffectiveAt,
			Precision: e.Precision, Source: &src, EventID: &id}
	}
	base := ComputeSlots(in)
	v.DisclosedAt = utcPtr(in.FirstAt[0])
	for k := range slots {
		slots[k].Slot = base[k]
		if slots[k].EventIDs == nil {
			slots[k].EventIDs = []int64{}
			slots[k].Sources = []string{}
		}
		switch base[k].State {
		case SlotKnown:
			p := first[k].Precision
			slots[k].Precision = &p
			slots[k].DaysSinceDisclosure = CalendarDays(v.DisclosedAt, base[k].At)
		case SlotUnknown:
			slots[k].Precision = strPtr(PrecisionUnknown)
		}
		if in.Exists[k] {
			stage := StageInfos[k].Type
			v.Stage = &stage
			code := StageInfos[k].Code
			v.StageCode = &code
		}
	}
	v.Slots = slots
	if v.Transition != nil {
		v.DaysSinceDisclosure = CalendarDays(v.DisclosedAt, &v.Transition.At)
	}

	// Panels.
	poc := map[string]*PocSource{}
	v.Poc = make([]PocSource, len(PocSourceNames))
	for i, n := range PocSourceNames {
		v.Poc[i] = PocSource{Source: n, Items: []PocItem{}}
		poc[n] = &v.Poc[i]
	}
	cwes := map[string]*CWE{}
	addCWE := func(id string, name *string, source string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !strings.HasPrefix(id, "CWE-") {
			return
		}
		c := cwes[id]
		if c == nil {
			c = &CWE{ID: id, Sources: []string{}}
			cwes[id] = c
		}
		if c.Name == nil && name != nil {
			c.Name = name
		}
		if !contains(c.Sources, source) {
			c.Sources = append(c.Sources, source)
		}
	}
	var ghsaCVSS *CVSS
	for i := range v.Events {
		e, d := &v.Events[i], details[i]
		switch {
		case e.Type == "disclosed" && e.Source == "cvelist":
			v.Assigner = jstr(d, "assigner_short_name")
			if s := jstr(d, "state"); s != nil && *s == "REJECTED" {
				v.IsRejected = true
				v.Rejection = &Rejection{DateRejected: jstr(d, "date_rejected"),
					Reasons: jstrs(d["rejected_reasons"]), ReplacedBy: jstrs(d["replaced_by"])}
			}
			if c := jobj(d, "cvss"); c != nil {
				src := "cvelist"
				if s := jstr(c, "source"); s != nil {
					src += ":" + *s
				}
				v.CVSS = &CVSS{Score: jnum(c, "base_score"), Severity: upper(jstr(c, "base_severity")),
					Vector: jstr(c, "vector"), Version: jstrOrNum(c, "version"), Source: src, EventID: e.ID}
			}
			if s := jobj(d, "ssvc"); s != nil {
				v.SSVC = &SSVC{Exploitation: jstr(s, "exploitation"), Automatable: jstr(s, "automatable"),
					TechnicalImpact: jstr(s, "technical_impact"), Timestamp: jstr(s, "timestamp"),
					Source: "cvelist:CISA-ADP"}
			}
		case e.Type == "disclosed" && e.Source == "ghsa" && IsGHSAID(v.CVEID):
			// the advisory of a vulnerability keyed by its GHSA id is its
			// record: a withdrawn one reads like a rejected CVE record
			// (vuln_state does the same, migrations/0027)
			if s := jstr(d, "state"); s != nil && *s == "REJECTED" {
				v.IsRejected = true
				v.Rejection = &Rejection{DateRejected: jstr(d, "withdrawn_at"), Reasons: []string{}, ReplacedBy: []string{}}
			}
		case e.Type == "patch_released":
			p := Patch{EventID: e.ID, Source: e.Source, AdvisoryID: jstr(d, "ghsa_id"), URL: e.URL,
				Severity: jstr(d, "severity"), AdvisoryPublishedAt: jtime(d, "advisory_published_at"),
				Packages: []Package{}, FixCommitURLs: jstrs(d["fix_commit_urls"]),
				SourceCodeLocation: jstr(d, "source_code_location")}
			if list, ok := d["packages"].([]any); ok {
				for _, x := range list {
					if pm, ok := x.(map[string]any); ok {
						p.Packages = append(p.Packages, Package{Ecosystem: jstr(pm, "ecosystem"), Name: jstr(pm, "name"),
							AffectedRange: jstr(pm, "vulnerable_version_range"), FixedVersion: jstr(pm, "first_patched_version")})
					}
				}
			}
			v.Patches = append(v.Patches, p)
			if list, ok := d["cwes"].([]any); ok {
				for _, x := range list {
					if cm, ok := x.(map[string]any); ok {
						if id := jstr(cm, "cwe_id"); id != nil {
							addCWE(*id, jstr(cm, "name"), e.Source)
						}
					}
				}
			}
			if ghsaCVSS == nil {
				if ghsaCVSS = ghsaScore(d); ghsaCVSS != nil {
					ghsaCVSS.EventID = e.ID
				}
			}
		case e.Type == "poc_published":
			if ps := poc[e.Source]; ps != nil {
				ps.Present = true
				ps.Items = append(ps.Items, PocItem{EventID: e.ID, Key: e.DedupeKey, Title: jstr(d, "title"),
					URL: firstNonNil(jstr(d, "url"), e.URL), Kind: jstr(d, "kind"), OccurredAt: e.OccurredAt,
					Precision: e.Precision})
			}
		case e.Type == "kev_added":
			if v.KEV == nil {
				v.KEV = &KEVFacts{
					EventID:                    e.ID,
					AddedAt:                    e.OccurredAt,
					Precision:                  e.Precision,
					DateAdded:                  jstr(d, "date_added"),
					DueDate:                    jstr(d, "due_date"),
					KnownRansomwareCampaignUse: jstr(d, "known_ransomware_campaign_use"),
					ForensicTriage:             jstr(d, "forensic_triage"),
					RequiredAction:             jstr(d, "required_action"),
					Notes:                      jstr(d, "notes"),
					VulnerabilityName:          jstr(d, "vulnerability_name"),
					VendorProject:              jstr(d, "vendor_project"),
					Product:                    jstr(d, "product"),
					URL:                        e.URL,
				}
			}
			for _, id := range jstrs(d["cwes"]) {
				addCWE(id, nil, e.Source)
			}
		}
	}
	for _, p := range v.Poc {
		if p.Present {
			v.PocSources++
		}
	}
	if v.CVSS == nil {
		v.CVSS = ghsaCVSS
	}
	for _, c := range cwes {
		v.CWEs = append(v.CWEs, *c)
	}
	sort.Slice(v.CWEs, func(a, b int) bool {
		na, _ := strconv.Atoi(strings.TrimPrefix(v.CWEs[a].ID, "CWE-"))
		nb, _ := strconv.Atoi(strings.TrimPrefix(v.CWEs[b].ID, "CWE-"))
		if na != nb {
			return na < nb
		}
		return v.CWEs[a].ID < v.CWEs[b].ID
	})
}

// betterTransitionEvent: among events with equal effective time prefer one
// with a source-given time, then the lowest id (as in vuln_state_mat).
func betterTransitionEvent(a, b *Event) bool {
	if (a.OccurredAt != nil) != (b.OccurredAt != nil) {
		return a.OccurredAt != nil
	}
	return a.ID < b.ID
}

// ghsaScore reads a GHSA detail.cvss: {cvss_v3:{score,vector_string},
// cvss_v4:{...}} (current API; v4 preferred when it has a vector) or the
// legacy {score, vector_string}.
func ghsaScore(d map[string]any) *CVSS {
	c := jobj(d, "cvss")
	if c == nil {
		return nil
	}
	pick := func(m map[string]any) *CVSS {
		if m == nil {
			return nil
		}
		score, vec := jnum(m, "score"), jstr(m, "vector_string")
		if vec == nil || score == nil || *score == 0 {
			return nil
		}
		out := &CVSS{Score: score, Vector: vec, Severity: upper(jstr(d, "severity")), Source: "ghsa"}
		if strings.HasPrefix(*vec, "CVSS:") {
			if ver, _, ok := strings.Cut(strings.TrimPrefix(*vec, "CVSS:"), "/"); ok {
				out.Version = &ver
			}
		}
		return out
	}
	if r := pick(jobj(c, "cvss_v4")); r != nil {
		return r
	}
	if r := pick(jobj(c, "cvss_v3")); r != nil {
		return r
	}
	return pick(c)
}

func jobj(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	return o
}

// jstr returns a non-empty string value, else nil.
func jstr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
		return &s
	}
	return nil
}

func jstrOrNum(m map[string]any, k string) *string {
	if f, ok := m[k].(float64); ok {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		return &s
	}
	return jstr(m, k)
}

func jnum(m map[string]any, k string) *float64 {
	if f, ok := m[k].(float64); ok {
		return &f
	}
	return nil
}

func jtime(m map[string]any, k string) *time.Time {
	s := jstr(m, k)
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// jstrs returns the string elements of a JSON array (others skipped).
func jstrs(v any) []string {
	out := []string{}
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func upper(s *string) *string {
	if s == nil {
		return nil
	}
	u := strings.ToUpper(*s)
	return &u
}

func firstNonNil(a, b *string) *string {
	if a != nil {
		return a
	}
	return b
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
