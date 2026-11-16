// Package kev is the CISA Known Exploited Vulnerabilities (KEV) catalog
// collector (port of src/nday/collectors/kev.py).
//
// Feed: top level title, catalogVersion, dateReleased, count,
// vulnerabilities[]; entry: cveID, vendorProject, product, vulnerabilityName,
// dateAdded, shortDescription, requiredAction, dueDate,
// knownRansomwareCampaignUse, notes, cwes, forensicTriage.
//
// KEV says a CVE was added to the catalog on dateAdded; it does NOT say when
// exploitation began, so only kev_added is emitted (never exploited_in_wild).
package kev

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// Name is the source name (raw_record.source, event.source, collector_state.source).
const Name = "kev"

// URLs, identical to Python.
const (
	FeedURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	CatalogURL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)

// Collector implements collector.Collector for KEV.
type Collector struct {
	HTTP   *httpc.Client
	URL    string
	Logger *slog.Logger
}

// Options configures New.
type Options struct {
	Transport http.RoundTripper // tests: fake transport; nil = real network
	URL       string            // default FeedURL
	Logger    *slog.Logger
}

// New builds the KEV collector. Python's KevCollector uses httpx with a 60 s
// timeout (connect and read), follows redirects and does NOT retry; the same
// policy is kept here (MaxAttempts 1). The 64 MiB body cap is new in Go (the
// feed is ~1.5 MB).
func New(o Options) *Collector {
	if o.URL == "" {
		o.URL = FeedURL
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Collector{
		HTTP: httpc.New(httpc.Options{
			Transport:   o.Transport,
			MaxAttempts: 1,
			ConnTimeout: 60 * time.Second,
			ReadTimeout: 60 * time.Second,
			MaxBytes:    httpc.DefaultMaxBytes,
			Logger:      o.Logger,
		}),
		URL:    o.URL,
		Logger: o.Logger,
	}
}

// Factory is the registry entry (KEV has no configuration).
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport}), nil
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// Fetch downloads the whole feed; one record per distinct (stripped) cveID.
func (c *Collector) Fetch(ctx context.Context, _ model.CollectorState) (*model.FetchResult, error) {
	resp, err := c.HTTP.Get(ctx, c.URL, httpc.GetOptions{})
	if err != nil {
		return nil, err
	}
	data, err := pyjson.Decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("KEV feed: %w", err)
	}
	top, _ := data.(*pyjson.Object)
	items, ok := top.Get("vulnerabilities").([]any)
	if !ok {
		return nil, errors.New("KEV feed: missing 'vulnerabilities' array")
	}
	var records []model.RawRecord
	seen := map[string]bool{}
	for _, item := range items {
		var cve *string
		if obj, ok := item.(*pyjson.Object); ok {
			cve = collector.Text(obj.Get("cveID"))
		}
		if cve == nil {
			c.Logger.Warn("KEV entry without cveID skipped: " + pyjson.Repr(item))
			continue
		}
		if seen[*cve] {
			c.Logger.Warn(fmt.Sprintf("duplicate KEV entry for %s skipped", *cve))
			continue
		}
		seen[*cve] = true
		records = append(records, model.RawRecord{Source: Name, SourceKey: *cve, Payload: item})
	}
	cursor := pyjson.NewObject()
	for _, k := range []string{"catalogVersion", "dateReleased", "count"} {
		cursor.Set(k, top.Get(k))
	}
	return &model.FetchResult{Records: records, Cursor: cursor}, nil
}

// Normalize maps one KEV entry to a stub vuln, an affected row and one
// kev_added event (day precision).
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, _ := rec.Payload.(*pyjson.Object)
	if p == nil {
		// Python: p.get on a non-dict raises AttributeError (a run failure, not
		// a NormalizeError). Fetch only yields objects, so this is unreachable
		// in practice; keep it fatal like Python.
		return nil, fmt.Errorf("KEV payload is %T, not an object", rec.Payload)
	}
	cve := collector.Text(p.Get("cveID"))
	if cve == nil || !model.IsValidCVEID(*cve) {
		return nil, collector.NormalizeErrorf("bad cveID: %s", pyjson.Repr(p.Get("cveID")))
	}
	out := &model.Normalized{}
	out.Vulns = append(out.Vulns, model.VulnUpsert{
		CVEID:         *cve,
		Title:         collector.Text(p.Get("vulnerabilityName")),
		Description:   collector.Text(p.Get("shortDescription")),
		Authoritative: false,
	})
	vendor, product := collector.Text(p.Get("vendorProject")), collector.Text(p.Get("product"))
	if vendor != nil && product != nil {
		out.Affected = append(out.Affected, model.Affected{CVEID: *cve, Vendor: *vendor, Product: *product})
	}
	var occurredAt *time.Time
	if s := collector.Text(p.Get("dateAdded")); s != nil {
		if t, ok := collector.ParseISODate(*s); ok {
			occurredAt = &t
		}
	}
	detail := map[string]any{
		"date_added":                    p.Get("dateAdded"),
		"vendor_project":                p.Get("vendorProject"),
		"product":                       p.Get("product"),
		"vulnerability_name":            p.Get("vulnerabilityName"),
		"known_ransomware_campaign_use": p.Get("knownRansomwareCampaignUse"),
		"required_action":               p.Get("requiredAction"),
		"due_date":                      p.Get("dueDate"),
		"notes":                         p.Get("notes"),
		"cwes":                          p.Get("cwes"),
		"forensic_triage":               p.Get("forensicTriage"),
	}
	if occurredAt != nil {
		detail["precision"] = "day"
	}
	out.Events = append(out.Events, model.Event{
		CVEID:      *cve,
		Type:       model.EventKevAdded,
		Source:     Name,
		OccurredAt: occurredAt,
		URL:        model.Ptr(CatalogURL),
		Detail:     detail,
		DedupeKey:  "",
	})
	return out, nil
}
