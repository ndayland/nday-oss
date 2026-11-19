package tags

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/titles"
)

// Composed titles (docs/titles.md; internal/titles has the rule, migration
// 0031 the table vuln_title).
//
// Maintenance: the rule reads the record's title and description, the
// affected rows and the visible tags. Every write to one of those queues
// the CVE in tag_queue (triggers of 0011, 0013 and 0031), and processBatch
// recomputes the composed parts of every CVE of its batch right after its
// tags, in the same transaction, so no separate scan is needed. A bumped
// titles.RuleVersion is not a database write: `nday titles` (Titles)
// recomposes every row of an older version.
//
// Only the composed columns are written here; the staff title is written
// by internal/admin alone.

// titleInputs reads the composition inputs of ids (inside tx, after the
// tag rows of the batch were written, so the visible tags are current).
func titleInputs(ctx context.Context, tx pgx.Tx, ids []string) (map[string]*titles.Input, error) {
	out := map[string]*titles.Input{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT cve_id, COALESCE(title, ''), COALESCE(description, '') FROM vuln WHERE cve_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		in := &titles.Input{}
		var id string
		if err := rows.Scan(&id, &in.RecordTitle, &in.Description); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = in
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT cve_id, vendor, product FROM affected WHERE cve_id = ANY($1) ORDER BY cve_id, id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var a titles.Affected
		if err := rows.Scan(&id, &a.Vendor, &a.Product); err != nil {
			rows.Close()
			return nil, err
		}
		if in := out[id]; in != nil {
			in.Affected = append(in.Affected, a)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT cve_id, tag FROM vuln_tag_visible WHERE cve_id = ANY($1) ORDER BY cve_id, tag`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, slug string
		if err := rows.Scan(&id, &slug); err != nil {
			rows.Close()
			return nil, err
		}
		in, t := out[id], bySlug[slug]
		if in == nil || t == nil {
			continue
		}
		switch t.Dim {
		case DimProduct:
			in.ProductLabels = append(in.ProductLabels, t.Label)
		case DimType:
			if in.Weakness == "" || Order(slug) < Order(in.Weakness) {
				in.Weakness = slug
			}
		}
	}
	rows.Close()
	return out, rows.Err()
}

// TypeLabel is the English label of a type tag slug (the slug itself when
// unknown): the weakness of a composed title in English.
func TypeLabel(slug string) string {
	if t, ok := bySlug[slug]; ok {
		return t.Label
	}
	return slug
}

// TitleCounts counts what a composition pass found.
type TitleCounts struct {
	// Considered: vulnerabilities examined.
	Considered int `json:"considered"`
	// Composed by form (full, weakness, component, excerpt).
	Composed map[string]int `json:"composed"`
	// RecordTitle: the record has a title (nothing composed).
	RecordTitle int `json:"record_title"`
	// Untitled: no record title and nothing usable to compose from.
	Untitled int `json:"untitled"`
	// Written: rows inserted or changed (the others were already equal).
	Written int `json:"written"`
}

func (c *TitleCounts) add(o TitleCounts) {
	c.Considered += o.Considered
	c.RecordTitle += o.RecordTitle
	c.Untitled += o.Untitled
	c.Written += o.Written
	for k, v := range o.Composed {
		if c.Composed == nil {
			c.Composed = map[string]int{}
		}
		c.Composed[k] += v
	}
}

type storedTitle struct {
	version                                     *int
	form, product, weakness, component, excerpt *string
	english                                     *string
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func same(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// composeTitles recomposes the titles of ids (vuln rows locked by the
// caller) and writes the rows that differ, in tx.
func composeTitles(ctx context.Context, tx pgx.Tx, ids []string, version int) (TitleCounts, error) {
	c := TitleCounts{Composed: map[string]int{}}
	inputs, err := titleInputs(ctx, tx, ids)
	if err != nil || len(inputs) == 0 {
		return c, err
	}
	stored := map[string]storedTitle{}
	rows, err := tx.Query(ctx, `SELECT cve_id, rule_version, form, product, weakness, component, excerpt, composed_en
		FROM vuln_title WHERE cve_id = ANY($1)`, ids)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var id string
		var s storedTitle
		if err := rows.Scan(&id, &s.version, &s.form, &s.product, &s.weakness, &s.component, &s.excerpt, &s.english); err != nil {
			rows.Close()
			return c, err
		}
		stored[id] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return c, err
	}
	var wID []string
	var wForm, wProduct, wWeakness, wComponent, wExcerpt, wEnglish []*string
	for _, id := range ids {
		in := inputs[id]
		if in == nil {
			continue
		}
		c.Considered++
		p := titles.Compose(*in)
		switch {
		case !p.Empty():
			c.Composed[p.Form]++
		case in.RecordTitle != "" && titles.Clean(in.RecordTitle) != "":
			c.RecordTitle++
		default:
			c.Untitled++
		}
		want := storedTitle{version: &version, form: ptr(p.Form), product: ptr(p.Product), weakness: ptr(p.Weakness),
			component: ptr(p.Component), excerpt: ptr(p.Excerpt), english: ptr(titles.English(p, TypeLabel))}
		if s, ok := stored[id]; ok && s.version != nil && *s.version == version && same(s.form, want.form) &&
			same(s.product, want.product) && same(s.weakness, want.weakness) && same(s.component, want.component) &&
			same(s.excerpt, want.excerpt) && same(s.english, want.english) {
			continue
		}
		wID = append(wID, id)
		wForm, wProduct, wWeakness = append(wForm, want.form), append(wProduct, want.product), append(wWeakness, want.weakness)
		wComponent, wExcerpt, wEnglish = append(wComponent, want.component), append(wExcerpt, want.excerpt), append(wEnglish, want.english)
	}
	if len(wID) == 0 {
		return c, nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO vuln_title AS t (cve_id, rule_version, form, product, weakness, component, excerpt, composed_en, composed_at)
		SELECT u.id, $2, u.form, u.product, u.weakness, u.component, u.excerpt, u.en, now()
		FROM unnest($1::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
		     AS u(id, form, product, weakness, component, excerpt, en)
		ON CONFLICT (cve_id) DO UPDATE SET rule_version = EXCLUDED.rule_version, form = EXCLUDED.form,
		    product = EXCLUDED.product, weakness = EXCLUDED.weakness, component = EXCLUDED.component,
		    excerpt = EXCLUDED.excerpt, composed_en = EXCLUDED.composed_en, composed_at = EXCLUDED.composed_at`,
		wID, version, wForm, wProduct, wWeakness, wComponent, wExcerpt, wEnglish)
	if err != nil {
		return c, fmt.Errorf("write vuln_title: %w", err)
	}
	c.Written = int(tag.RowsAffected())
	return c, nil
}

// ---------------------------------------------------------------- backfill

// DefaultTitleBatch is the backfill's batch size (vulnerabilities per
// transaction).
const DefaultTitleBatch = 1000

// TitlesOptions for Titles.
type TitlesOptions struct {
	// All recomposes every vulnerability, not only those without a row of
	// the current rule version.
	All bool
	// Limit stops after this many vulnerabilities (0 = no limit).
	Limit     int
	BatchSize int // default DefaultTitleBatch
	Logger    *slog.Logger
	// ruleVersion overrides titles.RuleVersion (tests: a version bump).
	ruleVersion int
	// afterBatch is a test hook run after each committed batch.
	afterBatch func(n int) error
}

// TitlesStats is the summary of a backfill (`nday titles` prints it).
type TitlesStats struct {
	RuleVersion int  `json:"rule_version"`
	All         bool `json:"all"`
	TitleCounts
	// Busy: vulnerabilities whose row another transaction held; they were
	// queued for the tag pass (which composes them) and are picked up by
	// the next backfill if still lacking.
	Busy    int `json:"busy"`
	Batches int `json:"batches"`
	// Done: nothing was left (false when Limit stopped the run).
	Done        bool    `json:"done"`
	DurationSec float64 `json:"duration_sec"`
}

// Titles composes the titles of vulnerabilities lacking a row of the
// current rule version (every vulnerability with All), in cve_id order and
// batches of BatchSize, each its own short transaction: the vuln rows are
// taken FOR KEY SHARE SKIP LOCKED (never waiting for, nor blocking, a
// collector), and only vuln_title is written. It holds the tag run lock, so
// no tag pass composes the same rows meanwhile (a pass after a collector
// run skips and leaves its queue for the next one). Resumable (a stopped
// run leaves the rows it has not reached lacking) and idempotent.
func Titles(ctx context.Context, conn *pgx.Conn, o TitlesOptions) (*TitlesStats, error) {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultTitleBatch
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.ruleVersion == 0 {
		o.ruleVersion = titles.RuleVersion
	}
	st := &TitlesStats{RuleVersion: o.ruleVersion, All: o.All, TitleCounts: TitleCounts{Composed: map[string]int{}}}
	start := time.Now()
	defer func() { st.DurationSec = time.Since(start).Seconds() }()
	unlock, err := lock(ctx, conn, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	after := ""
	next := 50000
	for {
		n := o.BatchSize
		if o.Limit > 0 {
			if st.Considered+st.Busy >= o.Limit {
				return st, nil
			}
			n = min(n, o.Limit-st.Considered-st.Busy)
		}
		rows, err := conn.Query(ctx, `SELECT v.cve_id FROM vuln v LEFT JOIN vuln_title t ON t.cve_id = v.cve_id
			WHERE v.cve_id > $1 AND ($2 OR t.rule_version IS DISTINCT FROM $3)
			ORDER BY v.cve_id LIMIT $4`, after, o.All, o.ruleVersion, n)
		if err != nil {
			return st, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return st, err
		}
		if len(ids) == 0 {
			st.Done = true
			return st, nil
		}
		after = ids[len(ids)-1]
		var bc TitleCounts
		var busy []string
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			var have []string
			var err error
			if have, busy, err = classify.LockVulns(ctx, tx, ids); err != nil {
				return err
			}
			if len(busy) > 0 {
				if _, err := tx.Exec(ctx, `INSERT INTO tag_queue (cve_id) SELECT unnest($1::text[])`, busy); err != nil {
					return err
				}
			}
			bc, err = composeTitles(ctx, tx, have, o.ruleVersion)
			return err
		})
		if err != nil {
			return st, err
		}
		st.Batches++
		st.Busy += len(busy)
		st.add(bc)
		if st.Considered >= next {
			o.Logger.Info("titles progress", "considered", st.Considered, "written", st.Written)
			next += 50000
		}
		if o.afterBatch != nil {
			if err := o.afterBatch(st.Batches); err != nil {
				return st, err
			}
		}
	}
}
