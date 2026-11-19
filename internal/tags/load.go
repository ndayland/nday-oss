package tags

import (
	"context"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
)

// The event types the derivation reads. Keep in sync with the event
// triggers of migrations/0011_tags.sql (TestTriggerEventTypes checks it).
var EventTypes = []string{"kev_added", "poc_published", "disclosed"}

// eventsSQL: KEV and curated-PoC events (public sources only: the exploit
// dimension names its sources explicitly, xposts is never one of them).
const eventsSQL = `
SELECT cve_id, type, source, dedupe_key, COALESCE(detail->>'known_ransomware_campaign_use', '')
FROM event
WHERE cve_id = ANY($1)
  AND ((type = 'kev_added' AND source = 'kev')
       OR (type = 'poc_published' AND source IN ('exploitdb', 'metasploit', 'nuclei')))`

// rejectedSQL: the vuln's own record's state as vuln_state reads it (the
// latest disclosed event with a state of the CVE record, or of the GitHub
// advisory for a GHSA-keyed vuln; migrations 0002 and 0027, CTE rej).
const rejectedSQL = `
SELECT DISTINCT ON (cve_id) cve_id, (detail->>'state') = 'REJECTED'
FROM event_effective
WHERE cve_id = ANY($1) AND type = 'disclosed' AND detail ? 'state'
  AND (source = 'cvelist' OR (source = 'ghsa' AND cve_id LIKE 'GHSA-%'))
ORDER BY cve_id, effective_at DESC NULLS LAST, observed_at DESC, id DESC`

// packagesSQL: the packages of the advisory versions the classification
// layer read (vuln_classify_input.source_key / content_hash).
const packagesSQL = `
SELECT r.source_key, r.content_hash, COALESCE(v->'package'->>'ecosystem', ''), COALESCE(v->'package'->>'name', '')
FROM raw_record r
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(r.payload->'vulnerabilities') = 'array' THEN r.payload->'vulnerabilities' ELSE '[]'::jsonb END) v
WHERE r.source = 'ghsa'
  AND (r.source_key, r.content_hash) IN (SELECT k, h FROM unnest($1::text[], $2::text[]) AS u(k, h))
  AND jsonb_typeof(v) = 'object'`

// affectedSQL: the CVE's affected rows (product and product-type tags).
const affectedSQL = `SELECT cve_id, vendor, product FROM affected WHERE cve_id = ANY($1)`

// cpeSQL: the vulnerable CPE names of the NVD record versions the
// classification layer read (vuln_classify_input.source_key / content_hash
// of the nvd family; payload = the feed's cve object). Entries with
// vulnerable = false are the "running on / with" platforms and are never
// read; neither are entries of negated nodes.
const cpeSQL = `
SELECT DISTINCT r.source_key, r.content_hash, m->>'criteria'
FROM raw_record r
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(r.payload->'configurations') = 'array' THEN r.payload->'configurations' ELSE '[]'::jsonb END) c
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(c->'nodes') = 'array' THEN c->'nodes' ELSE '[]'::jsonb END) n
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(n->'cpeMatch') = 'array' THEN n->'cpeMatch' ELSE '[]'::jsonb END) m
WHERE r.source = 'nvd'
  AND (r.source_key, r.content_hash) IN (SELECT k, h FROM unnest($1::text[], $2::text[]) AS u(k, h))
  AND jsonb_typeof(m) = 'object'
  AND m->'vulnerable' = 'true'::jsonb
  AND COALESCE(n->'negate', 'false'::jsonb) <> 'true'::jsonb
  AND jsonb_typeof(m->'criteria') = 'string'`

// loadInputs reads the derivation inputs of cves; CVEs without a vuln row
// are absent from the result.
func loadInputs(ctx context.Context, tx pgx.Tx, cves []string) (map[string]*Input, error) {
	out := map[string]*Input{}
	rows, err := tx.Query(ctx, `SELECT cve_id FROM vuln WHERE cve_id = ANY($1)`, cves)
	if err != nil {
		return nil, err
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(have) == 0 {
		return out, nil
	}
	for _, c := range have {
		out[c] = &Input{CVEID: c}
	}
	cls, err := classify.ForMany(ctx, tx, have)
	if err != nil {
		return nil, err
	}
	var advKeys, advHashes []string
	advSeen := map[string]bool{} // advisory key + content hash
	var nvdKeys, nvdHashes []string
	nvdOf := map[string][]string{} // NVD key + content hash -> CVE ids
	for id, c := range cls {
		in := out[id]
		in.CWE, in.CVSS = c.CWE, c.CVSS
		for _, x := range c.Inputs {
			switch {
			case x.Rejected && (x.Source == classify.FamCVEList || x.Source == classify.FamNVD):
				in.Rejected = true
			case x.Source == classify.FamGHSA && !x.Rejected:
				k := x.SourceKey + "\x00" + x.ContentHash
				if !advSeen[k] {
					advSeen[k] = true
					advKeys = append(advKeys, x.SourceKey)
					advHashes = append(advHashes, x.ContentHash)
				}
				in.Advisories = append(in.Advisories, Advisory{ID: x.SourceKey, hash: x.ContentHash})
			case x.Source == classify.FamNVD && !x.Rejected:
				k := x.SourceKey + "\x00" + x.ContentHash
				if nvdOf[k] == nil {
					nvdKeys = append(nvdKeys, x.SourceKey)
					nvdHashes = append(nvdHashes, x.ContentHash)
				}
				nvdOf[k] = append(nvdOf[k], id)
			}
		}
	}
	rows, err = tx.Query(ctx, rejectedSQL, have)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cve string
		var rej bool
		if err := rows.Scan(&cve, &rej); err != nil {
			rows.Close()
			return nil, err
		}
		if rej {
			out[cve].Rejected = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, eventsSQL, have)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cve string
		var e EventFact
		if err := rows.Scan(&cve, &e.Type, &e.Source, &e.Key, &e.Ransomware); err != nil {
			rows.Close()
			return nil, err
		}
		out[cve].Events = append(out[cve].Events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(advKeys) > 0 {
		rows, err = tx.Query(ctx, packagesSQL, advKeys, advHashes)
		if err != nil {
			return nil, err
		}
		pk := map[string][]Package{}
		for rows.Next() {
			var key, hash string
			var p Package
			if err := rows.Scan(&key, &hash, &p.Ecosystem, &p.Name); err != nil {
				rows.Close()
				return nil, err
			}
			pk[key+"\x00"+hash] = append(pk[key+"\x00"+hash], p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, in := range out {
			for i := range in.Advisories {
				a := &in.Advisories[i]
				a.Packages = pk[a.ID+"\x00"+a.hash]
			}
		}
	}
	rows, err = tx.Query(ctx, affectedSQL, have)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cve string
		var a AffectedRow
		if err := rows.Scan(&cve, &a.Vendor, &a.Product); err != nil {
			rows.Close()
			return nil, err
		}
		out[cve].Affected = append(out[cve].Affected, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(nvdKeys) > 0 {
		rows, err = tx.Query(ctx, cpeSQL, nvdKeys, nvdHashes)
		if err != nil {
			return nil, err
		}
		seen := map[string]map[CPE]bool{}
		for rows.Next() {
			var key, hash, crit string
			if err := rows.Scan(&key, &hash, &crit); err != nil {
				rows.Close()
				return nil, err
			}
			c, ok := ParseCPE(crit)
			if !ok {
				continue
			}
			for _, cve := range nvdOf[key+"\x00"+hash] {
				if seen[cve] == nil {
					seen[cve] = map[CPE]bool{}
				}
				if !seen[cve][c] {
					seen[cve][c] = true
					out[cve].CPEs = append(out[cve].CPEs, c)
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	rows, err = tx.Query(ctx, `SELECT cve_id, tag FROM vuln_tag_suppress WHERE cve_id = ANY($1)`, have)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cve, tag string
		if err := rows.Scan(&cve, &tag); err != nil {
			rows.Close()
			return nil, err
		}
		out[cve].Suppressed = append(out[cve].Suppressed, tag)
	}
	rows.Close()
	return out, rows.Err()
}
