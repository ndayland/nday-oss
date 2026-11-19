package site

import "strings"

// Description source: vuln.description holds the text of whichever upstream
// record last set it (internal/pipeline MergeVuln: the CVE record
// overwrites, a GitHub advisory or the KEV entry only fills an empty one),
// and the table does not record which. The vulnerability page names the
// source by looking, at request time, for the record whose text it is:
//
//   - cvelist: every value of containers.cna.descriptions[] of the latest
//     CVE record (the collector keeps the English one);
//   - ghsa: description of the latest version of every GitHub advisory whose
//     latest version names this CVE and is not withdrawn, or, for a
//     vulnerability keyed by a GHSA id, of that advisory while it names no
//     CVE (ghsaLatestSQL, as creditsSQL);
//   - kev: shortDescription of the latest KEV entry.
//
// A text matches when it equals Description after trimming surrounding
// white space. Several matches: cvelist first, then GHSA advisories by id,
// then kev. No match (the record changed since, or a source of the text is
// no longer stored): nil, and the page says only that the text is upstream
// text. All three sources are public (public.go).

// DescSource is the upstream record a description was taken from.
type DescSource struct {
	Source string // "cvelist" | "ghsa" | "kev"
	Key    string // its raw record key: the CVE id, or the GHSA id
}

// descSourceSQL: (source, key, text) candidates of $1, see above.
const descSourceSQL = `
SELECT 'cvelist', c.source_key, d->>'value'
FROM (SELECT source_key, payload FROM raw_record WHERE source = 'cvelist' AND source_key = $1
      ORDER BY fetched_at DESC, id DESC LIMIT 1) c,
     jsonb_array_elements(CASE WHEN jsonb_typeof(c.payload #> '{containers,cna,descriptions}') = 'array'
                               THEN c.payload #> '{containers,cna,descriptions}' ELSE '[]' END) AS d
WHERE jsonb_typeof(d) = 'object' AND jsonb_typeof(d->'value') = 'string'
UNION ALL
SELECT 'ghsa', g.source_key, g.payload->>'description'
FROM (` + ghsaLatestSQL + `) g
WHERE jsonb_typeof(g.payload->'description') = 'string'
UNION ALL
SELECT 'kev', k.source_key, k.payload->>'shortDescription'
FROM (SELECT source_key, payload FROM raw_record WHERE source = 'kev' AND source_key = $1
      ORDER BY fetched_at DESC, id DESC LIMIT 1) k
WHERE jsonb_typeof(k.payload->'shortDescription') = 'string'`

// descText is one row of descSourceSQL.
type descText struct {
	Source, Key, Text string
}

// descSourceRank orders matching sources (see above).
var descSourceRank = map[string]int{"cvelist": 0, "ghsa": 1, "kev": 2}

// matchDescSource returns the record whose text is desc (nil: none, or no
// description).
func matchDescSource(desc *string, texts []descText) *DescSource {
	if desc == nil {
		return nil
	}
	want := strings.TrimSpace(*desc)
	if want == "" {
		return nil
	}
	var best *descText
	for i := range texts {
		t := &texts[i]
		r, ok := descSourceRank[t.Source]
		if !ok || !IsPublicSource(t.Source) || strings.TrimSpace(t.Text) != want {
			continue
		}
		if best == nil || r < descSourceRank[best.Source] || (r == descSourceRank[best.Source] && t.Key < best.Key) {
			best = t
		}
	}
	if best == nil {
		return nil
	}
	return &DescSource{Source: best.Source, Key: best.Key}
}
