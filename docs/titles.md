# Vulnerability titles

57.7% of the vulnerabilities (247,191 of 428,301, measured on production, 2026-11-19) have no title in their record: every Oracle CVE, for one, carries only a boilerplate description. nday shows such a vulnerability with a title of its own, and staff can set a better one by hand.

- **Effective title** = the staff title, else the record's title (`vuln.title`; `title_zh` on Simplified Chinese pages), else the composed title. A vulnerability with none of them stays untitled and keeps its placeholder ("(the CVE record has no title)").
- `vuln.title` is never written: it stays what the sources delivered. Composed and staff titles live in `vuln_title` (migration `0031_vuln_title.sql`, a 1:1 side table: the backfill writes 428k rows without rewriting or locking the wide `vuln` rows the collectors upsert).
- The JSON API keeps `title` and adds `effective_title` and `title_origin` (`staff` | `record` | `composed`); see `docs/api.md`.

## 1. Composition rule (`internal/titles`, rule version 1)

Deterministic, from structured data already in the database; no external service, no language model.

1. Nothing is composed when the record has a title.
2. **Product**: the label of the vulnerability's product tag when it has exactly one (`Java SE`); else the first affected row (first reported) that names a product: the product alone when it already names the vendor (`Oracle Java SE`; vendor `Apache Software Foundation`, product `Apache Tomcat`; vendor `Hewlett Packard Enterprise (HPE)`, product `HPE iLO 5`) or the vendor is missing, else `vendor product` (`Google Chrome`). Company-form suffixes (`Corporation`, `Inc.`, `Co., Ltd.`, `GmbH`, `SE` …), a leading `The` and a trailing `(short name)` are dropped from the vendor; placeholders (`n/a`, `unspecified`, …) name nothing. At most 60 characters (cut at a word, with `…`). No "and N more".
3. **Weakness**: the first type tag in vocabulary display order (`internal/tags` vocabulary; stored as its slug, shown with the tag's localised name).
4. **Component**: only an explicit, anchored mention in the description, first match wins: Oracle's `(component: X)`, VulDB's `of the component X.`, `in the X component` (a capitalised name), `The X component of|in …` at a sentence's start. At most 40 characters and six words, never cut, never a guess; dropped when the product already contains it.
5. **Forms**: `full` "{product}: {weakness} in {component}", `weakness` "{product}: {weakness}", `component` "{product}: vulnerability in {component}". A product alone is not a title: then (and without a product) `excerpt`: the description's first sentence (abbreviations such as `e.g.`, initials and version numbers do not end it; rejection notices yield nothing; leading `** DISPUTED **` markers are dropped), without its final period, cut at a word to at most 100 characters with `…`. No usable description: untitled.
6. **Untrusted input**: every text is cleaned before use (`titles.Clean`): HTML tags removed and entities decoded, backticks removed, control characters and line separators become spaces, format characters (bidi embeddings, overrides and isolates, zero-width characters) are dropped, white space collapsed, NFC. Every sink escapes the result (HTML templates, JSON, the Atom feed, the share card, the X draft body's own cleaning).

Example (CVE-2026-114938: product tag `java-se`, type tag `buffer-overflow`, description "… product of Oracle Java SE (component: Compiler). …"): en "Java SE: buffer overflow / out-of-bounds write in Compiler", zh-Hans "Java SE：Compiler 中的 buffer overflow / out-of-bounds write".

Stored per vulnerability: `rule_version`, `form`, `product`, `weakness`, `component`, `excerpt` and the English rendering `composed_en` (API, feed, share card, X drafts, search). Pages render the parts in the visitor's language: the joining pattern `title.composed` (select on the form, all 7 locales) around the product and component as the record names them and the weakness's tag name (`tag.name`); an excerpt is the record's English text (`lang="en"` outside English).

Bump `titles.RuleVersion` whenever `Compose` changes its output for some input, then run `nday titles` (it recomposes every row of an older version).

## 2. Maintenance

The composed parts are recomputed by the tag pass, right after a CVE's tags, in the same transaction (`internal/tags` `processBatch` → `composeTitles`), for every CVE of the batch. Every input reaches the pass through `tag_queue`, in the same transaction as the write:

| Input | Trigger |
|---|---|
| a new vulnerability; its title or description | `vuln_title_ins` / `vuln_title_upd` on `vuln` (0031; an update queues only when `title` or `description` changed) |
| affected rows | `affected_tag_*` (0013) |
| type and product tags (classification, NVD CPEs) | the tag inputs' triggers (0011, 0013); the pass derives the tags first |
| a suppressed tag | `vuln_tag_suppress_tag_*` (0011) |
| a staff tag row | `vuln_tag_staff_*` (0031; rule rows are written by the pass itself and are not watched) |

So no separate scan is needed in normal operation. `nday tags --all` recomposes everything too.

## 3. Backfill: `nday titles [--all] [--limit N] [--batch-size N]`

Composes the vulnerabilities without a `vuln_title` row of the current rule version (`--all`: every vulnerability), in `cve_id` order, 1000 per batch (`--batch-size`, 1–20000), each batch its own short transaction: the vuln rows are taken `FOR KEY SHARE SKIP LOCKED` (a row a collector holds is skipped and queued for the tag pass), only `vuln_title` is written. It holds the tag run lock (a tag pass after a collector run meanwhile skips and leaves its queue for the next one). Resumable (a stopped run leaves the rest lacking; the next run continues), idempotent (rows already equal are not written). Prints a JSON summary: `rule_version`, `all`, `considered`, `composed` (by form), `record_title`, `untitled`, `written`, `busy`, `batches`, `done` (false when `--limit` stopped it), `duration_sec`.

Measured locally (Apple silicon, PostgreSQL 16 in Docker): 250,000 synthetic vulnerabilities (145,000 composed) in 11.2 s, about 22,000 rows/s; a second run 0.08 s. Expect well under a few minutes for production's 428k on the VPS.

Search: `composed_en` and `staff_title` have trigram indexes (`vuln_title_composed_trgm_idx`, `vuln_title_staff_trgm_idx`; 19 MB for the 145k synthetic titles above); the text search matches them like the record's titles.

## 4. Staff titles

An admin sets a title by hand on `/admin/titles` (docs/admin.md §2.4, §4.6): 1–160 characters, one line, no control or bidi characters, NFC; optimistic concurrency on `staff_version`; one audit row per change (`vuln.title_set`, `vuln.title_clear`, with the old and the new title). A cleared title falls back to the record's or the composed one. A GHSA merge moves the staff title to the CVE unless the CVE has its own.

## 5. Display

A composed or staff title is shown like any title (not dimmed), followed by one small marker (`parts.tmpl` "titlemark": a dim `*` joined to the last word by U+2060, its `title` tooltip and screen-reader text say "Title composed by nday; the CVE record has none." or "Title set by nday staff."). The record's own title has no marker. Same marker in the lists (hot, tag pages, /discussed, search) and the vulnerability page's heading. `<title>`, the meta description, the share card and the feed carry the effective title.
