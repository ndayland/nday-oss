# en — English (primary) · notes

Catalog: `internal/webui/i18n/catalogs/en.json` · golden: `internal/webui/testdata/golden/en.txt`

## 1. Audience and register

Security engineers, SOC/IR analysts, vulnerability-management and patch
teams, researchers — people who read NVD, CISA KEV, GitHub advisories and
vendor bulletins daily. English here is original copy for them, not a
rendering of the Chinese site.

- Terse, declarative, terminal-flavoured. Lower-case UI labels (`copy`,
  `last run`, `stage`) like a CLI; sentence case for headings
  (`Event log`, `Affected & fixed`).
- The navigation is the path itself (`~/hot`, `~/vuln`, `~/stats`, `~/src`):
  English readers parse it without a gloss, so `nav.*` is just `{path}`.
- No "please", no exclamation marks, no hedging adverbs. Facts first.
- The home list is "Just moved": vulnerabilities that just reached a later
  stage. Chosen over "Trending"/"Hot" (popularity, which nday does not
  measure) and over "Heating up" (a calque of 升温).

## 2. Terminology

| Concept | Wording | Why / source |
| --- | --- | --- |
| DIS | disclosed / disclosure | CVE record publication time is the disclosure proxy; CVE Program wording |
| PAT | patch, patch on record, fixed in | "fixed in 2.2.0" is GHSA/vendor advisory phrasing |
| ANA | technical analysis | neutral; avoids "write-up" (informal) |
| POC | public PoC | community standard abbreviation; "exploit code" for Exploit-DB entries (its own term) |
| ITW | exploited in the wild / exploitation in the wild | CISA, Google TAG, vendor bulletins |
| KEV | CISA KEV, Known Exploited Vulnerabilities catalog | CISA's own name; "added to KEV" mirrors CISA's "added to the catalog" |
| due_date | remediation deadline | CISA BOD 22-01 language ("remediation due date") |
| forensic triage | forensic triage | KEV field name, kept |
| CNA | "published by {assigner}" | the CNA short name is shown as-is (`GitHub_M`) |
| CVSS severity | critical / high / medium / low / none | FIRST CVSS v3/v4 rating names, lower-case in running text |
| SSVC | "CISA's SSVC assessment rates exploitation as active" | SSVC decision point "Exploitation" with values `active`/`poc` kept as tokens |
| fixed version | fixed version(s) | GHSA "first patched version" |
| bulk import | bulk import, not observed live | describes the data path plainly |
| collectors | collectors | matches the CLI (`nday collect`) |
| backfill | backfill, backfill queue | the cvelist backfill job |
| rejected | REJECTED (state token) / rejected | CVE record state is upper-case in the record |
| tags (`tag.*`) | weakness classes by their CWE/OWASP names ("SQL injection", "broken access control"); "remote, unauthenticated"; "ransomware use" | the English label of each tag is also the API label (`internal/tags/vocab.go`); a tag is always "derived by nday", never attributed to NVD or the CNA |

- 2026-11-14 (`rsch.`, `veil.`, `discussed.`, `nav.discussed`): "researcher discussion" for the section of X posts; "researchers are discussing" for `/discussed`; "mentioned this" = posted about it on X. The placeholder sentences say "Sign in to read N posts/comments" — they are also what screen readers get instead of the speckle.

## 3. Honesty vocabulary

| Idea | Wording |
| --- | --- |
| unknown | "time unknown", "disclosure time unknown", "Ransomware use: unknown." |
| inferred | "inferred from KEV", "inferred, no direct source" |
| not later than | `≤ {date}` + "only an upper bound is known" |
| not listed | "not listed" (PoC sources), "Not in CISA KEV." |
| no record yet | "no record yet", "No patch on record yet." (never "no patch") |

"Not in CISA KEV." deliberately says nothing about safety.

## 4. Typography

- Straight ASCII punctuation; curly quotes “…” around upstream titles and
  quoted UI terms; em dash — for asides; `→` in `disclosure → KEV` labels.
- Oxford comma in prose lists (`list.and.end` = "{a}, and {b}"); compact
  lists use plain commas (`list.seq.*`).
- `sentence.joiner` is a single space; `strip.sep` is "; ".
- Numbers: `45,965`.

## 5. Open doubts

- `status.patch.fixed` uses the same text for one/other ("Patched: fixed in
  …"); fine in English, kept as plural only so other languages can inflect.
- `chart.mark.more` / `chart.unknown.fixed_many` render "+2 more" — compact
  by design (chart labels at 11px).
- `fact.kev_due` "KEV due date" vs. the Chinese `kev.due_date` field-name
  style: English readers don't need the field name.
