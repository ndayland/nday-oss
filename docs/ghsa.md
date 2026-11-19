# GitHub advisories without a CVE

## The id rule

A vulnerability's main id is its CVE id; the GHSA id is the second id.

- An advisory **with** a CVE is recorded under the CVE, and the GHSA id is an alias (`vuln_alias`, `alias_type = 'ghsa'`). Unchanged.
- An advisory **without** a CVE is recorded as a vulnerability whose id is the GHSA id.
- When a CVE turns up for it later, the record and everything attached to it move to the CVE id, and the GHSA id becomes an ordinary alias.

The column keeps its name: `vuln.cve_id`, and every `cve_id` that references it, holds the vulnerability's id, which is either a CVE id or a GHSA id (`migrations/0026_vuln_id_ghsa.sql`). A GHSA id is always stored in GitHub's canonical form, `GHSA-xxxx-xxxx-xxxx` with the three groups in lower case from `23456789cfghjmpqrvwx` (`model.IsGHSAID`). `model.IsValidVulnID` accepts either kind of id. cvelist, nvd and kev still only accept CVE ids (`model.IsValidCVEID`).

## What an advisory without a CVE produces

`internal/collector/ghsa/normalize.go`, mirrored in `src/nday/collectors/ghsa.py`:

| | not withdrawn | withdrawn |
|---|---|---|
| vuln `G` | authoritative: summary, description, `published_at`, `modified_at` = `updated_at` | none |
| `disclosed` event | source `ghsa`, `occurred_at` = `published_at`, `dedupe_key` = `G`, url = `html_url`, detail `{ghsa_id, state: "PUBLISHED", withdrawn_at}` | the same event with `state: "REJECTED"` |
| `patch_released` event | exactly as for an advisory with a CVE (only if some package has a `first_patched_version`) | none |

A GHSA id never gets a stub vuln. Rows for a GHSA id that has no vuln row are skipped, so a withdrawn advisory that was never stored stores nothing. If it was stored, its disclosed event changes to `REJECTED`. `vuln_state.is_rejected` reads that event for GHSA-keyed rows (`migrations/0027_ghsa_vuln_classify.sql`), and so does the tag layer, so a withdrawn advisory looks like a rejected CVE: the row stays, and so do its comments.

An advisory **with** a CVE never emits the ghsa `disclosed` event, because the CVE record owns disclosure.

Classification: the `raw_record` trigger also queues the advisory's GHSA id (0027), and `classify.DeriveGHSA` keys an advisory without a CVE by its GHSA id. That gives the GHSA-keyed vuln `vuln_cwe`, `vuln_cvss` and `vuln_classify_input` rows (source `ghsa`, `source_org` = the GHSA id), and tags.

## The merge

`internal/pipeline/merge.go`. When the alias `(ghsa, G) -> C` is written while a vuln row `G` exists, `ApplyNormalized` calls `mergeVuln(G, C)` in the same transaction. That happens when the advisory gains a `cve_id`, and also when a CVE record names the advisory first. `mergeVuln`:

1. Takes its locks (order explained under "Concurrency" below): the corrections lock of `G`, `G`'s threads (top-level comments), then both vuln rows `FOR UPDATE` in id order. If `C` doesn't exist yet, it creates it from `G`'s fields. Otherwise it fills only `C`'s empty fields (the stub rule) and keeps the earlier `first_seen_at`.
2. Moves every row keyed by `G` to `C`: `event`, `vuln_alias`, `affected`, `vuln_cwe`, `vuln_cvss`, `vuln_classify_input`, `vuln_tag`, `vuln_tag_suppress`, `x_post_no_cve_link`, `x_draft`, `comments` (threads and replies in one statement), `vuln_corrections`, `classify_queue` and `tag_queue`. When `C` already has a row with the same key, `C`'s row is kept and `G`'s is dropped. Drafts that point at a dropped event are repointed to `C`'s event with the same key. Comments and corrections have no such key, so they always move.
3. `x_draft` (one per vuln and stage): where both have a draft for a stage, the one staff got furthest with stays, `posted` over `discarded` over `draft`; on a tie `C`'s stays. When the one dropped was decided (`posted` or `discarded`), a warning is logged with its id, stage, status and `post_url` (`merge of G into C dropped a decided x_draft id=… stage=… status=… post_url=… kept=…`), so nothing staff decided disappears without trace. `admin_audit` rows about that draft (target `x_draft`, target id = the draft id, no foreign key) stay, since the table is append-only; their link on the audit page then points at a draft that no longer exists.
4. The advisory's `disclosed` event moves only if `C` has no disclosed event from another source. Until the CVE record is ingested, it's the vulnerability's only disclosure. When the CVE record's disclosed event is written later, the pipeline deletes the ghsa one.
5. A **withdrawn** advisory contributes nothing to the CVE. Withdrawn means: the latest stored raw record of `G` has `withdrawn_at` (the ghsa run stores the version before it applies it, so this covers an advisory withdrawn in the same version in which it gains its CVE, where normalize returns only the alias), or, with no raw record, `G`'s disclosed event says `REJECTED` (withdrawn earlier, named by a CVE record later). Then `G`'s events from source `ghsa`, its `vuln_cwe`, `vuln_cvss` and `vuln_classify_input` rows from source `ghsa` and its rule tags are dropped, not moved, and `C` takes none of `G`'s fields (a missing `C` is created bare). Comments, corrections, staff tags, suppressions, drafts and other sources' events still move. `classify` derives `C` from the advisory's latest version anyway, which gives a withdrawn advisory no rows.
6. Deletes the `G` vuln row and leaves the alias in place. It queues `C` in `classify_queue` and `tag_queue`. `vuln_state_mat` drops `G` and shows `C` at the refresh after the run.
7. Logs one line: `merged vuln G into C created_target=… withdrawn=… moved=… dropped=…`.

It's idempotent: if there's no `G` row it does nothing.

Two more rules keep a GHSA-keyed vuln from ever sitting next to an alias row for the same GHSA id:

- `redirectGHSA`: rows that a record wants to write under a GHSA id that's already an alias go to the alias's vuln instead. The vuln upsert becomes a stub, and the ghsa disclosed event is left out if the target has another disclosure.
- If the advisory's CVE changes upstream from C1 to C2, the alias stays with C1. The unique key is `(alias_type, alias)` and the first CVE wins, as before. C2 gets the advisory's stub and events like any CVE advisory, and the GHSA id doesn't come back as a vuln.

## Concurrency

Vuln rows were never deleted before this change; the merge deletes `G`. What keeps that safe:

- **Two collector runs.** The ghsa run that writes `G` and a cvelist run that writes the alias both take a transaction-level advisory lock on `G` before they look at the alias or the row, so one of them sees what the other committed. A run is one transaction that holds every lock until it commits, and collectors start within the same 300 s window (`nday-collect@.timer`), so the order across records matters too: `RunCollector` and `Renormalize` first store the raw records, then take the GHSA-id locks of every record they will apply (`pipeline.LockGHSAIDs`, sorted), and only then apply the records. A run therefore never holds a vuln row while it waits for a GHSA-id lock, which rules out the cycle "the ghsa run holds row `C` (upserted for an earlier advisory naming `C`) and wants lock `G`; the cvelist run holds lock `G` and wants row `C`" (`TestCrossRunGHSALockNoDeadlock`). Vuln *row* locks of two runs can still meet in opposite orders, as they always could for CVE rows. PostgreSQL then aborts one run with `deadlock detected`. Nothing of it is half-applied: `RunCollector` stores the raw records, applies them and saves the cursor in one transaction (`pgx.BeginFunc`), which is rolled back; the failure is then recorded with the previous cursor kept (`saveState(…, success=false)`), so the next timer tick fetches and applies the same records again. `internal/cveimport` calls `ApplyNormalized` per batch without `LockGHSAIDs`; its batches can still meet a collector run that way and are retried the same way.
- **Comments and corrections** (`pipeline.lockForMerge`). A reply locks its parent comment `FOR SHARE` and then needs `G`'s vuln row (foreign key). So the merge locks in this order: (1) the corrections lock of `G` (the per-vulnerability advisory lock a submission takes before its insert; a submission waiting there then finds no vulnerability and gets the not-found error), (2) `G`'s threads (top-level comments, the rows a reply locks) `FOR UPDATE`, waiting for any edit, hide, delete, report or reply in flight to commit, (3) both vuln rows `FOR UPDATE`, waiting for new threads and corrections in flight and blocking new ones, (4) `G`'s threads again with `NOWAIT`: a thread created between (2) and (3) may already be locked by a reply that now waits for (3). Instead of waiting, which would deadlock, the merge rolls back to a savepoint taken before (2), releasing the vuln rows, and starts over (at most 10 times, then the run fails and is retried). A post or submission that waited for the merge and runs after it gets 404 `not_found`: discuss and corrections map the foreign-key violation on the vuln (and on a parent that moved with its thread) to their not-found error, and retry a transaction once on `deadlock detected`.
- **Background jobs.** `classify`, `tags` and the X-draft pass now write rows for a vuln that may be deleted. `classify` and `tags` lock the vuln rows of a batch `FOR KEY SHARE SKIP LOCKED` (`classify.LockVulns`) before they read, so a merge cannot delete one before the batch writes. A row another transaction holds (a merge, or a collector's upsert) is skipped, not waited for, so the batch never holds rows it rewrites while it waits on a merge. The skipped id stays queued: a `--pending` pass keeps its queue rows, and the other modes queue it. Stats report it as `busy`. The X-draft pass holds the event table, which a merge needs to move the events, so it locks the vuln rows of the drafts it may create `NOWAIT` and defers with `deferred: vuln_busy` (watermark unchanged, recorded like `lock_busy`) when one is held.

## Backfill (deploy)

Advisories without a CVE that were collected before this change have a stored raw record. A normal `collect ghsa` skips them as unchanged. After deploying the migrations (`nday migrate`, applying 0026 and 0027), re-normalize the stored records offline, without any network access:

```sh
nday renormalize ghsa --dry-run   # check the counts first (rolled back)
nday renormalize ghsa
nday classify --pending
nday tags --pending
```

`renormalize` refreshes `vuln_state_mat` itself (or run `nday refresh-state`). Events it creates are marked `is_backfill = true`. The disclosed event has `occurred_at` (published_at), so its place on the timeline doesn't depend on that flag. `classify --pending` picks up the new GHSA-keyed vulns, because inserting a vuln queues it. Running `nday classify --source ghsa` re-derives every advisory, if you'd rather be thorough.

## Known limits

- Only the Go pipeline redirects and merges. The Python reference mirrors normalize and the "no stub for a GHSA id" rule, nothing more (docs/go.md).
- An alias is sticky. If an advisory loses its `cve_id` upstream, its rows keep going to the CVE the alias names.
- `admin_audit` is append-only, so audit rows that name `G` in `details.cve` keep naming `G`.
- GitHub repositories: `github_repo_cve` and `github_search_cve` hold CVE and GHSA ids as found and resolve them through `vuln_alias` when read, so nothing of theirs moves in a merge (`docs/github.md`, "GHSA ids").
- `nday classify --cve` and `nday tags --cve` parse their arguments with `site.ParseCVEID`, so they don't accept GHSA ids. Use `--pending` or `--source ghsa`.
- Two collector runs whose vuln row locks meet in opposite orders can still deadlock (see "Concurrency"); the aborted run rolls back whole and is retried at the next timer tick. GHSA-id locks are taken before any row lock, so they are no longer part of such a cycle.
- If one transaction ever both row-locked `G` and later merged it (a run applying two versions of the same advisory), a reply waiting for `G` could still deadlock with it. `RunCollector` applies one version per advisory and `Renormalize` only the latest, so this does not happen today.
- Comments and corrections are the only web writes that reference a vuln row. A new writer of a per-vuln table must expect the row to go away under it (map the foreign-key error, or lock the row as `classify.LockVulns` does).
