"""Collector interface.

How to write a collector
------------------------
Subclass `Collector`, set a unique `name` (it becomes `raw_record.source`,
`event.source` and `collector_state.source`), and implement two methods:

1. ``fetch(state) -> FetchResult``  (side effects allowed: network I/O)
   - `state` is the stored `CollectorState` (cursor from the last successful
     run, or `state.is_first_run` when there has never been one).
   - Return ALL upstream records you want considered as `RawRecord`s, each with
     a stable `source_key` (e.g. the CVE id) and the verbatim upstream JSON as
     `payload`. Do not filter "unchanged" records yourself: the pipeline hashes
     each payload and skips versions it already stored.
   - Return the new cursor in `FetchResult.cursor`. It is persisted only if the
     whole run succeeds, so an incremental collector can resume safely.
   - Send `nday.USER_AGENT`; never put personal names/emails/hostnames in
     requests.

2. ``normalize(record) -> Normalized``  (MUST be pure and deterministic)
   - Input: one RawRecord. Output: vuln upserts, aliases, affected rows and
     lifecycle events. No I/O, no clock reads: the pipeline sets
     `event.observed_at` (run time) and `event.is_backfill` itself.
   - `Event.occurred_at` is what the source claims; use None if unknown and
     never fabricate it. Put precision (e.g. ``{"precision": "day"}``) and
     source-specific facts in `Event.detail`.
   - Use `VulnUpsert(authoritative=False)` for stub/secondary info (only fills
     empty fields) and `authoritative=True` only for the canonical CVE source.
   - Raise `NormalizeError` for a malformed record; the pipeline logs it,
     keeps the raw record, and continues with the other records.
   - Because raw payloads are kept, normalize() can be re-run later
     (`nday collect <name> --renormalize`) after its logic changes.

Optional: on-demand backfill of CVEs other sources already reference
   - Set ``wants_missing_cves = True`` to receive, in ``state.wanted``, the CVE
     ids that are in ``vuln`` but for which this source has never stored a raw
     record (``raw_record.source = name AND source_key = cve_id``), newest CVE
     first (numeric year, then numeric sequence), at most ``wanted_limit`` ids.
     The pipeline computes this before ``fetch`` so fetch() stays DB-free; it is
     recomputed every run, so a collector may drop ids it cannot handle now.
   - Mark records fetched only because they were wanted with
     ``RawRecord(..., is_backfill=True)``: their events are stored with
     ``is_backfill=true`` (not observed live) even on an incremental run.
   - Collectors that do not opt in get ``state.wanted == ()`` and are unaffected.

Pipeline guarantees (see nday.pipeline.run_collector): fetch -> store raw
(skip unchanged by content hash) -> normalize changed records -> idempotent
upserts -> update collector_state, all data writes in one transaction. Running
a collector twice on unchanged upstream data creates zero new rows.

Register the class in `nday.collectors.COLLECTORS` to expose it to the CLI.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from nday.models import CollectorState, FetchResult, Normalized, RawRecord


class NormalizeError(ValueError):
    """A raw record could not be normalized (malformed upstream data)."""


class Collector(abc.ABC):
    name: ClassVar[str]
    # Opt-in for on-demand backfill (see module docstring). Default: off.
    wants_missing_cves: ClassVar[bool] = False
    # Max ids the pipeline puts in state.wanted (a collector may override,
    # also per instance, e.g. from its per-run cap).
    wanted_limit: int = 1000

    @abc.abstractmethod
    def fetch(self, state: CollectorState) -> FetchResult:
        """Fetch upstream records (+ new cursor). May do network I/O."""

    @abc.abstractmethod
    def normalize(self, record: RawRecord) -> Normalized:
        """Pure transformation of one raw record into normalized rows."""

    def close(self) -> None:
        """Release resources (HTTP clients etc.)."""
