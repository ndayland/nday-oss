"""Plain data types shared by collectors and the pipeline (no ORM)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")

EVENT_TYPES = frozenset(
    {
        "disclosed",
        "patch_released",
        "analysis_published",
        "poc_published",
        "exploited_in_wild",
        "kev_added",
    }
)


def is_valid_cve_id(value: str) -> bool:
    return CVE_ID_RE.fullmatch(value) is not None


def _require_cve(value: str) -> None:
    if not is_valid_cve_id(value):
        raise ValueError(f"invalid CVE id: {value!r}")


def _require_aware(dt: datetime | None, name: str) -> None:
    if dt is not None and dt.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RawRecord:
    """One upstream record, verbatim. `source_key` identifies it within `source`.

    is_backfill: set by a collector when this record was fetched on demand for a
    CVE we already knew about (e.g. cvelist filling in an old CVE referenced by
    KEV), i.e. NOT observed live as an upstream change. The pipeline then stores
    its events with is_backfill=true even on an incremental run, so our fetch time
    is never mistaken for the event time. It is metadata about how we got the
    record: it is not part of `payload`, so `content_hash` and raw storage are
    unaffected.
    """

    source: str
    source_key: str
    payload: dict[str, Any]
    is_backfill: bool = False

    @property
    def content_hash(self) -> str:
        return content_hash(self.payload)


@dataclass(frozen=True)
class VulnUpsert:
    """Vuln fields a collector knows.

    authoritative=False (stub): only fills fields that are currently NULL/empty;
    never overwrites existing non-empty values. Use for sources like KEV that
    are not the canonical description of a CVE.
    authoritative=True: non-None values overwrite existing ones (e.g. the CVE
    list collector). None never erases existing data in either mode.
    """

    cve_id: str
    title: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    authoritative: bool = False

    def __post_init__(self) -> None:
        _require_cve(self.cve_id)
        _require_aware(self.published_at, "published_at")
        _require_aware(self.modified_at, "modified_at")


@dataclass(frozen=True)
class Alias:
    cve_id: str
    alias: str
    alias_type: str

    def __post_init__(self) -> None:
        _require_cve(self.cve_id)


@dataclass(frozen=True)
class Affected:
    cve_id: str
    vendor: str
    product: str

    def __post_init__(self) -> None:
        _require_cve(self.cve_id)


@dataclass(frozen=True)
class Event:
    """A lifecycle event. observed_at / is_backfill are set by the pipeline,
    not by the collector, so normalize() stays pure.

    occurred_at: the time the SOURCE claims; None if unknown. Never invent it.
    dedupe_key: distinguishes multiple events of the same (cve, type, source),
    e.g. two different PoC URLs. Use "" when one per (cve, type, source).
    """

    cve_id: str
    type: str
    source: str
    occurred_at: datetime | None
    url: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""

    def __post_init__(self) -> None:
        _require_cve(self.cve_id)
        if self.type not in EVENT_TYPES:
            raise ValueError(f"invalid event type: {self.type!r}")
        _require_aware(self.occurred_at, "occurred_at")


@dataclass
class Normalized:
    """Everything derived from one RawRecord."""

    vulns: list[VulnUpsert] = field(default_factory=list)
    aliases: list[Alias] = field(default_factory=list)
    affected: list[Affected] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)


@dataclass(frozen=True)
class CollectorState:
    source: str
    cursor: dict[str, Any] | None = None
    last_run_at: datetime | None = None
    last_status: str | None = None
    last_error: str | None = None
    last_success_at: datetime | None = None
    # Filled by the pipeline (never stored) only for collectors that set
    # `Collector.wants_missing_cves`: CVE ids present in `vuln` for which this
    # source has never stored a raw record, newest CVE first, bounded by
    # `Collector.wanted_limit`. Empty for every other collector.
    wanted: tuple[str, ...] = ()

    @property
    def is_first_run(self) -> bool:
        """True until the collector has completed one successful run."""
        return self.last_success_at is None


@dataclass
class FetchResult:
    records: list[RawRecord]
    cursor: dict[str, Any] | None = None
