"""CISA Known Exploited Vulnerabilities (KEV) catalog collector.

Feed fields verified against the live feed (catalogVersion 2026.11.10):
top level: title, catalogVersion, dateReleased, count, vulnerabilities[];
entry: cveID, vendorProject, product, vulnerabilityName, dateAdded,
shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
notes, cwes, forensicTriage.

KEV says a CVE was added to the catalog on `dateAdded`; it does NOT say when
exploitation began, so only `kev_added` is emitted (never exploited_in_wild).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
import logging

import httpx

from nday import USER_AGENT
from nday.collectors.base import Collector, NormalizeError
from nday.models import (
    Affected,
    CollectorState,
    Event,
    FetchResult,
    Normalized,
    RawRecord,
    VulnUpsert,
    is_valid_cve_id,
)

log = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _parse_day(value: object) -> datetime | None:
    """'YYYY-MM-DD' -> that date 00:00 UTC; anything else -> None."""
    s = _text(value)
    if s is None:
        return None
    try:
        d = date.fromisoformat(s)
    except ValueError:
        return None
    return datetime(d.year, d.month, d.day, tzinfo=UTC)


class KevCollector(Collector):
    name = "kev"

    def __init__(self, client: httpx.Client | None = None, url: str = KEV_FEED_URL):
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=60.0, follow_redirects=True)
        self.url = url

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def fetch(self, state: CollectorState) -> FetchResult:
        resp = self.client.get(self.url, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        items = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ValueError("KEV feed: missing 'vulnerabilities' array")

        records: list[RawRecord] = []
        seen: set[str] = set()
        for item in items:
            cve = _text(item.get("cveID")) if isinstance(item, dict) else None
            if cve is None:
                log.warning("KEV entry without cveID skipped: %r", item)
                continue
            if cve in seen:
                log.warning("duplicate KEV entry for %s skipped", cve)
                continue
            seen.add(cve)
            records.append(RawRecord(source=self.name, source_key=cve, payload=item))

        cursor = {k: data.get(k) for k in ("catalogVersion", "dateReleased", "count")}
        return FetchResult(records=records, cursor=cursor)

    def normalize(self, record: RawRecord) -> Normalized:
        p = record.payload
        cve = _text(p.get("cveID"))
        if cve is None or not is_valid_cve_id(cve):
            raise NormalizeError(f"bad cveID: {p.get('cveID')!r}")

        out = Normalized()
        out.vulns.append(
            VulnUpsert(
                cve_id=cve,
                title=_text(p.get("vulnerabilityName")),
                description=_text(p.get("shortDescription")),
                authoritative=False,
            )
        )
        vendor, product = _text(p.get("vendorProject")), _text(p.get("product"))
        if vendor and product:
            out.affected.append(Affected(cve_id=cve, vendor=vendor, product=product))

        occurred_at = _parse_day(p.get("dateAdded"))
        detail: dict[str, object] = {
            "date_added": p.get("dateAdded"),
            "vendor_project": p.get("vendorProject"),
            "product": p.get("product"),
            "vulnerability_name": p.get("vulnerabilityName"),
            "known_ransomware_campaign_use": p.get("knownRansomwareCampaignUse"),
            "required_action": p.get("requiredAction"),
            "due_date": p.get("dueDate"),
            "notes": p.get("notes"),
            "cwes": p.get("cwes"),
            "forensic_triage": p.get("forensicTriage"),
        }
        if occurred_at is not None:
            detail["precision"] = "day"
        out.events.append(
            Event(
                cve_id=cve,
                type="kev_added",
                source=self.name,
                occurred_at=occurred_at,
                url=KEV_CATALOG_URL,
                detail=detail,
                dedupe_key="",
            )
        )
        return out
