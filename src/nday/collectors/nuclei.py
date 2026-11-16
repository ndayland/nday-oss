"""ProjectDiscovery nuclei-templates CVE index collector -> poc_published.

Upstream facts (verified 2026-11-12 against the live file):
- ``https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json``
  (~2.3 MB plain, ~0.5 MB gzip; MIT repo) is JSON Lines: 4,606 objects
  ``{"ID", "Info": {"Name", "Severity", "Description",
  "Classification": {"CVSSScore"}}, "file_path"}``. ID is the template id,
  which equals the CVE id and the file name stem (e.g.
  http/cves/2021/CVE-2021-44228.yaml); IDs and paths are unique.
- The index has NO timestamps and NO tags, so occurred_at is None (a later,
  non-backfill run dates NEW templates by our observation time via the
  pipeline) and tags are not reported.
- raw.githubusercontent.com returns an ETag (no Last-Modified) and honours
  If-None-Match with 304; the gzip variant has its own weak ETag, see _feed.

Scope: everything in the index. source_key = ID, payload = the line's object
verbatim, one event (the template's CVE), dedupe_key = ID, url = the template
on GitHub.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nday.collectors._feed import FeedCollector, require_cves, text
from nday.collectors.base import NormalizeError
from nday.models import Event, Normalized, RawRecord

log = logging.getLogger(__name__)

NUCLEI_CVES_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
NUCLEI_SOURCE_URL = "https://github.com/projectdiscovery/nuclei-templates/blob/main/{}"


def _cve_token(payload: dict[str, Any]) -> list[str]:
    tid = payload.get("ID")
    return [tid] if isinstance(tid, str) and tid.strip().upper().startswith("CVE") else []


class NucleiCollector(FeedCollector):
    name = "nuclei"
    feed_url = NUCLEI_CVES_URL

    def parse_items(self, body: bytes) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, int]]:
        items: dict[str, dict[str, Any]] = {}
        lines = malformed = 0
        for line in body.decode("utf-8").splitlines():
            if not line.strip():
                continue
            lines += 1
            obj = json.loads(line)  # a broken line means a broken feed: fail the run
            key = text(obj.get("ID")) if isinstance(obj, dict) else None
            if key is None or key in items:
                malformed += 1
                log.warning("nuclei: line without ID or duplicate ID skipped: %.200r", obj)
                continue
            items[key] = obj
        return list(items.items()), {"lines": lines, "malformed_skipped": malformed}

    def cve_tokens(self, payload: dict[str, Any]) -> list[str]:
        return _cve_token(payload)

    def normalize(self, record: RawRecord) -> Normalized:
        p = record.payload
        if not isinstance(p, dict):
            raise NormalizeError("payload is not an object")
        tid = text(p.get("ID"))
        if tid is None or tid != record.source_key:
            raise NormalizeError(f"ID {p.get('ID')!r} != source_key {record.source_key}")
        info = p.get("Info")
        path = text(p.get("file_path"))
        if not isinstance(info, dict) or path is None:
            raise NormalizeError(f"{tid}: missing Info or file_path")
        (cve,), _ = require_cves(tid, _cve_token(p))

        url = NUCLEI_SOURCE_URL.format(path)
        cls = info.get("Classification") if isinstance(info.get("Classification"), dict) else {}
        detail: dict[str, Any] = {
            "kind": "detection_template",
            "confidence": "curated",
            "title": text(info.get("Name")),
            "url": url,
            "template_id": tid,
            "severity": text(info.get("Severity")),
            "cvss_score": cls.get("CVSSScore"),
            "template_path": path,
        }
        return Normalized(events=[Event(cve_id=cve, type="poc_published", source=self.name,
                                        occurred_at=None, url=url, detail=detail,
                                        dedupe_key=tid)])
