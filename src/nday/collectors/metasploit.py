"""Metasploit Framework module metadata collector -> poc_published.

Upstream facts (verified 2026-11-12 against the live file):
- ``https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json``
  (~11.4 MB plain, ~1.4 MB gzip; BSD-3-Clause repo): one JSON object mapping
  "<type>_<ref_name>" -> module. 7,265 modules (exploit 2723, payload 2651,
  auxiliary 1371, post 436, encoder 57, nop 14, evasion 13).
- Module fields: name, fullname, aliases, rank, disclosure_date, type, author,
  description, references, platform, arch, rport, autofilter_ports,
  autofilter_services, targets, mod_time, path, is_install_path, ref_name,
  check, post_auth, default_credential, notes, session_types, needs_cleanup
  (+ actions / payload-only keys). ``fullname`` is unique.
- ``references`` is a list of strings like "CVE-2007-4387", "OSVDB-...",
  "URL-...", "EDB-..."; 2 CVE refs carry a trailing space (stripped here).
- Timestamps: ``disclosure_date`` (YYYY-MM-DD or null) is the VULNERABILITY's
  disclosure date; ``mod_time`` ("YYYY-MM-DD HH:MM:SS +0000") is the module
  file's last modification. Neither says when the module was first published,
  and the file has no such field, so occurred_at is None. Both go to detail as
  ``vuln_disclosure_date`` / ``module_last_modified``. (A later, non-backfill
  run still dates NEW modules by our observation time via the pipeline.)
- raw.githubusercontent.com returns an ETag (no Last-Modified) and honours
  If-None-Match with 304; the gzip variant has its own weak ETag, see _feed.

Scope: module types ``exploit`` and ``auxiliary`` only. source_key = fullname,
payload = the module object verbatim. One event per valid CVE reference,
dedupe_key = fullname, url = the module source on GitHub.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nday.collectors._feed import FeedCollector, require_cves, text
from nday.collectors.base import NormalizeError
from nday.models import Event, Normalized, RawRecord

log = logging.getLogger(__name__)

MSF_METADATA_URL = ("https://raw.githubusercontent.com/rapid7/metasploit-framework/"
                    "master/db/modules_metadata_base.json")
MSF_SOURCE_URL = "https://github.com/rapid7/metasploit-framework/blob/master/{}"
IN_SCOPE_TYPES = ("exploit", "auxiliary")
# Msf::*Ranking constants (lib/msf/core/constants.rb).
RANK_NAMES = {0: "manual", 100: "low", 200: "average", 300: "normal", 400: "good",
              500: "great", 600: "excellent"}


def _cve_refs(payload: dict[str, Any]) -> list[str]:
    refs = payload.get("references")
    if not isinstance(refs, list):
        return []
    return [r for r in refs if isinstance(r, str) and r.strip().upper().startswith("CVE")]


class MetasploitCollector(FeedCollector):
    name = "metasploit"
    feed_url = MSF_METADATA_URL

    def parse_items(self, body: bytes) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, int]]:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("metasploit metadata: expected a JSON object")
        items: dict[str, dict[str, Any]] = {}
        out_of_scope = malformed = 0
        for mod in data.values():
            if not isinstance(mod, dict) or text(mod.get("fullname")) is None:
                malformed += 1
                log.warning("metasploit: module without fullname skipped: %.200r", mod)
                continue
            if mod.get("type") not in IN_SCOPE_TYPES:
                out_of_scope += 1
                continue
            key = mod["fullname"].strip()
            if key in items:
                malformed += 1
                log.warning("metasploit: duplicate fullname %s skipped", key)
                continue
            items[key] = mod
        extra = {"modules": len(data), "out_of_scope_types": out_of_scope,
                 "malformed_skipped": malformed}
        return list(items.items()), extra

    def cve_tokens(self, payload: dict[str, Any]) -> list[str]:
        return _cve_refs(payload)

    def normalize(self, record: RawRecord) -> Normalized:
        p = record.payload
        if not isinstance(p, dict):
            raise NormalizeError("payload is not an object")
        fullname = text(p.get("fullname"))
        if fullname is None or fullname != record.source_key:
            raise NormalizeError(f"fullname {p.get('fullname')!r} != source_key {record.source_key}")
        if p.get("type") not in IN_SCOPE_TYPES:
            raise NormalizeError(f"{fullname}: out-of-scope type {p.get('type')!r}")
        if not isinstance(p.get("references"), list):
            raise NormalizeError(f"{fullname}: references is not a list")
        cves, dropped = require_cves(fullname, _cve_refs(p))

        path = text(p.get("path"))
        url = MSF_SOURCE_URL.format(path.lstrip("/")) if path else None
        rank = p.get("rank")
        detail: dict[str, Any] = {
            "kind": "msf_module",
            "confidence": "curated",
            "title": text(p.get("name")),
            "url": url,
            "fullname": fullname,
            "module_type": p.get("type"),
            "rank": rank,
            "rank_name": RANK_NAMES.get(rank) if isinstance(rank, int) else None,
            "vuln_disclosure_date": text(p.get("disclosure_date")),
            "module_last_modified": text(p.get("mod_time")),
            "path": path,
            "check": p.get("check"),
            "cve_ids": cves,
        }
        if dropped:
            detail["dropped_cve_tokens"] = dropped
        out = Normalized()
        for cve in cves:
            out.events.append(Event(cve_id=cve, type="poc_published", source=self.name,
                                    occurred_at=None, url=url, detail=detail,
                                    dedupe_key=fullname))
        return out
