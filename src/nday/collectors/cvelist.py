"""CVE List (CVE JSON 5, GitHub CVEProject/cvelistV5) collector.

Upstream facts (verified 2026-11-12 against the live repo):
- ``cves/deltaLog.json`` (raw.githubusercontent.com, ~41 MB plain / ~2.4 MB
  gzip): a JSON array of change sets, newest first, each
  ``{fetchTime, numberOfChanges, new[], updated[], error[]}``; items of
  new/updated are ``{cveId, cveOrgLink, githubLink, dateUpdated}``. It holds
  ~30 days (observed 3178 entries, 2026-10-13T13:54:47Z .. 2026-11-12T13:43Z,
  one entry every ~2-230 min, median ~8.5 min).
- Per-record files ``cves/<year>/<N>xxx/<CVE id>.json`` (a few KB each).
- Daily GitHub release ``cve_<YYYY-MM-DD>_at_end_of_day`` with asset
  ``<YYYY-MM-DD>_delta_CVEs_at_end_of_day.zip`` (~0.3-4 MB) containing
  ``deltaCves/<CVE id>.json`` for every CVE changed that UTC day; for
  2026-11-11 its 2198 ids equal exactly the ids of the deltaLog change sets
  whose fetchTime falls on that day. Download URLs are fixed by convention
  (github.com/.../releases/download/<tag>/<asset>), so no REST API call (60/h
  unauthenticated) is needed; a missing release returns 404.
- We never clone the repo or download the ~630 MB "all CVEs" baseline.

Strategy
- First run (no cursor): import the last ``bootstrap_days`` full UTC days
  (env NDAY_CVELIST_BOOTSTRAP_DAYS, default 7) from the end-of-day delta zips
  (one download per day), plus today's changes (and any day whose zip is not
  published yet) from deltaLog via per-record files. The cursor then points at
  the newest deltaLog fetchTime.
- Later runs: change sets in deltaLog with fetchTime > cursor; their CVE ids
  (deduplicated) are fetched as individual files, at most ``max_files`` per run
  (env NDAY_CVELIST_MAX_FILES, default 1000). Ids over the cap, and ids whose
  fetch failed after retries, are kept in ``cursor.pending`` and fetched first
  next run, so a skipped run or a burst never loses change sets.
- On-demand backfill (incremental runs only): the pipeline hands over
  ``state.wanted`` = CVEs in our ``vuln`` table (e.g. referenced only by KEV or
  GHSA) for which we never stored a cvelist raw record, newest first. They are
  queued AFTER ``pending`` and the new change-set ids, in the room left under
  ``max_files``; ids that do not fit are dropped for this run (the pipeline
  recomputes the list next run) and never enter ``pending``. Such records are
  flagged ``RawRecord.is_backfill`` so their events are stored as backfill.
  A wanted id whose file is 404 goes into ``cursor.backfill_missing``
  ({cve_id: time of the last 404}) and is not requested again for
  ``backfill_retry_days`` (env NDAY_CVELIST_BACKFILL_RETRY_DAYS, default 7);
  the map keeps at most MAX_BACKFILL_MISSING newest entries. A wanted id that
  fails transiently (5xx/timeouts after retries) is just dropped for this run.
  Counts are in ``cursor.last_run.backfill_*``.
- Falling behind: if the oldest change set still in deltaLog is newer than the
  cursor, the change sets in between have aged out of the ~30-day log. This is
  logged as a WARNING and appended to ``cursor.gaps`` (never silently skipped);
  repairing it (e.g. from the daily zips) is left to an operator.

Normalization
- One ``disclosed`` event per CVE (dedupe_key ""), occurred_at =
  cveMetadata.datePublished (None if absent). State, assigner, CVSS (CNA
  metrics, newest CVSS version first, else ADP containers) and CISA-ADP SSVC /
  KEV facts go into ``detail``.
- RESERVED records produce nothing (raw kept). REJECTED records: vuln row with
  published_at/modified_at only (no title/description), disclosed event with
  state=REJECTED and the rejection facts; nothing fabricated.
- Aliases: only ``containers.cna.source.advisory`` when it is a well-formed
  GHSA id (the field is free text; other values such as vendor ids are not
  typed, so they are ignored).
- patch_released / exploited_in_wild are NOT emitted (see README / report):
  reference "patch" tags carry no time, and CISA-ADP SSVC "Exploitation" is a
  mutable assessment, which an append-only event cannot retract.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import threading
import time
import zipfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

from nday import USER_AGENT
from nday.collectors.base import Collector, NormalizeError
from nday.models import (
    Affected,
    Alias,
    CollectorState,
    Event,
    FetchResult,
    Normalized,
    RawRecord,
    VulnUpsert,
    is_valid_cve_id,
)

log = logging.getLogger(__name__)

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DELTA_LOG_URL = f"{RAW_BASE}/deltaLog.json"
RELEASE_BASE = "https://github.com/CVEProject/cvelistV5/releases/download"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={}"

DEFAULT_BOOTSTRAP_DAYS = 7
MAX_BOOTSTRAP_DAYS = 30  # deltaLog reaches back ~30 days; zips are only for bootstrap
DEFAULT_MAX_FILES = 1000
CONCURRENCY = 4
MAX_ATTEMPTS = 4  # 1 try + 3 retries
BACKOFF_BASE = 1.0  # seconds: 1, 2, 4
MAX_RETRY_AFTER = 60.0
MAX_ZIP_BYTES = 100 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_GAPS_KEPT = 50
DEFAULT_BACKFILL_RETRY_DAYS = 7
MAX_BACKFILL_MISSING = 5000  # bound of cursor.backfill_missing

GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
ZIP_MEMBER_RE = re.compile(r"(?:^|/)(CVE-\d{4}-\d{4,})\.json$")
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")  # preference order


# --------------------------------------------------------------------------- helpers


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def parse_ts(value: object) -> datetime | None:
    """CVE JSON 5 timestamp -> aware datetime. The schema allows omitting the
    offset (meaning UTC). Unparseable/absent -> None (never fabricated)."""
    s = _text(value)
    if s is None:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def record_url(cve_id: str) -> str:
    """Path of a record file in the repo, e.g. cves/2026/108xxx/CVE-2026-108262.json."""
    _, year, num = cve_id.split("-")
    return f"{RAW_BASE}/{year}/{int(num) // 1000}xxx/{cve_id}.json"


def eod_zip_url(day: date) -> str:
    d = day.isoformat()
    return f"{RELEASE_BASE}/cve_{d}_at_end_of_day/{d}_delta_CVEs_at_end_of_day.zip"


def _ids_of(change_set: dict[str, Any]) -> Iterable[str]:
    for key in ("new", "updated"):
        for item in change_set.get(key) or []:
            cve = _text(item.get("cveId")) if isinstance(item, dict) else None
            if cve and is_valid_cve_id(cve):
                yield cve


def _dedupe(ids: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(ids))


def bf_got_any(got: dict[str, Any], backfill: set[str]) -> bool:
    return any(c in backfill for c in got)


# --------------------------------------------------------------------------- normalize helpers


def _english_description(cna: dict[str, Any]) -> str | None:
    descs = [d for d in cna.get("descriptions") or [] if isinstance(d, dict)]
    for exact in (True, False):
        for d in descs:
            lang = (_text(d.get("lang")) or "").lower()
            if (lang == "en") if exact else lang.startswith("en"):
                value = _text(d.get("value"))
                if value:
                    return value
    return None


def _cvss_from(metrics: object, source: str) -> dict[str, Any] | None:
    if not isinstance(metrics, list):
        return None
    for key in CVSS_KEYS:
        for m in metrics:
            c = m.get(key) if isinstance(m, dict) else None
            if isinstance(c, dict) and c.get("baseScore") is not None:
                return {
                    "version": c.get("version") or key[5:].replace("_", "."),
                    "base_score": c.get("baseScore"),
                    "base_severity": c.get("baseSeverity"),
                    "vector": c.get("vectorString"),
                    "source": source,
                }
    return None


def extract_cvss(containers: dict[str, Any]) -> dict[str, Any] | None:
    """CNA metrics first (newest CVSS version wins); else the first ADP
    container that has one. Returns None if no base score anywhere."""
    cna = containers.get("cna") or {}
    found = _cvss_from(cna.get("metrics"), "cna")
    if found:
        return found
    for adp in containers.get("adp") or []:
        if not isinstance(adp, dict):
            continue
        name = _text((adp.get("providerMetadata") or {}).get("shortName")) or "unknown"
        found = _cvss_from(adp.get("metrics"), f"adp:{name}")
        if found:
            return found
    return None


def _cisa_adp_facts(containers: dict[str, Any]) -> dict[str, Any]:
    """CISA-ADP SSVC decision points and KEV marker, verbatim values."""
    out: dict[str, Any] = {}
    for adp in containers.get("adp") or []:
        if not isinstance(adp, dict):
            continue
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        for m in adp.get("metrics") or []:
            other = m.get("other") if isinstance(m, dict) else None
            if not isinstance(other, dict):
                continue
            content = other.get("content") or {}
            if other.get("type") == "ssvc" and isinstance(content, dict):
                opts: dict[str, Any] = {}
                for o in content.get("options") or []:
                    if isinstance(o, dict):
                        opts.update(o)
                out["ssvc"] = {
                    "exploitation": opts.get("Exploitation"),
                    "automatable": opts.get("Automatable"),
                    "technical_impact": opts.get("Technical Impact"),
                    "timestamp": content.get("timestamp"),
                }
            elif other.get("type") == "kev" and isinstance(content, dict):
                out["kev"] = {
                    "date_added": content.get("dateAdded"),
                    "reference": content.get("reference"),
                }
    return out


# --------------------------------------------------------------------------- collector


class CveListCollector(Collector):
    name = "cvelist"
    wants_missing_cves = True

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        bootstrap_days: int | None = None,
        max_files: int | None = None,
        backfill_retry_days: int | None = None,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._owns_client = client is None
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(120.0, connect=15.0),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        days = bootstrap_days if bootstrap_days is not None else env_int(
            "NDAY_CVELIST_BOOTSTRAP_DAYS", DEFAULT_BOOTSTRAP_DAYS
        )
        if not 0 <= days <= MAX_BOOTSTRAP_DAYS:
            raise ValueError(f"bootstrap_days must be 0..{MAX_BOOTSTRAP_DAYS}, got {days}")
        cap = max_files if max_files is not None else env_int(
            "NDAY_CVELIST_MAX_FILES", DEFAULT_MAX_FILES
        )
        if cap < 1:
            raise ValueError(f"max_files must be >= 1, got {cap}")
        retry = backfill_retry_days if backfill_retry_days is not None else env_int(
            "NDAY_CVELIST_BACKFILL_RETRY_DAYS", DEFAULT_BACKFILL_RETRY_DAYS
        )
        if retry < 0:
            raise ValueError(f"backfill_retry_days must be >= 0, got {retry}")
        self.bootstrap_days = days
        self.max_files = cap
        self.backfill_retry = timedelta(days=retry)
        # Enough wanted ids to fill a whole run even if every id still inside its
        # 404 retry window (at most MAX_BACKFILL_MISSING) is among the newest ones.
        self.wanted_limit = cap + MAX_BACKFILL_MISSING
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sleep = sleep
        self.requests_made = 0  # HTTP requests incl. retries (for reporting)
        self._lock = threading.Lock()

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    # ------------------------------------------------------------------ HTTP

    def _get(self, url: str, *, allow_404: bool = False) -> httpx.Response | None:
        """GET with bounded retries + exponential backoff on 429/5xx/transport
        errors (honours Retry-After up to MAX_RETRY_AFTER). 404 -> None if
        allow_404, other 4xx raise immediately."""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            delay = BACKOFF_BASE * 2 ** (attempt - 1)
            try:
                with self._lock:
                    self.requests_made += 1
                resp = self.client.get(url, headers={"User-Agent": USER_AGENT})
            except httpx.TransportError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise
                log.warning("GET %s failed (%s), retry %d in %.0fs", url, exc, attempt, delay)
                self.sleep(delay)
                continue
            if resp.status_code == 404 and allow_404:
                return None
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == MAX_ATTEMPTS:
                    resp.raise_for_status()
                ra = resp.headers.get("Retry-After", "")
                if ra.isdigit():
                    delay = min(float(ra), MAX_RETRY_AFTER)
                log.warning("GET %s -> %d, retry %d in %.0fs", url, resp.status_code, attempt, delay)
                self.sleep(delay)
                continue
            resp.raise_for_status()
            return resp
        raise AssertionError("unreachable")

    def _delta_log(self) -> list[dict[str, Any]]:
        resp = self._get(DELTA_LOG_URL)
        data = resp.json()
        if not isinstance(data, list) or not all(
            isinstance(e, dict) and isinstance(e.get("fetchTime"), str) for e in data
        ):
            raise ValueError("deltaLog.json: expected a list of change sets with fetchTime")
        if not data:
            raise ValueError("deltaLog.json is empty")
        for e in data:
            if parse_ts(e["fetchTime"]) is None:
                raise ValueError(f"deltaLog.json: bad fetchTime {e['fetchTime']!r}")
        return sorted(data, key=lambda e: parse_ts(e["fetchTime"]))  # oldest first

    def _fetch_record(self, cve_id: str) -> tuple[str, str, dict[str, Any] | None]:
        """-> (cve_id, status, payload); status in ok | missing | failed."""
        try:
            resp = self._get(record_url(cve_id), allow_404=True)
            if resp is None:
                return cve_id, "missing", None
            payload = resp.json()
            if not isinstance(payload, dict):
                raise ValueError("record is not a JSON object")
            return cve_id, "ok", payload
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("could not fetch %s: %s", cve_id, exc)
            return cve_id, "failed", None

    def _fetch_records(self, ids: list[str]) -> tuple[dict[str, dict], list[str], list[str]]:
        got: dict[str, dict] = {}
        missing: list[str] = []
        failed: list[str] = []
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            for cve_id, status, payload in pool.map(self._fetch_record, ids):
                if status == "ok":
                    got[cve_id] = payload
                elif status == "missing":
                    missing.append(cve_id)
                else:
                    failed.append(cve_id)
        return got, missing, failed

    def _zip_records(self, day: date) -> dict[str, dict] | None:
        """Records from the end-of-day delta zip of `day`; None if not published."""
        resp = self._get(eod_zip_url(day), allow_404=True)
        if resp is None:
            return None
        if len(resp.content) > MAX_ZIP_BYTES:
            raise ValueError(f"{eod_zip_url(day)}: {len(resp.content)} bytes > limit")
        out: dict[str, dict] = {}
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for info in zf.infolist():
                m = ZIP_MEMBER_RE.search(info.filename)
                if not m or info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    log.warning("skipping oversized zip member %s", info.filename)
                    continue
                payload = json.loads(zf.read(info))
                if isinstance(payload, dict):
                    out[m.group(1)] = payload
        return out

    # ------------------------------------------------------------------ fetch

    def fetch(self, state: CollectorState) -> FetchResult:
        cursor = dict(state.cursor or {})
        if not cursor.get("last_fetch_time"):
            return self._bootstrap()
        return self._incremental(cursor, state.wanted)

    def _bootstrap(self) -> FetchResult:
        now = self.clock()
        changes = self._delta_log()
        today = now.astimezone(UTC).date()
        records: dict[str, dict] = {}
        zip_days: list[str] = []
        boundary_day = today
        for i in range(self.bootstrap_days, 0, -1):
            day = today - timedelta(days=i)
            recs = self._zip_records(day)
            if recs is None:  # not published (yet): this day onward comes from deltaLog
                log.info("no end-of-day zip for %s; using deltaLog from that day", day)
                boundary_day = day
                break
            records.update(recs)  # later days override earlier versions
            zip_days.append(day.isoformat())
        boundary = datetime(boundary_day.year, boundary_day.month, boundary_day.day, tzinfo=UTC)

        gaps: list[dict[str, Any]] = []
        oldest = parse_ts(changes[0]["fetchTime"])
        if oldest > boundary:
            gaps.append(self._gap(boundary.isoformat(), changes[0]["fetchTime"], now))

        ids = _dedupe(
            cve for e in changes if parse_ts(e["fetchTime"]) >= boundary for cve in _ids_of(e)
        )
        result = self._fetch_and_build(records, ids, pending=[], cursor={
            "last_fetch_time": changes[-1]["fetchTime"],
            "bootstrap": {
                "days": self.bootstrap_days,
                "zip_days": zip_days,
                "deltalog_from": boundary.isoformat(),
                "at": now.isoformat(),
            },
            "gaps": gaps,
        }, change_sets=sum(1 for e in changes if parse_ts(e["fetchTime"]) >= boundary))
        result.cursor["last_run"]["zip_records"] = len(records)
        return result

    def _incremental(self, cursor: dict[str, Any], wanted: Iterable[str] = ()) -> FetchResult:
        now = self.clock()
        changes = self._delta_log()
        last = cursor["last_fetch_time"]
        last_dt = parse_ts(last)
        if last_dt is None:
            raise ValueError(f"cursor.last_fetch_time is not a timestamp: {last!r}")

        gaps = list(cursor.get("gaps") or [])
        oldest = changes[0]["fetchTime"]
        if parse_ts(oldest) > last_dt:
            gaps.append(self._gap(last, oldest, now))
        newer = [e for e in changes if parse_ts(e["fetchTime"]) > last_dt]
        new_last = newer[-1]["fetchTime"] if newer else last

        pending = [p for p in cursor.get("pending") or [] if is_valid_cve_id(str(p))]
        ids = _dedupe(cve for e in newer for cve in _ids_of(e))
        out_cursor = {k: v for k, v in cursor.items() if k not in ("pending", "last_run")}
        out_cursor.update(last_fetch_time=new_last, gaps=gaps[-MAX_GAPS_KEPT:])
        return self._fetch_and_build({}, ids, pending=pending, cursor=out_cursor,
                                     change_sets=len(newer), wanted=list(wanted), now=now)

    def _missing_map(self, raw: object) -> dict[str, datetime]:
        """cursor.backfill_missing -> {cve_id: time of last 404}; junk dropped."""
        out: dict[str, datetime] = {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                t = parse_ts(v)
                if isinstance(k, str) and is_valid_cve_id(k) and t is not None:
                    out[k] = t
        return out

    def _gap(self, missed_from: str, log_starts: str, now: datetime) -> dict[str, Any]:
        log.warning(
            "cvelist fell behind: change sets between %s and %s are no longer in "
            "deltaLog.json (it keeps ~30 days); records changed only in that interval "
            "were NOT fetched. Recorded in collector_state.cursor.gaps.",
            missed_from, log_starts,
        )
        return {"missed_from": missed_from, "log_starts": log_starts, "detected_at": now.isoformat()}

    def _fetch_and_build(
        self,
        records: dict[str, dict],
        ids: list[str],
        *,
        pending: list[str],
        cursor: dict[str, Any],
        change_sets: int,
        wanted: list[str] | None = None,
        now: datetime | None = None,
    ) -> FetchResult:
        """`wanted` is None on bootstrap (backfill ignored, no backfill state
        touched); a list on incremental runs."""
        queue = _dedupe([*pending, *ids])  # backlog first
        batch, rest = queue[: self.max_files], queue[self.max_files :]
        if rest:
            log.warning(
                "cvelist: %d CVE ids queued, fetching %d this run (max_files); %d left pending",
                len(queue), len(batch), len(rest),
            )

        # On-demand backfill: only in the room left under the cap, never pending.
        cursor = dict(cursor)
        missing_map = self._missing_map(cursor.get("backfill_missing"))
        wanted_all = _dedupe(c for c in wanted or [] if is_valid_cve_id(str(c)))
        in_queue = set(queue)
        retry_window = [
            c for c in wanted_all
            if c in missing_map and now is not None and now - missing_map[c] < self.backfill_retry
        ]
        skip = set(retry_window)
        candidates = [c for c in wanted_all if c not in in_queue and c not in skip]
        room = max(self.max_files - len(batch), 0)
        backfill, dropped = candidates[:room], candidates[room:]

        got, missing, failed = self._fetch_records([*batch, *backfill])
        bf = set(backfill)
        batch_failed = [c for c in failed if c not in bf]
        if batch and len(batch_failed) == len(batch) and not bf_got_any(got, bf):
            # upstream looks down: judged on change-set ids only, so wanted-id
            # failures alone never fail a run
            raise RuntimeError(f"all {len(batch)} record fetches failed")
        batch_missing = [c for c in missing if c not in bf]
        bf_missing = [c for c in missing if c in bf]
        bf_failed = [c for c in failed if c in bf]
        bf_got = [c for c in got if c in bf]
        for cve_id in batch_missing:
            log.warning("cvelist: %s listed in deltaLog but its file is 404; dropped", cve_id)

        records = {**records, **got}  # per-file version is newer than the zip one
        cursor["pending"] = _dedupe([*rest, *batch_failed])
        cursor["last_run"] = {
            "change_sets": change_sets,
            "ids_queued": len(queue),
            "files_fetched": len(got),
            "files_missing": batch_missing,
            "files_failed": len(batch_failed),
            "pending": len(cursor["pending"]),
            "http_requests": self.requests_made,
        }
        if wanted is not None:
            if now is not None:
                for c in bf_missing:
                    missing_map[c] = now
            for c in got:  # exists upstream now (via backfill or a change set)
                missing_map.pop(c, None)
            if len(wanted) < self.wanted_limit:
                # complete list: entries no longer wanted are obsolete
                keep = set(wanted_all)
                missing_map = {c: t for c, t in missing_map.items() if c in keep}
            if len(missing_map) > MAX_BACKFILL_MISSING:  # keep the most recent 404s
                newest = sorted(missing_map.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
                missing_map = dict(newest[:MAX_BACKFILL_MISSING])
            cursor["backfill_missing"] = {
                c: t.isoformat() for c, t in sorted(missing_map.items())
            }
            cursor["last_run"].update(
                backfill_wanted=len(wanted),
                backfill_skipped_missing=len(retry_window),
                backfill_queued=len(backfill),
                backfill_fetched=len(bf_got),
                backfill_missing=len(bf_missing),
                backfill_failed=len(bf_failed),
                backfill_dropped=len(dropped),
                backfill_missing_tracked=len(missing_map),
            )
            if wanted_all:
                log.info(
                    "cvelist backfill: %d wanted, %d queued, %d fetched, %d 404, %d failed, "
                    "%d over cap (retried next run), %d in 404 retry window",
                    len(wanted), len(backfill), len(bf_got), len(bf_missing), len(bf_failed),
                    len(dropped), len(retry_window),
                )
        raw = [
            RawRecord(self.name, k, v, is_backfill=k in bf)
            for k, v in sorted(records.items())
        ]
        return FetchResult(records=raw, cursor=cursor)

    # ------------------------------------------------------------------ normalize

    def normalize(self, record: RawRecord) -> Normalized:
        p = record.payload
        if not isinstance(p, dict):
            raise NormalizeError("payload is not a JSON object")
        meta = p.get("cveMetadata")
        containers = p.get("containers")
        if p.get("dataType") != "CVE_RECORD" or not isinstance(meta, dict):
            raise NormalizeError("not a CVE JSON 5 record (dataType/cveMetadata)")
        cve = _text(meta.get("cveId"))
        if cve is None or not is_valid_cve_id(cve):
            raise NormalizeError(f"bad cveId: {meta.get('cveId')!r}")
        if cve != record.source_key:
            raise NormalizeError(f"cveId {cve} != source_key {record.source_key}")
        state = meta.get("state")
        if state == "RESERVED":
            return Normalized()  # nothing public to say; raw is kept
        if state not in ("PUBLISHED", "REJECTED"):
            raise NormalizeError(f"unknown state {state!r}")
        if not isinstance(containers, dict) or not isinstance(containers.get("cna"), dict):
            raise NormalizeError("missing containers.cna")
        cna = containers["cna"]

        published_at = parse_ts(meta.get("datePublished"))
        modified_at = parse_ts(meta.get("dateUpdated"))
        out = Normalized()
        detail: dict[str, Any] = {
            "state": state,
            "assigner_short_name": meta.get("assignerShortName"),
            "date_published": meta.get("datePublished"),
        }

        if state == "REJECTED":
            out.vulns.append(VulnUpsert(cve_id=cve, published_at=published_at,
                                        modified_at=modified_at, authoritative=True))
            detail["date_rejected"] = meta.get("dateRejected")
            detail["rejected_reasons"] = [
                r.get("value") for r in cna.get("rejectedReasons") or [] if isinstance(r, dict)
            ]
            if cna.get("replacedBy"):
                detail["replaced_by"] = cna.get("replacedBy")
        else:
            out.vulns.append(
                VulnUpsert(
                    cve_id=cve,
                    title=_text(cna.get("title")),
                    description=_english_description(cna),
                    published_at=published_at,
                    modified_at=modified_at,
                    authoritative=True,
                )
            )
            seen: set[tuple[str, str]] = set()
            for a in cna.get("affected") or []:
                if not isinstance(a, dict):
                    continue
                vendor, product = _text(a.get("vendor")), _text(a.get("product"))
                if not vendor or not product or "n/a" in (vendor.lower(), product.lower()):
                    continue
                if (vendor, product) not in seen:
                    seen.add((vendor, product))
                    out.affected.append(Affected(cve, vendor, product))
            advisory = _text((cna.get("source") or {}).get("advisory")) if isinstance(
                cna.get("source"), dict) else None
            if advisory and GHSA_RE.fullmatch(advisory):
                out.aliases.append(Alias(cve, advisory, "ghsa"))
            cvss = extract_cvss(containers)
            if cvss:
                detail["cvss"] = cvss
            detail.update(_cisa_adp_facts(containers))

        out.events.append(
            Event(
                cve_id=cve,
                type="disclosed",
                source=self.name,
                occurred_at=published_at,
                url=CVE_ORG_URL.format(cve),
                detail=detail,
                dedupe_key="",
            )
        )
        return out
