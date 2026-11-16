"""GitHub Advisory Database (global security advisories, REST) collector.

Upstream facts (verified 2026-11-12, docs + live responses; see the report):
- ``GET https://api.github.com/advisories`` lists global advisories. Query
  parameters used: ``type=reviewed`` (default anyway), ``sort=updated``,
  ``direction=asc``, ``per_page=100`` (max), ``updated=>=<ISO8601>`` (GitHub
  search date syntax; second precision works: ``>=2026-11-05T18:05:13Z``
  starts exactly at an advisory updated at that second. Note ``>`` returned
  the same first item, i.e. it is NOT strict, so we only use ``>=``).
- Pagination is cursor based: the ``Link`` header carries ``rel="next"`` with
  an ``after=`` cursor. We follow the given URL verbatim.
- Unauthenticated REST quota: 60 requests/hour per IP. Every response carries
  ``x-ratelimit-remaining`` / ``x-ratelimit-reset``; when exhausted GitHub
  answers 403 (or 429) with remaining=0. ``GET /rate_limit`` does not count
  against the primary limit but may disagree with the headers, so we only rely
  on response headers.

Strategy
- Sort ascending by ``updated_at`` so the cursor is a monotone high-water mark
  (``cursor.since`` = newest updated_at fully covered). An advisory edited
  while we paginate moves to the end of the ascending order, so it is still
  reached (this run or the next).
- First run: advisories updated in the last ``bootstrap_days`` (env
  NDAY_GHSA_BOOTSTRAP_DAYS, default 7). No full-history backfill. The first run
  must complete within the request cap / quota, otherwise it fails (nothing is
  stored) and is retried: the pipeline labels every event of the first
  successful run as backfill and every later one as new, so carrying half of the
  bootstrap over into run 2 would mislabel it.
- Later runs: ``updated >= since - overlap`` (env NDAY_GHSA_OVERLAP_MINUTES,
  default 60). The inclusive bound means advisories sharing the high-water
  timestamp are never missed; the overlap absorbs search-index lag. Re-fetched
  unchanged advisories are skipped by the pipeline's content hash.
- Per-run cap: at most ``max_requests`` list requests (env
  NDAY_GHSA_MAX_REQUESTS, default 10 = 1000 advisories). If more pages remain,
  or a rate limit / persistent error stops us mid-way, the not-yet-fetched
  ``next`` URL is kept in ``cursor.pending`` and resumed first next run (so a
  burst of thousands of advisories with the same timestamp still progresses).
  Everything already fetched is stored and the run succeeds.
- Falling behind: a run that ends with pending work while ``since`` is more
  than 24 h old logs a WARNING and appends to ``cursor.gaps``.
- Optional ``NDAY_GITHUB_TOKEN`` is sent as ``Authorization: Bearer``; it is
  never logged or stored in the cursor.

Normalization
- Raw record per advisory: source_key = GHSA id, payload verbatim.
- No ``cve_id``: nothing emitted. Withdrawn: GHSA alias only.
- Otherwise: alias (cve, GHSA, "ghsa"), stub vuln (summary/description,
  authoritative=False) and, iff some package has a non-empty
  ``first_patched_version``, one ``patch_released`` event (dedupe_key = GHSA
  id, occurred_at None: GitHub does not say when the patch shipped).
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx

from nday import USER_AGENT
from nday.collectors.base import Collector, NormalizeError
from nday.models import (
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

API_BASE = "https://api.github.com"
ADVISORIES_URL = f"{API_BASE}/advisories"
API_VERSION = "2022-11-28"
PER_PAGE = 100

DEFAULT_BOOTSTRAP_DAYS = 7
MAX_BOOTSTRAP_DAYS = 90
DEFAULT_MAX_REQUESTS = 10
DEFAULT_OVERLAP_MINUTES = 60
MAX_ATTEMPTS = 4  # 1 try + 3 retries (5xx / transport / short secondary limits)
BACKOFF_BASE = 1.0  # seconds: 1, 2, 4
MAX_RETRY_AFTER = 60.0
MAX_GAPS_KEPT = 50
LAG_WARN = timedelta(hours=24)

GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")

# Fix links on code hosts: commits and pull/merge requests (input of the later
# patch-analysis milestone). Matched against the whole URL.
FIX_URL_RES = (
    # github.com/<owner>/<repo>/commit/<sha>
    re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/commit/[0-9a-fA-F]{7,40}(?:[/?#].*)?"),
    # github.com/<owner>/<repo>/pull/<n>[/commits/<sha>|/files|...]
    re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/pull/\d+(?:[/?#].*)?"),
    # GitLab (gitlab.com or self-hosted): .../-/commit/<sha>, .../-/merge_requests/<n>
    re.compile(r"https?://[^/\s]*gitlab[^/\s]*/(?:[^/\s]+/)+-/commit/[0-9a-fA-F]{7,40}(?:[/?#].*)?"),
    re.compile(r"https?://[^/\s]*gitlab[^/\s]*/(?:[^/\s]+/)+-/merge_requests/\d+(?:[/?#].*)?"),
    # bitbucket.org/<owner>/<repo>/commits/<sha>
    re.compile(r"https?://bitbucket\.org/[^/\s]+/[^/\s]+/commits?/[0-9a-fA-F]{7,40}(?:[/?#].*)?"),
)


# --------------------------------------------------------------------------- helpers


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def parse_ts(value: object) -> datetime | None:
    s = _text(value)
    if s is None:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def iso_z(dt: datetime) -> str:
    """UTC timestamp at second precision, e.g. 2026-11-12T14:00:00Z."""
    return dt.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def list_url(since: datetime) -> str:
    """First-page URL: reviewed advisories updated at/after `since`, oldest first."""
    params = {
        "type": "reviewed",
        "sort": "updated",
        "direction": "asc",
        "per_page": str(PER_PAGE),
        "updated": f">={iso_z(since)}",
    }
    return str(httpx.URL(ADVISORIES_URL, params=params))


# PRs/commits on the advisory database itself are edits of the advisory, not fixes
# (observed live, e.g. https://github.com/github/advisory-database/pull/10102).
NOT_FIX_RE = re.compile(r"https?://github\.com/github/advisory-database/", re.IGNORECASE)


def fix_commit_urls(references: object) -> list[str]:
    """Reference URLs that are commit / PR / MR links on a code host (deduped,
    upstream order, verbatim)."""
    out: list[str] = []
    for ref in references if isinstance(references, list) else []:
        url = _text(ref)
        if (url and url not in out and not NOT_FIX_RE.match(url)
                and any(r.fullmatch(url) for r in FIX_URL_RES)):
            out.append(url)
    return out


def _patched_version(value: object) -> str | None:
    # API v2022-11-28 gives a string; older shapes used {"identifier": "..."}.
    if isinstance(value, dict):
        value = value.get("identifier")
    return _text(value)


class _Stop(Exception):
    """Stop paginating cleanly (rate limit / persistent upstream error)."""

    def __init__(self, reason: str, info: dict[str, Any]):
        super().__init__(reason)
        self.reason = reason
        self.info = info


# --------------------------------------------------------------------------- collector


class GhsaCollector(Collector):
    name = "ghsa"

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        bootstrap_days: int | None = None,
        max_requests: int | None = None,
        overlap_minutes: int | None = None,
        token: str | None = None,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._owns_client = client is None
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=False
        )
        days = bootstrap_days if bootstrap_days is not None else env_int(
            "NDAY_GHSA_BOOTSTRAP_DAYS", DEFAULT_BOOTSTRAP_DAYS
        )
        if not 0 <= days <= MAX_BOOTSTRAP_DAYS:
            raise ValueError(f"bootstrap_days must be 0..{MAX_BOOTSTRAP_DAYS}, got {days}")
        cap = max_requests if max_requests is not None else env_int(
            "NDAY_GHSA_MAX_REQUESTS", DEFAULT_MAX_REQUESTS
        )
        if cap < 1:
            raise ValueError(f"max_requests must be >= 1, got {cap}")
        overlap = overlap_minutes if overlap_minutes is not None else env_int(
            "NDAY_GHSA_OVERLAP_MINUTES", DEFAULT_OVERLAP_MINUTES
        )
        if overlap < 0:
            raise ValueError(f"overlap_minutes must be >= 0, got {overlap}")
        self.bootstrap_days = days
        self.max_requests = cap
        self.overlap = timedelta(minutes=overlap)
        tok = token if token is not None else os.environ.get("NDAY_GITHUB_TOKEN", "")
        self._token = tok.strip() or None
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sleep = sleep
        self.requests_made = 0
        self.rate: dict[str, Any] = {}

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    # ------------------------------------------------------------------ HTTP

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _note_rate(self, resp: httpx.Response) -> None:
        for key in ("limit", "remaining", "used", "reset"):
            v = resp.headers.get(f"x-ratelimit-{key}")
            if v is not None and v.strip().isdigit():
                self.rate[key] = int(v)
        if "reset" in self.rate:
            self.rate["reset_at"] = iso_z(datetime.fromtimestamp(self.rate["reset"], UTC))

    @staticmethod
    def _is_rate_limited(resp: httpx.Response) -> bool:
        if resp.status_code == 429:
            return True
        if resp.status_code != 403:
            return False
        if resp.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in resp.headers:
            return True
        return "rate limit" in resp.text.lower()

    def _get(self, url: str) -> httpx.Response:
        """One logical GET. Retries 5xx/transport errors and short secondary
        rate limits with backoff. Raises _Stop when the primary quota is
        exhausted (or a long wait is demanded / retries are exhausted);
        raises httpx.HTTPStatusError for other 4xx."""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            delay = BACKOFF_BASE * 2 ** (attempt - 1)
            self.requests_made += 1
            try:
                resp = self.client.get(url, headers=self._headers())
            except httpx.TransportError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise _Stop("transport_error", {"error": str(exc)}) from exc
                log.warning("GET %s failed (%s), retry %d in %.0fs", url, exc, attempt, delay)
                self.sleep(delay)
                continue
            self._note_rate(resp)
            if self._is_rate_limited(resp):
                info = {"status": resp.status_code, **self.rate}
                if resp.headers.get("x-ratelimit-remaining") == "0":
                    raise _Stop("rate_limited", info)
                ra = resp.headers.get("retry-after", "").strip()
                wait = float(ra) if ra.isdigit() else 60.0  # docs: else wait >= 1 min
                if wait > MAX_RETRY_AFTER or attempt == MAX_ATTEMPTS:
                    raise _Stop("secondary_rate_limited", {**info, "retry_after": wait})
                log.warning("GET %s -> %d (secondary rate limit), retry in %.0fs",
                            url, resp.status_code, wait)
                self.sleep(wait)
                continue
            if resp.status_code >= 500:
                if attempt == MAX_ATTEMPTS:
                    raise _Stop("server_error", {"status": resp.status_code})
                log.warning("GET %s -> %d, retry %d in %.0fs", url, resp.status_code, attempt, delay)
                self.sleep(delay)
                continue
            resp.raise_for_status()
            return resp
        raise AssertionError("unreachable")

    @staticmethod
    def _next_url(resp: httpx.Response) -> str | None:
        nxt = resp.links.get("next", {}).get("url")
        if not nxt:
            return None
        parts = urlsplit(nxt)
        if f"{parts.scheme}://{parts.netloc}" != API_BASE or parts.path != "/advisories":
            raise ValueError(f"unexpected Link next URL: {nxt!r}")
        return nxt

    # ------------------------------------------------------------------ fetch

    def fetch(self, state: CollectorState) -> FetchResult:
        cursor = dict(state.cursor or {})
        now = self.clock()
        first = state.is_first_run or not cursor.get("since")
        resuming = False
        if first:
            since = now - timedelta(days=self.bootstrap_days)
            query_since = since
            url = list_url(since)
        else:
            since = parse_ts(cursor["since"])
            if since is None:
                raise ValueError(f"cursor.since is not a timestamp: {cursor['since']!r}")
            pending = cursor.get("pending") or None
            if pending and pending.get("next_url"):
                resuming = True
                query_since = parse_ts(pending.get("query_since")) or since
                url = pending["next_url"]
                log.info("ghsa: resuming pending pagination (%s, query since %s)",
                         pending.get("reason"), pending.get("query_since"))
            else:
                query_since = since - self.overlap
                url = list_url(query_since)

        records: dict[str, dict[str, Any]] = {}
        high = since
        pages = 0
        stop: _Stop | None = None
        next_url: str | None = None
        while True:
            if pages >= self.max_requests:
                next_url, stop = url, _Stop("request_cap", {"max_requests": self.max_requests})
                break
            if pages and self.rate.get("remaining") == 0:  # don't spend a doomed request
                next_url, stop = url, _Stop("rate_limited", {"status": None, **self.rate})
                break
            try:
                resp = self._get(url)
            except _Stop as exc:
                next_url, stop = url, exc
                break
            except httpx.HTTPStatusError as exc:
                if resuming and pages == 0 and 400 <= exc.response.status_code < 500:
                    # stale pending cursor rejected: restart from the high-water mark
                    log.warning("ghsa: pending next URL rejected (%s); restarting from since",
                                exc.response.status_code)
                    resuming = False
                    query_since = since - self.overlap
                    url = list_url(query_since)
                    continue
                raise
            pages += 1
            data = resp.json()
            if not isinstance(data, list):
                raise ValueError("GET /advisories: expected a JSON array")
            for adv in data:
                gid = _text(adv.get("ghsa_id")) if isinstance(adv, dict) else None
                if not gid:
                    raise ValueError(f"advisory without ghsa_id: {str(adv)[:200]}")
                records[gid] = adv  # later pages hold newer versions
                upd = parse_ts(adv.get("updated_at"))
                if upd is not None and upd > high:
                    high = upd
            nxt = self._next_url(resp)
            if not nxt:
                break
            url = nxt

        if stop is not None and (
            first or (not records and stop.reason in ("transport_error", "server_error"))
        ):
            # Bootstrap must be complete (see module docstring). An incremental
            # run whose very first request failed is a plain failure (cursor kept);
            # one stopped by the rate limit succeeds with the work left pending.
            raise RuntimeError(
                f"ghsa: stopped ({stop.reason}) after {pages} page(s) "
                f"{'during the first-run window' if first else 'before any data'}: {stop.info}. "
                "Nothing stored; retry later, lower NDAY_GHSA_BOOTSTRAP_DAYS, raise "
                "NDAY_GHSA_MAX_REQUESTS or set NDAY_GITHUB_TOKEN."
            )

        out: dict[str, Any] = {k: v for k, v in cursor.items() if k not in ("pending", "last_run")}
        gaps = list(cursor.get("gaps") or [])
        out["since"] = iso_z(high)
        out["pending"] = None
        if first:
            out["bootstrap"] = {"days": self.bootstrap_days, "window_from": iso_z(since),
                                "at": iso_z(now)}
        if stop is not None:
            out["pending"] = {"next_url": next_url, "query_since": iso_z(query_since),
                              "reason": stop.reason}
            log.warning("ghsa: stopped early (%s) after %d page(s), %d advisories; "
                        "remaining pages resume next run. %s",
                        stop.reason, pages, len(records), stop.info)
            if now - high > LAG_WARN:
                log.warning("ghsa fell behind: advisories updated since %s are not all "
                            "fetched yet (%s). Recorded in collector_state.cursor.gaps.",
                            iso_z(high), stop.reason)
                gaps.append({"behind_since": iso_z(high), "reason": stop.reason,
                             "detected_at": iso_z(now)})
        out["gaps"] = gaps[-MAX_GAPS_KEPT:]
        out["last_run"] = {
            "query_since": iso_z(query_since),
            "pages": pages,
            "http_requests": self.requests_made,
            "advisories": len(records),
            "stopped": stop.reason if stop else None,
            "rate_limit": {k: self.rate[k] for k in ("limit", "remaining", "reset_at")
                           if k in self.rate},
        }
        raw = [RawRecord(self.name, k, v) for k, v in sorted(records.items())]
        return FetchResult(records=raw, cursor=out)

    # ------------------------------------------------------------------ normalize

    def normalize(self, record: RawRecord) -> Normalized:
        p = record.payload
        if not isinstance(p, dict):
            raise NormalizeError("payload is not a JSON object")
        gid = _text(p.get("ghsa_id"))
        if gid is None or not GHSA_RE.fullmatch(gid):
            raise NormalizeError(f"bad ghsa_id: {p.get('ghsa_id')!r}")
        if gid != record.source_key:
            raise NormalizeError(f"ghsa_id {gid} != source_key {record.source_key}")
        for key in ("published_at", "updated_at"):
            if parse_ts(p.get(key)) is None:
                raise NormalizeError(f"{gid}: bad {key}: {p.get(key)!r}")
        vulns = p.get("vulnerabilities")
        if vulns is not None and not isinstance(vulns, list):
            raise NormalizeError(f"{gid}: vulnerabilities is not a list")
        refs = p.get("references")
        if refs is not None and not isinstance(refs, list):
            raise NormalizeError(f"{gid}: references is not a list")

        cve = _text(p.get("cve_id"))
        if cve is None:
            return Normalized()  # vuln table is keyed by CVE; raw is kept
        if not is_valid_cve_id(cve):
            raise NormalizeError(f"{gid}: bad cve_id {cve!r}")

        out = Normalized(aliases=[Alias(cve, gid, "ghsa")])
        if _text(p.get("withdrawn_at")):
            return out

        out.vulns.append(VulnUpsert(cve_id=cve, title=_text(p.get("summary")),
                                    description=_text(p.get("description")),
                                    authoritative=False))
        packages = []
        for v in vulns or []:
            if not isinstance(v, dict):
                raise NormalizeError(f"{gid}: vulnerability entry is not an object")
            pkg = v.get("package") if isinstance(v.get("package"), dict) else {}
            packages.append({
                "ecosystem": pkg.get("ecosystem"),
                "name": pkg.get("name"),
                "vulnerable_version_range": v.get("vulnerable_version_range"),
                "first_patched_version": _patched_version(v.get("first_patched_version")),
            })
        if not any(pkg["first_patched_version"] for pkg in packages):
            return out  # no fix known yet: alias + stub only

        cvss = p.get("cvss_severities")
        if cvss is None and "cvss" in p:
            cvss = p.get("cvss")
        detail = {
            "ghsa_id": gid,
            "advisory_published_at": p.get("published_at"),
            "advisory_updated_at": p.get("updated_at"),
            "github_reviewed_at": p.get("github_reviewed_at"),
            "severity": p.get("severity"),
            "cvss": cvss,
            "cwes": p.get("cwes") or [],
            "packages": packages,
            "fix_commit_urls": fix_commit_urls(refs),
            "source_code_location": p.get("source_code_location"),
            "references": refs or [],
        }
        out.events.append(Event(cve_id=cve, type="patch_released", source=self.name,
                                occurred_at=None, url=_text(p.get("html_url")),
                                detail=detail, dedupe_key=gid))
        return out
