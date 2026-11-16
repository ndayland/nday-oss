"""Shared plumbing for collectors that download ONE curated feed file per run
(exploitdb, metasploit, nuclei). Private module: not a collector itself.

What it does
- Download: one GET with ``nday.USER_AGENT``, a fixed ``Accept-Encoding: gzip``
  (raw.githubusercontent.com gives the gzip variant a different, weak ETag than
  the identity variant; pinning the encoding keeps the stored validator valid
  for the next request), timeouts, bounded retries with exponential backoff on
  429 / 5xx / transport errors (Retry-After honoured up to MAX_RETRY_AFTER), and
  a hard size cap on the DECODED body (checked against Content-Length first,
  then while streaming), so a runaway or decompression-bomb response aborts the
  run instead of exhausting memory.
- Conditional requests: the response's ETag / Last-Modified are stored in the
  cursor and sent back as If-None-Match / If-Modified-Since (only when the
  cursor belongs to the same URL). A 304 yields zero records; the validators
  and the counts of the last full download are kept.
- Scope + CVE filter: subclasses parse the body into (source_key, payload)
  items already restricted to their scope; items without any CVE-looking token
  are NOT returned as raw records (keeps raw_record small) but are counted in
  ``cursor.last_run``.
- Payloads are verbatim except that U+0000 (which PostgreSQL text/jsonb
  rejects, aborting the whole run) is replaced by the literal text '\\u0000';
  affected keys are listed in ``cursor.last_run.items_nul_scrubbed``.

Subclass contract
- ``feed_url`` (default URL), ``parse_items(body) -> (items, counts)`` and
  ``cve_tokens(payload) -> list[str]`` (candidate CVE strings, unvalidated);
  ``normalize`` as usual (see base.py), typically using ``split_cve_ids``.
"""

from __future__ import annotations

import abc
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

import httpx

from nday import USER_AGENT
from nday.collectors.base import Collector, NormalizeError
from nday.models import CollectorState, FetchResult, RawRecord, is_valid_cve_id

log = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # all three feeds are 2-12 MB (2026-11)
MAX_ATTEMPTS = 4  # 1 try + 3 retries
BACKOFF_BASE = 1.0  # seconds: 1, 2, 4
MAX_RETRY_AFTER = 60.0
TIMEOUT = httpx.Timeout(120.0, connect=15.0)


class FeedTooLarge(RuntimeError):
    """The feed exceeded the configured size cap; nothing is stored."""


@dataclass
class FeedResponse:
    status: int  # 200 or 304
    body: bytes | None
    etag: str | None
    last_modified: str | None
    attempts: int

    @property
    def not_modified(self) -> bool:
        return self.status == 304


def text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


NUL_REPLACEMENT = "\\u0000"  # the 6-char text, as the upstream JSON spells it


def scrub_nul(value: Any) -> tuple[Any, int]:
    """PostgreSQL text/jsonb cannot store U+0000 (live: nuclei CVE-2021-32030's
    Description contains one). Replace each NUL in strings (and keys) with the
    literal text '\\u0000'; return (value, number of strings changed)."""
    if isinstance(value, str):
        return (value.replace("\x00", NUL_REPLACEMENT), 1) if "\x00" in value else (value, 0)
    if isinstance(value, list):
        out, n = [], 0
        for v in value:
            v, k = scrub_nul(v)
            out.append(v)
            n += k
        return out, n
    if isinstance(value, dict):
        res, n = {}, 0
        for key, v in value.items():
            key, k1 = scrub_nul(key)
            v, k2 = scrub_nul(v)
            res[key] = v
            n += k1 + k2
        return res, n
    return value, 0


def split_cve_ids(tokens: Iterable[object]) -> tuple[list[str], list[str]]:
    """Candidate CVE tokens -> (valid ids: stripped, upper-cased, deduped, in
    upstream order; dropped tokens verbatim). Nothing else is repaired (e.g.
    'CVE-2019–9193' with an en dash is dropped, not guessed)."""
    valid: list[str] = []
    dropped: list[str] = []
    for tok in tokens:
        s = tok.strip().upper() if isinstance(tok, str) else ""
        if is_valid_cve_id(s):
            if s not in valid:
                valid.append(s)
        else:
            dropped.append(tok if isinstance(tok, str) else repr(tok))
    return valid, dropped


def require_cves(source_key: str, tokens: Iterable[object]) -> tuple[list[str], list[str]]:
    """split_cve_ids, but an item with no valid id at all is malformed."""
    valid, dropped = split_cve_ids(tokens)
    if not valid:
        raise NormalizeError(f"{source_key}: no valid CVE id among {dropped!r}")
    return valid, dropped


def download(
    client: httpx.Client,
    url: str,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    sleep: Callable[[float], None] = time.sleep,
) -> FeedResponse:
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    for attempt in range(1, MAX_ATTEMPTS + 1):
        delay = BACKOFF_BASE * 2 ** (attempt - 1)
        try:
            with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt == MAX_ATTEMPTS:
                        resp.raise_for_status()
                    ra = resp.headers.get("Retry-After", "").strip()
                    if ra.isdigit():
                        delay = min(float(ra), MAX_RETRY_AFTER)
                    log.warning("GET %s -> %d, retry %d in %.0fs",
                                url, resp.status_code, attempt, delay)
                    sleep(delay)
                    continue
                if resp.status_code == 304:
                    return FeedResponse(304, None, resp.headers.get("ETag") or etag,
                                        resp.headers.get("Last-Modified") or last_modified,
                                        attempt)
                resp.raise_for_status()
                declared = resp.headers.get("Content-Length", "").strip()
                if declared.isdigit() and int(declared) > max_bytes:
                    raise FeedTooLarge(f"{url}: Content-Length {declared} > cap {max_bytes}")
                buf = bytearray()
                for chunk in resp.iter_bytes():  # decoded (gunzipped) bytes
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise FeedTooLarge(f"{url}: body exceeds cap {max_bytes} bytes")
                return FeedResponse(resp.status_code, bytes(buf), resp.headers.get("ETag"),
                                    resp.headers.get("Last-Modified"), attempt)
        except httpx.TransportError as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            log.warning("GET %s failed (%s), retry %d in %.0fs", url, exc, attempt, delay)
            sleep(delay)
    raise AssertionError("unreachable")


class FeedCollector(Collector):
    """Base for single-file curated feeds (see module docstring)."""

    feed_url: ClassVar[str]

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        url: str | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if max_bytes < 1:
            raise ValueError(f"max_bytes must be >= 1, got {max_bytes}")
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=TIMEOUT, follow_redirects=True)
        self.url = url or self.feed_url
        self.max_bytes = max_bytes
        self.sleep = sleep

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    @abc.abstractmethod
    def parse_items(self, body: bytes) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, int]]:
        """Body -> ([(source_key, payload)] in scope, extra counts for last_run).
        Raise ValueError if the feed as a whole is malformed."""

    @abc.abstractmethod
    def cve_tokens(self, payload: dict[str, Any]) -> list[str]:
        """Candidate CVE strings of one item (unvalidated; [] = no CVE)."""

    def fetch(self, state: CollectorState) -> FetchResult:
        prev = dict(state.cursor or {})
        same_feed = prev.get("url") == self.url
        resp = download(
            self.client,
            self.url,
            etag=prev.get("etag") if same_feed else None,
            last_modified=prev.get("last_modified") if same_feed else None,
            max_bytes=self.max_bytes,
            sleep=self.sleep,
        )
        cursor: dict[str, Any] = {"url": self.url, "etag": resp.etag,
                                  "last_modified": resp.last_modified}
        if resp.not_modified:
            cursor["feed"] = prev.get("feed")  # counts of the last full download
            cursor["last_run"] = {"http_status": 304, "attempts": resp.attempts}
            return FetchResult(records=[], cursor=cursor)

        assert resp.body is not None
        items, extra = self.parse_items(resp.body)
        records: list[RawRecord] = []
        without_cve = 0
        nul_scrubbed: list[str] = []
        for key, payload in items:
            if not self.cve_tokens(payload):
                without_cve += 1
                continue
            payload, n_nul = scrub_nul(payload)
            if n_nul:
                nul_scrubbed.append(key)
                log.warning("%s: %s contains NUL characters; stored as literal '\\u0000'",
                            self.name, key)
            records.append(RawRecord(source=self.name, source_key=key, payload=payload))
        feed = {
            "bytes": len(resp.body),
            **extra,
            "items_in_scope": len(items),
            "items_with_cve": len(records),
            "items_without_cve": without_cve,
            "items_nul_scrubbed": nul_scrubbed[:20],
        }
        cursor["feed"] = feed
        cursor["last_run"] = {"http_status": resp.status, "attempts": resp.attempts, **feed}
        return FetchResult(records=records, cursor=cursor)
