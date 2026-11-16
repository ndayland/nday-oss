"""Shared test helpers for the curated PoC feed collectors (no network)."""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path

import httpx

from nday.collectors.exploitdb import ExploitDbCollector
from nday.collectors.metasploit import MetasploitCollector
from nday.collectors.nuclei import NucleiCollector

FIXTURES = Path(__file__).parent / "fixtures"


def no_sleep(_seconds: float) -> None:
    pass


class FeedServer:
    """Serves one feed body like GitLab / raw.githubusercontent.com do: ETag on
    200, 304 when If-None-Match matches. `script` (list of status codes) is
    consumed first, to simulate 429/5xx."""

    def __init__(self, url: str, body: bytes, etag: str = '"v1"', *, gzip_body: bool = False,
                 script: list[int] | None = None, content_length: bool = True):
        self.url, self.body, self.etag = url, body, etag
        self.gzip_body = gzip_body
        self.script = list(script or [])
        self.content_length = content_length
        self.requests: list[httpx.Request] = []

    def set(self, body: bytes, etag: str) -> None:
        self.body, self.etag = body, etag

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == self.url
        self.requests.append(request)
        if self.script:
            return httpx.Response(self.script.pop(0), headers={"Retry-After": "1"})
        if request.headers.get("if-none-match") == self.etag:
            return httpx.Response(304, headers={"ETag": self.etag})
        headers = {"ETag": self.etag}
        content = self.body
        if self.gzip_body:
            content = gzip.compress(self.body)
            headers["Content-Encoding"] = "gzip"
        if not self.content_length:
            # streamed body without Content-Length (cap must still apply)
            return httpx.Response(200, headers=headers, stream=httpx.ByteStream(content))
        return httpx.Response(200, headers=headers, content=content)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


# ------------------------------------------------------------------ per-source adapters
# Each adapter loads the recorded fixture as editable data and serializes it back
# to the exact upstream wire format.


class EdbFeed:
    cls = ExploitDbCollector
    url = ExploitDbCollector.feed_url
    new_key = "52705"  # held back on run 1, "appears" on run 2
    change_key = "52675"
    cve_of_change = "CVE-2026-9198"
    title_field = "title"

    @staticmethod
    def load() -> list[list[str]]:
        text = (FIXTURES / "exploitdb" / "files_exploits.csv").read_text(encoding="utf-8")
        return list(csv.reader(io.StringIO(text, newline="")))

    @staticmethod
    def dump(rows: list[list[str]]) -> bytes:
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(rows)
        return buf.getvalue().encode("utf-8")

    @staticmethod
    def without(rows, key):
        return [r for r in rows if r[0] != key]

    @staticmethod
    def changed(rows, key):
        out = [list(r) for r in rows]
        for r in out:
            if r[0] == key:
                r[2] = r[2] + " (updated)"  # description
        return out


class MsfFeed:
    cls = MetasploitCollector
    url = MetasploitCollector.feed_url
    new_key = "exploit/multi/http/langflow_unauth_rce_cve_2026_9198"
    change_key = "auxiliary/admin/2wire/xslt_password_reset"
    cve_of_change = "CVE-2007-4387"

    @staticmethod
    def load() -> dict:
        return json.loads((FIXTURES / "metasploit" / "modules_metadata_base.json").read_text())

    @staticmethod
    def dump(data: dict) -> bytes:
        return json.dumps(data, indent=2).encode("utf-8")

    @staticmethod
    def without(data, fullname):
        return {k: v for k, v in data.items() if v["fullname"] != fullname}

    @staticmethod
    def changed(data, fullname):
        out = json.loads(json.dumps(data))
        for v in out.values():
            if v["fullname"] == fullname:
                v["mod_time"] = "2026-11-12 10:00:00 +0000"
                v["name"] = v["name"] + " (updated)"
        return out


class NucleiFeed:
    cls = NucleiCollector
    url = NucleiCollector.feed_url
    new_key = "CVE-2026-41940"
    change_key = "CVE-2021-44228"
    cve_of_change = "CVE-2021-44228"

    @staticmethod
    def load() -> list[dict]:
        text = (FIXTURES / "nuclei" / "cves.json").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    @staticmethod
    def dump(objs: list[dict]) -> bytes:
        return "".join(json.dumps(o, separators=(",", ":")) + "\n" for o in objs).encode()

    @staticmethod
    def without(objs, key):
        return [o for o in objs if o["ID"] != key]

    @staticmethod
    def changed(objs, key):
        out = json.loads(json.dumps(objs))
        for o in out:
            if o["ID"] == key:
                o["Info"]["Name"] = o["Info"]["Name"] + " (updated)"
        return out


ADAPTERS = {"exploitdb": EdbFeed, "metasploit": MsfFeed, "nuclei": NucleiFeed}


def collector(adapter, server: FeedServer, **kw):
    return adapter.cls(client=server.client(), sleep=no_sleep, **kw)
