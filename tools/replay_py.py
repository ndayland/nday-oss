"""Python half of tools/replay: run the PYTHON pipeline for one collector with
every HTTP request answered from a local file (status 200, the file as body).

    NDAY_DATABASE_URL=... .venv/bin/python tools/replay_py.py kev /tmp/kev.json

Prints the same stats JSON as `nday collect`. Works for collectors whose
constructor accepts `client=` (all current ones) and that fetch one file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nday import db  # noqa: E402
from nday.collectors import COLLECTORS  # noqa: E402
from nday.pipeline import run_collector  # noqa: E402


def main(argv: list[str]) -> int:
    source, path = argv
    body = Path(path).read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        print(f"replay: GET {request.url} (User-Agent {request.headers.get('user-agent')!r}) <- {path}",
              file=sys.stderr)
        return httpx.Response(200, content=body)

    collector = COLLECTORS[source](client=httpx.Client(transport=httpx.MockTransport(handler)))
    with db.connect() as conn:
        stats = run_collector(conn, collector)
    print(json.dumps(stats.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
