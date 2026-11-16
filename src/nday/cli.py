"""Command line: nday migrate | nday collect <source> | nday status."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import timedelta

from nday import db, state
from nday.collectors import COLLECTORS
from nday.pipeline import run_collector

TABLES = ("raw_record", "vuln", "vuln_alias", "affected", "event", "collector_state")


def cmd_migrate(args: argparse.Namespace) -> int:
    with db.connect() as conn:
        applied = db.migrate(conn)
    print(f"applied: {', '.join(applied) if applied else '(none, up to date)'}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    collector = COLLECTORS[args.source]()
    try:
        with db.connect() as conn:
            stats = run_collector(conn, collector, renormalize=args.renormalize)
    finally:
        collector.close()
    print(json.dumps(stats.as_dict(), indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with db.connect() as conn:
        print("table counts:")
        for t in TABLES:
            (n,) = conn.execute(f"SELECT count(*) FROM {t}").fetchone()
            print(f"  {t:<16} {n}")
        print("events by type / is_backfill:")
        for typ, backfill, n in conn.execute(
            "SELECT type, is_backfill, count(*) FROM event GROUP BY 1, 2 ORDER BY 1, 2"
        ):
            print(f"  {typ:<20} backfill={str(backfill):<5} {n}")
        print("collector_state:")
        rows = conn.execute(
            """SELECT source, last_status, last_run_at, last_success_at, cursor, last_error
               FROM collector_state ORDER BY source"""
        ).fetchall()
        if not rows:
            print("  (none)")
        for source, status, run_at, ok_at, cursor, err in rows:
            print(f"  {source}: status={status} last_run_at={run_at} last_success_at={ok_at}")
            print(f"    cursor={json.dumps(cursor, ensure_ascii=False)}")
            if err:
                print(f"    last_error={err}")
        print("stage counts:")
        for stage, n in state.stage_counts(conn):
            print(f"  {stage:<20} {n}")
    return 0


def parse_since(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([hd])", text.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"bad duration {text!r}, use e.g. 24h or 7d")
    n = int(m.group(1))
    return timedelta(hours=n) if m.group(2) == "h" else timedelta(days=n)


def cmd_hot(args: argparse.Namespace) -> int:
    with db.connect() as conn:
        rows = state.hot(conn, args.since, args.limit,
                         include_rejected=args.include_rejected, min_stage=args.min_stage)
    if not rows:
        print("(none)")
        return 0
    for r in rows:
        flags = "".join(
            c if r[k] else "-"
            for c, k in (("P", "has_patch"), ("A", "has_analysis"), ("O", "has_poc"),
                         ("X", "exploited"), ("K", "in_kev"), ("R", "is_rejected"))
        )
        title = (r["title"] or "").replace("\n", " ")
        if len(title) > 50:
            title = title[:49] + "…"
        when = r["last_transition_at"].strftime("%Y-%m-%d %H:%M")
        print(f"{r['cve_id']:<16} {r['stage']:<18} {r['last_transition_type']:<18} "
              f"{when} {flags} {title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nday")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("migrate", help="apply pending SQL migrations").set_defaults(func=cmd_migrate)

    c = sub.add_parser("collect", help="run a collector")
    c.add_argument("source", choices=sorted(COLLECTORS))
    c.add_argument(
        "--renormalize",
        action="store_true",
        help="also re-run normalize() on records whose raw content is unchanged",
    )
    c.set_defaults(func=cmd_collect)

    h = sub.add_parser("hot", help="vulns with the most recent stage transitions")
    h.add_argument("--since", type=parse_since, default=timedelta(hours=24))
    h.add_argument("--limit", type=int, default=20)
    h.add_argument("--include-rejected", action="store_true")
    h.add_argument("--min-stage", choices=state.STAGES, default="patch_released",
                   help="only transitions to this stage or later (default: patch_released; "
                        "use 'disclosed' to include plain new disclosures)")
    h.set_defaults(func=cmd_hot)

    sub.add_parser("status", help="row counts and collector state").set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
