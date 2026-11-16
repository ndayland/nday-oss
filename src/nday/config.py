"""Configuration from environment variables (optionally seeded from a local .env)."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MIGRATIONS_DIR = PROJECT_ROOT / "migrations"


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader: KEY=VALUE lines; never overrides real env vars."""
    path = path or Path.cwd() / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def database_url() -> str:
    load_dotenv()
    url = os.environ.get("NDAY_DATABASE_URL")
    if not url:
        raise RuntimeError("NDAY_DATABASE_URL is not set (see .env.example)")
    return url


def migrations_dir() -> Path:
    return Path(os.environ.get("NDAY_MIGRATIONS_DIR", DEFAULT_MIGRATIONS_DIR))
