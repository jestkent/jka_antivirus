"""Async SQLite connection layer using aiosqlite."""

from __future__ import annotations

import importlib.resources
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite


async def _get_schema_sql() -> str:
    """Read schema.sql from the package, supporting both installed and editable installs."""
    try:
        ref = importlib.resources.files("jka_antivirus.db").joinpath("schema.sql")
        return ref.read_text(encoding="utf-8")
    except (AttributeError, FileNotFoundError):
        # Fallback for environments where importlib.resources traversal is unavailable.
        fallback = Path(__file__).parent / "schema.sql"
        return fallback.read_text(encoding="utf-8")


async def init_db(db_path: Path) -> None:
    """Create the database file and apply the schema (idempotent via IF NOT EXISTS).

    Also enables WAL journal mode and foreign key enforcement.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = await _get_schema_sql()

    async with aiosqlite.connect(db_path) as conn:
        await conn.executescript(schema_sql)
        await conn.commit()


@asynccontextmanager
async def get_connection(db_path: Path) -> AsyncGenerator[aiosqlite.Connection, None]:
    """Yield a configured aiosqlite connection with WAL mode and foreign keys active.

    Usage:
        async with get_connection(settings.database.path) as conn:
            rows = await conn.execute("SELECT * FROM scan_runs")
    """
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode = WAL")
        await conn.execute("PRAGMA foreign_keys = ON")
        yield conn


async def get_table_counts(db_path: Path) -> dict[str, int]:
    """Return row counts for the four core tables. Returns zeros if DB does not exist."""
    if not db_path.exists():
        return {"scan_runs": 0, "detections": 0, "quarantine_items": 0, "event_log": 0}

    tables = ["scan_runs", "detections", "quarantine_items", "event_log"]
    counts: dict[str, int] = {}
    async with get_connection(db_path) as conn:
        for table in tables:
            cursor = await conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            row = await cursor.fetchone()
            counts[table] = int(row[0]) if row else 0
    return counts
