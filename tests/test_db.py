"""Tests for the SQLite schema and async connection layer (db/connection.py)."""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest

from jka_antivirus.db.connection import get_connection, get_table_counts, init_db


@pytest.mark.asyncio
async def test_init_db_creates_file(tmp_path: Path) -> None:
    """init_db creates the database file."""
    db_path = tmp_path / "test.db"
    assert not db_path.exists()
    await init_db(db_path)
    assert db_path.exists()


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_path: Path) -> None:
    """Calling init_db twice does not raise an error (IF NOT EXISTS)."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)
    await init_db(db_path)  # should not raise


@pytest.mark.asyncio
async def test_all_tables_exist(tmp_path: Path) -> None:
    """All four schema tables exist after init_db."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)

    expected_tables = {"scan_runs", "detections", "quarantine_items", "event_log"}
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        rows = await cursor.fetchall()
    actual_tables = {row[0] for row in rows}
    assert expected_tables == actual_tables


@pytest.mark.asyncio
async def test_indexes_exist(tmp_path: Path) -> None:
    """Required indexes exist after init_db."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)

    required_indexes = {
        "idx_detections_sha256",
        "idx_detections_detected_at",
        "idx_detections_verdict",
        "idx_event_log_timestamp",
    }
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )
        rows = await cursor.fetchall()
    actual_indexes = {row[0] for row in rows}
    assert required_indexes.issubset(actual_indexes)


@pytest.mark.asyncio
async def test_foreign_keys_enforced(tmp_path: Path) -> None:
    """Foreign key constraints are active: inserting a detection without a scan_run fails."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)

    async with get_connection(db_path) as conn:
        with pytest.raises(aiosqlite.IntegrityError):
            await conn.execute(
                """
                INSERT INTO detections
                    (scan_run_id, file_path, file_hash_sha256, file_hash_md5,
                     verdict, score, reasoning_json, detected_at)
                VALUES (999, '/tmp/evil.exe', 'aaa', 'bbb',
                        'malicious', 1.0, '{}', '2026-01-01T00:00:00')
                """
            )
            await conn.commit()


@pytest.mark.asyncio
async def test_get_table_counts_zeros_on_fresh_db(tmp_path: Path) -> None:
    """get_table_counts returns zeros for an empty, freshly initialised database."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)
    counts = await get_table_counts(db_path)
    assert counts["scan_runs"] == 0
    assert counts["detections"] == 0
    assert counts["quarantine_items"] == 0
    assert counts["event_log"] == 0


@pytest.mark.asyncio
async def test_get_table_counts_missing_db(tmp_path: Path) -> None:
    """get_table_counts returns zeros when the database file does not exist."""
    db_path = tmp_path / "nonexistent.db"
    counts = await get_table_counts(db_path)
    assert all(v == 0 for v in counts.values())


@pytest.mark.asyncio
async def test_wal_mode_enabled(tmp_path: Path) -> None:
    """WAL journal mode is active after connecting via get_connection."""
    db_path = tmp_path / "test.db"
    await init_db(db_path)
    async with get_connection(db_path) as conn:
        cursor = await conn.execute("PRAGMA journal_mode")
        row = await cursor.fetchone()
    assert row is not None
    assert row[0].lower() == "wal"
