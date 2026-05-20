"""Tests for Phase 2 static analysis engines and scanner orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jka_antivirus.engines.hash_engine import HashEngine, compute_hashes
from jka_antivirus.engines.pe_engine import PEEngine, _section_entropy
from jka_antivirus.engines.yara_engine import YaraEngine
from jka_antivirus.scanner import _collect_files, _merge_results, run_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_text(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _write_bytes(tmp_path: Path, name: str, content: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p



# ---------------------------------------------------------------------------
# compute_hashes
# ---------------------------------------------------------------------------

def test_compute_hashes_returns_hex_strings(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "a.txt", "hello")
    sha256, md5 = compute_hashes(f)
    assert len(sha256) == 64
    assert len(md5) == 32
    assert all(c in "0123456789abcdef" for c in sha256)


def test_compute_hashes_deterministic(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "a.txt", "hello")
    assert compute_hashes(f) == compute_hashes(f)


# ---------------------------------------------------------------------------
# HashEngine
# ---------------------------------------------------------------------------

def test_hash_engine_clean_on_unknown_file(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "a.txt", "benign content")
    result = HashEngine().analyze(f)
    assert result.verdict == "clean"
    assert result.score == 0.0


def test_hash_engine_detects_blocklisted_file(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "evil.exe", "evil content")
    sha256, _ = compute_hashes(f)

    blocklist = tmp_path / "bl.json"
    blocklist.write_text(json.dumps({sha256: "TestMalware.A"}), encoding="utf-8")

    engine = HashEngine(blocklist_path=blocklist)
    result = engine.analyze(f)
    assert result.verdict == "malicious"
    assert result.score == 1.0
    assert any("TestMalware.A" in ind for ind in result.indicators)


def test_hash_engine_reload(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "evil.exe", "evil content")
    sha256, _ = compute_hashes(f)
    engine = HashEngine()
    assert engine.analyze(f).verdict == "clean"

    blocklist = tmp_path / "bl.json"
    blocklist.write_text(json.dumps({sha256: "Trojan.X"}), encoding="utf-8")
    engine.reload_blocklist(blocklist)
    assert engine.analyze(f).verdict == "malicious"


# ---------------------------------------------------------------------------
# PEEngine
# ---------------------------------------------------------------------------

def test_pe_engine_skips_non_pe(tmp_path: Path) -> None:
    f = _write_text(tmp_path, "readme.txt", "not a PE")
    assert not PEEngine().can_analyze(f)
    result = PEEngine().analyze(f)
    assert result.verdict == "clean"


def test_pe_engine_handles_corrupt_pe(tmp_path: Path) -> None:
    f = _write_bytes(tmp_path, "corrupt.exe", b"MZ" + b"\xff" * 100)
    result = PEEngine().analyze(f)
    assert result.verdict == "unknown"
    assert any("malformed" in ind or "PE" in ind for ind in result.indicators)


def test_section_entropy_zero_bytes() -> None:
    assert _section_entropy(b"\x00" * 100) == 0.0


def test_section_entropy_random_high() -> None:
    import os
    data = os.urandom(4096)
    entropy = _section_entropy(data)
    assert entropy > 6.0


# ---------------------------------------------------------------------------
# YaraEngine
# ---------------------------------------------------------------------------

def test_yara_engine_no_rules_dir_returns_clean(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    engine = YaraEngine(rules_dir=empty_dir)
    f = _write_text(tmp_path, "a.txt", "hello")
    result = engine.analyze(f)
    assert result.verdict == "clean"


def test_yara_engine_matches_custom_rule(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(
        'rule JKA_TEST { strings: $m = "JKA_MALWARE_TEST_MARKER" condition: $m }',
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=rules_dir)

    malicious_file = _write_text(tmp_path, "bad.bin", "data JKA_MALWARE_TEST_MARKER data")
    result = engine.analyze(malicious_file)
    assert result.verdict == "malicious"
    assert "JKA_TEST" in result.matched_rules


def test_yara_engine_clean_on_benign(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(
        'rule EICAR { strings: $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $e }',
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=rules_dir)
    f = _write_text(tmp_path, "clean.txt", "nothing suspicious here")
    result = engine.analyze(f)
    assert result.verdict == "clean"


# ---------------------------------------------------------------------------
# _merge_results
# ---------------------------------------------------------------------------

def test_merge_malicious_wins() -> None:
    from jka_antivirus.engines.base import EngineResult  # noqa: PLC0415

    results = [
        EngineResult(verdict="clean", score=0.0, engine="hash"),
        EngineResult(verdict="malicious", score=1.0, engine="yara"),
        EngineResult(verdict="suspicious", score=0.5, engine="pe"),
    ]
    verdict, score, reasoning = _merge_results(results)
    assert verdict == "malicious"
    assert score == 1.0
    assert "yara" in reasoning


def test_merge_empty_returns_unknown() -> None:
    verdict, score, _ = _merge_results([])
    assert verdict == "unknown"
    assert score == 0.0


# ---------------------------------------------------------------------------
# _collect_files
# ---------------------------------------------------------------------------

def test_collect_files_single_file(tmp_path: Path) -> None:
    f = _write_bytes(tmp_path, "sample.exe", b"MZ" + b"\x00" * 10)
    assert _collect_files(f) == [f]


def test_collect_files_skips_log_extension(tmp_path: Path) -> None:
    _write_text(tmp_path, "debug.log", "log content")
    _write_bytes(tmp_path, "real.exe", b"MZ" + b"\x00" * 10)
    files = _collect_files(tmp_path)
    names = {f.name for f in files}
    assert "real.exe" in names
    assert "debug.log" not in names


# ---------------------------------------------------------------------------
# run_scan (integration)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_scan_no_threats(tmp_path: Path) -> None:
    from jka_antivirus.db.connection import init_db  # noqa: PLC0415

    db_path = tmp_path / "jka.db"
    await init_db(db_path)

    scan_dir = tmp_path / "target"
    scan_dir.mkdir()
    _write_text(scan_dir, "readme.md", "nothing here")
    _write_bytes(scan_dir, "sample.bin", b"\x00" * 64)

    summary = await run_scan(target=scan_dir, db_path=db_path)
    assert summary.threats_found == 0
    assert summary.files_scanned >= 0
    assert summary.run_id > 0


@pytest.mark.asyncio
async def test_run_scan_detects_yara_match(tmp_path: Path) -> None:
    from jka_antivirus.db.connection import get_connection, init_db  # noqa: PLC0415

    db_path = tmp_path / "jka.db"
    await init_db(db_path)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(
        'rule JKA_TEST { strings: $m = "JKA_MALWARE_TEST_MARKER" condition: $m }',
        encoding="utf-8",
    )

    scan_dir = tmp_path / "target"
    scan_dir.mkdir()
    _write_text(scan_dir, "bad.bin", "data JKA_MALWARE_TEST_MARKER data")

    summary = await run_scan(target=scan_dir, db_path=db_path, rules_dir=rules_dir)
    assert summary.threats_found == 1

    async with get_connection(db_path) as conn:
        cur = await conn.execute(
            "SELECT verdict FROM detections WHERE scan_run_id=?", (summary.run_id,)
        )
        rows = await cur.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "malicious"


@pytest.mark.asyncio
async def test_run_scan_records_scan_run(tmp_path: Path) -> None:
    from jka_antivirus.db.connection import get_connection, init_db  # noqa: PLC0415

    db_path = tmp_path / "jka.db"
    await init_db(db_path)

    scan_dir = tmp_path / "target"
    scan_dir.mkdir()
    _write_bytes(scan_dir, "a.bin", b"\x00" * 8)

    summary = await run_scan(target=scan_dir, db_path=db_path)

    async with get_connection(db_path) as conn:
        cur = await conn.execute(
            "SELECT status, files_scanned FROM scan_runs WHERE id=?", (summary.run_id,)
        )
        row = await cur.fetchone()
    assert row is not None
    assert row[0] == "completed"
