"""Scanner orchestrator: walks a path, runs all engines, writes results to DB."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from jka_antivirus.db.connection import get_connection
from jka_antivirus.engines.base import BaseEngine, EngineResult
from jka_antivirus.engines.hash_engine import HashEngine, compute_hashes
from jka_antivirus.engines.pe_engine import PEEngine
from jka_antivirus.engines.yara_engine import YaraEngine

logger = logging.getLogger(__name__)

ScanProgressCallback = Callable[[int, int, Path], None]

_SKIP_EXTENSIONS = frozenset(
    {
        # Plaintext and config formats — not executable, high false-positive risk
        ".lnk", ".tmp", ".log", ".bak", ".ini", ".cfg", ".xml",
        ".json", ".yaml", ".yml", ".toml", ".csv", ".txt",
        # Source code and bytecode — YARA string rules false-positive on security
        # tool source that lists suspicious API names as data, not as calls
        ".py", ".pyc", ".pyo", ".pyd",
        ".js", ".ts", ".rb", ".go", ".rs", ".java", ".cs", ".cpp", ".c", ".h",
        # YARA rule files themselves contain the strings they search for
        ".yar", ".yara",
    }
)

_MAX_FILE_SIZE = 256 * 1024 * 1024  # 256 MB


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _merge_results(results: list[EngineResult]) -> tuple[str, float, dict[str, object]]:
    """Combine per-engine results into a single verdict, score, and reasoning blob."""
    if not results:
        return "unknown", 0.0, {}

    priority = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}
    final_verdict = max(results, key=lambda r: priority.get(r.verdict, 0)).verdict
    final_score = max(r.score for r in results)
    reasoning: dict[str, object] = {r.engine: r.to_reasoning() for r in results}
    return final_verdict, final_score, reasoning


def _collect_files(target: Path) -> list[Path]:
    """Return all scannable files under target, applying size and extension filters."""
    if target.is_file():
        return [target]

    files: list[Path] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_SIZE:
            logger.debug("Skipping oversized file: %s (%d bytes)", path, size)
            continue
        files.append(path)
    return files


def _build_engines(
    blocklist_path: Path | None,
    rules_dir: Path | None,
) -> list[BaseEngine]:
    return [HashEngine(blocklist_path), PEEngine(), YaraEngine(rules_dir)]


async def _insert_scan_run(conn: aiosqlite.Connection, started_at: str) -> int:
    cursor = await conn.execute(
        "INSERT INTO scan_runs (started_at, status) VALUES (?, 'running')",
        (started_at,),
    )
    await conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def _update_scan_run(
    conn: aiosqlite.Connection,
    run_id: int,
    finished_at: str,
    files_scanned: int,
    threats_found: int,
    status: str,
) -> None:
    await conn.execute(
        """
        UPDATE scan_runs
        SET finished_at=?, files_scanned=?, threats_found=?, status=?
        WHERE id=?
        """,
        (finished_at, files_scanned, threats_found, status, run_id),
    )
    await conn.commit()


async def _insert_detection(
    conn: aiosqlite.Connection,
    run_id: int,
    path: Path,
    sha256: str,
    md5: str,
    verdict: str,
    score: float,
    reasoning: dict[str, object],
) -> None:
    await conn.execute(
        """
        INSERT INTO detections
            (scan_run_id, file_path, file_hash_sha256, file_hash_md5,
             verdict, score, reasoning_json, detected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, str(path), sha256, md5, verdict, score, json.dumps(reasoning), _now_iso()),
    )


class ScanSummary:
    def __init__(
        self,
        run_id: int,
        files_scanned: int,
        threats_found: int,
        target: Path,
    ) -> None:
        self.run_id = run_id
        self.files_scanned = files_scanned
        self.threats_found = threats_found
        self.target = target


async def run_scan(
    target: Path,
    db_path: Path,
    blocklist_path: Path | None = None,
    rules_dir: Path | None = None,
    on_progress: ScanProgressCallback | None = None,
) -> ScanSummary:
    """Run all engines against target and persist results to the database.

    Args:
        target: File or directory to scan.
        db_path: Path to the SQLite database.
        blocklist_path: Optional extra hash blocklist JSON file.
        rules_dir: Optional directory of YARA .yar/.yara rule files.
        on_progress: Optional callback(current, total, path) for UI updates.

    Returns:
        ScanSummary with counts and the scan_run_id.
    """
    engines = _build_engines(blocklist_path, rules_dir)
    files = _collect_files(target)
    total = len(files)
    started_at = _now_iso()
    files_scanned = 0
    threats_found = 0

    async with get_connection(db_path) as conn:
        run_id = await _insert_scan_run(conn, started_at)

        for idx, file_path in enumerate(files):
            if on_progress:
                on_progress(idx, total, file_path)

            try:
                sha256, md5 = compute_hashes(file_path)
            except OSError as exc:
                logger.warning("Cannot hash %s: %s", file_path, exc)
                continue

            applicable = [e for e in engines if e.can_analyze(file_path)]
            results: list[EngineResult] = []
            for engine in applicable:
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, engine.analyze, file_path
                    )
                    results.append(result)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Engine %s failed on %s: %s", engine.name, file_path, exc)

            if not results:
                files_scanned += 1
                continue

            verdict, score, reasoning = _merge_results(results)

            if verdict in ("suspicious", "malicious"):
                threats_found += 1
                await _insert_detection(
                    conn, run_id, file_path, sha256, md5, verdict, score, reasoning
                )
                await conn.commit()

            files_scanned += 1

        await _update_scan_run(conn, run_id, _now_iso(), files_scanned, threats_found, "completed")

    return ScanSummary(
        run_id=run_id,
        files_scanned=files_scanned,
        threats_found=threats_found,
        target=target,
    )
