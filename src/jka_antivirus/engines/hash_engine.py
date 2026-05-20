"""Hash reputation engine: checks SHA256 against a local blocklist."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jka_antivirus.engines.base import BaseEngine, EngineResult

# Default blocklist bundled with the package (empty at install time).
# Operators add entries via `jka blocklist add <sha256> <label>`.
_BUNDLED_BLOCKLIST = Path(__file__).parent / "data" / "hash_blocklist.json"


def compute_hashes(path: Path) -> tuple[str, str]:
    """Return (sha256, md5) hex digests for a file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _load_blocklist(extra_path: Path | None) -> dict[str, str]:
    """Load the bundled blocklist and optionally merge a user-supplied one."""
    combined: dict[str, str] = {}
    for candidate in [_BUNDLED_BLOCKLIST, extra_path]:
        if candidate and candidate.exists():
            data: dict[str, str] = json.loads(candidate.read_text(encoding="utf-8-sig"))
            combined.update(data)
    return combined


class HashEngine(BaseEngine):
    """Verdict: malicious if SHA256 is in the blocklist, else clean."""

    name = "hash"

    def __init__(self, blocklist_path: Path | None = None) -> None:
        self._blocklist = _load_blocklist(blocklist_path)

    def reload_blocklist(self, blocklist_path: Path | None = None) -> None:
        self._blocklist = _load_blocklist(blocklist_path)

    def analyze(self, path: Path) -> EngineResult:
        try:
            sha256, _ = compute_hashes(path)
        except OSError as exc:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=[f"read error: {exc}"],
            )

        if sha256 in self._blocklist:
            label = self._blocklist[sha256]
            return EngineResult(
                verdict="malicious",
                score=1.0,
                engine=self.name,
                indicators=[f"hash match: {label}"],
            )

        return EngineResult(verdict="clean", score=0.0, engine=self.name)
