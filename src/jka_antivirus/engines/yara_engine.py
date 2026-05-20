"""YARA engine: matches files against compiled rules from a rules directory."""

from __future__ import annotations

import logging
from pathlib import Path

import yara

from jka_antivirus.engines.base import BaseEngine, EngineResult

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent.parent.parent / "rules"


def _compile_rules(rules_dir: Path) -> yara.Rules | None:
    """Compile all .yar and .yara files in rules_dir into a single Rules object."""
    rule_files = sorted(
        [*rules_dir.glob("*.yar"), *rules_dir.glob("*.yara")]
    )
    if not rule_files:
        return None

    filepaths: dict[str, str] = {}
    for rf in rule_files:
        filepaths[rf.stem] = str(rf)

    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error as exc:
        logger.warning("YARA compile error: %s", exc)
        return None


class YaraEngine(BaseEngine):
    """Verdict: malicious if any YARA rule matches, else clean."""

    name = "yara"

    def __init__(self, rules_dir: Path | None = None) -> None:
        resolved = rules_dir or _DEFAULT_RULES_DIR
        self._rules = _compile_rules(resolved) if resolved.is_dir() else None
        if self._rules is None:
            logger.debug("YARA engine: no rules loaded from %s", resolved)

    def reload_rules(self, rules_dir: Path) -> None:
        self._rules = _compile_rules(rules_dir)

    def can_analyze(self, path: Path) -> bool:
        return path.is_file() and self._rules is not None

    def analyze(self, path: Path) -> EngineResult:
        if self._rules is None:
            return EngineResult(verdict="clean", score=0.0, engine=self.name)

        try:
            file_data = path.read_bytes()
        except OSError as exc:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=[f"read error: {exc}"],
            )

        try:
            matches: list[yara.Match] = self._rules.match(data=file_data, timeout=30)
        except yara.TimeoutError:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=["YARA scan timed out"],
            )
        except yara.Error as exc:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=[f"YARA match error: {exc}"],
            )

        if not matches:
            return EngineResult(verdict="clean", score=0.0, engine=self.name)

        matched_rules = [m.rule for m in matches]
        indicators = [
            f"YARA match: {m.rule} (namespace={m.namespace})" for m in matches
        ]
        return EngineResult(
            verdict="malicious",
            score=1.0,
            engine=self.name,
            indicators=indicators,
            matched_rules=matched_rules,
        )
