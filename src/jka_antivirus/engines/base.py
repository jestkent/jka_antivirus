"""Abstract base class for all detection engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EngineResult:
    """Result produced by a single engine for a single file."""

    verdict: str  # "clean" | "suspicious" | "malicious" | "unknown"
    score: float  # 0.0 - 1.0
    engine: str
    indicators: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    def to_reasoning(self) -> dict[str, object]:
        return {
            "engine": self.engine,
            "verdict": self.verdict,
            "score": self.score,
            "indicators": self.indicators,
            "matched_rules": self.matched_rules,
        }


class BaseEngine(ABC):
    """All detection engines implement this interface."""

    name: str

    @abstractmethod
    def analyze(self, path: Path) -> EngineResult:
        """Analyze a file and return a verdict. Must not raise on corrupt input."""
        ...

    def can_analyze(self, path: Path) -> bool:
        """Return True if this engine is applicable to the given file."""
        return path.is_file()
