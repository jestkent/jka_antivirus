"""AI engine stub: plugs into the engine pipeline now; ML model added in Phase 6.

Phase 6 implementation plan:
  - Replace the no-op analyze() with a call to an XGBoost / ONNX model.
  - The model is trained on features extracted from the existing detections DB
    (file size, section entropy, import count, string patterns, etc.).
  - can_analyze() will return True for PE files and generic binaries once the
    model is trained; exclude scripts and docs the same way PEEngine does.
  - Model file path will be configurable via JKA_ML__MODEL_PATH.
"""

from __future__ import annotations

from pathlib import Path

from jka_antivirus.engines.base import BaseEngine, EngineResult


class AIEngine(BaseEngine):
    """Placeholder AI engine.

    Returns clean / score 0.0 until a model is loaded (Phase 6).
    The engine is intentionally always present in the pipeline so that
    adding the real model requires no changes to the orchestrator.
    """

    name = "ai"

    def can_analyze(self, path: Path) -> bool:
        return False  # disabled until Phase 6 — model not loaded

    def analyze(self, path: Path) -> EngineResult:
        return EngineResult(verdict="clean", score=0.0, engine=self.name)
