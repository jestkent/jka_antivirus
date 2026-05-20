"""PE analysis engine: inspects Windows executables for suspicious characteristics."""

from __future__ import annotations

import math
from pathlib import Path

import pefile

from jka_antivirus.engines.base import BaseEngine, EngineResult

_PE_MAGIC = (b"MZ", b"ZM")

# Imports commonly abused by malware.
_SUSPICIOUS_IMPORTS = frozenset(
    {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "CreateToolhelp32Snapshot",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "RegSetValueEx",
        "ShellExecuteEx",
        "URLDownloadToFile",
        "InternetOpenUrl",
        "WinExec",
        "CreateProcessA",
        "CreateProcessW",
    }
)

_SCORE_PER_INDICATOR = 0.12
_MALICIOUS_THRESHOLD = 0.75
_SUSPICIOUS_THRESHOLD = 0.30


def _section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy


def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            magic = fh.read(2)
        return magic in _PE_MAGIC
    except OSError:
        return False


class PEEngine(BaseEngine):
    """Scores PE files on a set of static heuristics."""

    name = "pe"

    def can_analyze(self, path: Path) -> bool:
        return path.is_file() and _is_pe(path)

    def analyze(self, path: Path) -> EngineResult:
        if not _is_pe(path):
            return EngineResult(verdict="clean", score=0.0, engine=self.name)

        indicators: list[str] = []

        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError as exc:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=[f"malformed PE: {exc}"],
            )
        except OSError as exc:
            return EngineResult(
                verdict="unknown",
                score=0.0,
                engine=self.name,
                indicators=[f"read error: {exc}"],
            )

        # Timestamp of 0 or in the future is suspicious.
        ts = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        if ts == 0:
            indicators.append("zero compile timestamp")
        elif ts is not None and ts > 2_000_000_000:
            indicators.append("future compile timestamp")

        # High-entropy sections indicate packing or encryption.
        try:
            for section in pe.sections:
                data = section.get_data()
                entropy = _section_entropy(data)
                name = section.Name.decode(errors="replace").strip("\x00")
                if entropy > 7.2:
                    indicators.append(f"high entropy section '{name}' ({entropy:.2f})")
        except Exception:  # noqa: BLE001
            indicators.append("section entropy check failed")

        # Suspicious imports.
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode(errors="replace") in _SUSPICIOUS_IMPORTS:
                        indicators.append(
                            f"suspicious import: {imp.name.decode(errors='replace')}"
                        )

        # No imports at all is suspicious (packer characteristic).
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            indicators.append("no import table (packed or hollow)")

        # Abnormally small overlay (data after last section) or large overlay.
        try:
            overlay = pe.get_overlay()
            if overlay and len(overlay) > 1_000_000:
                indicators.append(f"large overlay: {len(overlay):,} bytes")
        except Exception:  # noqa: BLE001
            pass

        # Check for TLS callbacks (anti-analysis / early execution).
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            indicators.append("TLS callbacks present")

        # Deduplicate indicators preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for ind in indicators:
            if ind not in seen:
                seen.add(ind)
                unique.append(ind)
        indicators = unique

        score = min(1.0, len(indicators) * _SCORE_PER_INDICATOR)
        if score >= _MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif score >= _SUSPICIOUS_THRESHOLD:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return EngineResult(
            verdict=verdict,
            score=score,
            engine=self.name,
            indicators=indicators,
        )
