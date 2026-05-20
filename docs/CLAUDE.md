# jka_antivirus: Claude Session Guide

Read this file first. It gives you everything needed to continue work on this project without asking the user to re-explain the context.

## What this project is

A layered, defense-in-depth antivirus engine for Windows 11, written in Python 3.11+.
It is intended to run as a Windows service (Phase 7). The codebase is fully typed, async-first for I/O, and modular so each detection layer can be developed and tested independently.

## Current state (Phase 2, completed)

Phase 2 delivers the static analysis layer. `jka scan` is now fully functional.

**Phase 1 foundation (still present):**
- `src/jka_antivirus/config.py`: Pydantic v2 BaseSettings, loads `config/config.yaml` then applies `JKA_` env var overrides.
- `src/jka_antivirus/logging_setup.py`: Rich console handler + RotatingFileHandler, called once at CLI startup.
- `src/jka_antivirus/db/schema.sql`: Four tables (`scan_runs`, `detections`, `quarantine_items`, `event_log`) with indexes and foreign keys.
- `src/jka_antivirus/db/connection.py`: `init_db`, `get_connection` (async context manager), `get_table_counts`.

**Phase 2 additions:**
- `src/jka_antivirus/engines/base.py`: `BaseEngine` ABC and `EngineResult` dataclass. All engines implement `analyze(path) -> EngineResult`.
- `src/jka_antivirus/engines/hash_engine.py`: SHA256/MD5 hash computation; checks against a JSON blocklist. Bundled empty blocklist at `engines/data/hash_blocklist.json`.
- `src/jka_antivirus/engines/pe_engine.py`: Uses `pefile` to score Windows executables on: zero/future timestamps, high-entropy sections (>7.2), suspicious imports (VirtualAllocEx, WriteProcessMemory, etc.), missing import table, large overlay, TLS callbacks.
- `src/jka_antivirus/engines/yara_engine.py`: Compiles all `.yar`/`.yara` files from `rules/` and matches against file bytes (reads bytes then passes `data=` to avoid Windows path issues). Gracefully no-ops when rules dir is empty.
- `src/jka_antivirus/scanner.py`: Orchestrator. Collects files (skips `.log .tmp .txt` etc., max 256 MB), runs all engines, merges verdicts (malicious > suspicious > unknown > clean), writes `scan_runs` + `detections` rows to DB.
- `rules/common_malware.yar`: Five starter YARA rules (download-and-execute, keylogger, process injection, anti-debug, EICAR test marker).
- `src/jka_antivirus/cli.py`: `jka scan <path> [--blocklist] [--rules]` is functional with a rich progress bar. `jka quarantine list` stub moved to Phase 3.
- `tests/test_engines.py`: 19 new tests covering all engines and the scanner orchestrator.

## Phase plan at a glance

| Phase | What to build |
|-------|--------------|
| 2 | Static analysis: PE parser (pefile), YARA engine, hash reputation lookup |
| 3 | Behavioral: psutil process monitor, watchdog file-system watcher |
| 4 | Network: scapy capture, DNS/connection reputation |
| 5 | Cloud: VirusTotal API, threat intel feeds |
| 6 | ML: feature extraction, XGBoost classifier |
| 7 | Windows service: pywin32 service wrapper, real-time protection |

## Key conventions to follow

- Type hints on every function and method, no exceptions.
- Async-first for all DB and I/O code. Use `asyncio.run()` only at the CLI boundary.
- Paths always via `pathlib.Path`, never raw string concatenation.
- No em-dashes anywhere in source files or docs (use commas, periods, or colons instead).
- No comments explaining what code does. Only add a comment when the WHY is non-obvious.
- `ruff check` must pass before committing (see `pyproject.toml` for rule set).
- `mypy src/` with strict mode must pass.

## Where things live

| File | Purpose |
|------|---------|
| `src/jka_antivirus/config.py` | Settings loader. Modify here when adding new config sections. |
| `src/jka_antivirus/db/schema.sql` | DDL. Add new tables/indexes here and re-run `jka init-db`. |
| `src/jka_antivirus/db/connection.py` | Async DB helpers. Add new query helpers here. |
| `src/jka_antivirus/cli.py` | CLI commands. Register new subcommands here. |
| `config/config.yaml` | Runtime defaults. Add new top-level sections for each new phase. |
| `data/` | Runtime files: `jka.db`, `logs/`, `quarantine/`. Not committed. |

## How to install and run

```powershell
cd d:\Desktop\jka_antivirus
pip install -e ".[dev]"   # or: pip install -e .
jka --help
jka init-db
jka status
pytest
```

## Environment variable overrides

Prefix: `JKA_`, delimiter: `__`.

```
JKA_APP__LOG_LEVEL=DEBUG
JKA_DATABASE__PATH=C:\data\jka.db
```

## What NOT to do in Phase 2+

- Do not import `yara`, `pefile`, `psutil`, `scapy`, `torch`, or `xgboost` until the relevant phase begins. Add them to `pyproject.toml` only when the phase starts.
- Do not store raw file bytes in the database. Store hashes and paths only.
- Do not block the event loop with synchronous I/O. All file reads in detection engines must be async or run in a thread pool.
