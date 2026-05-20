# jka_antivirus: Claude Session Guide

Read this file first. It gives you everything needed to continue work on this project without asking the user to re-explain the context.

## What this project is

A layered, defense-in-depth antivirus engine for Windows 11, written in Python 3.11+.
It is intended to run as a Windows service (Phase 7). The codebase is fully typed, async-first for I/O, and modular so each detection layer can be developed and tested independently.

## Current state (Phase 1, completed)

Phase 1 delivered the foundation only. No detection logic exists yet.

Completed:
- `src/jka_antivirus/config.py`: Pydantic v2 BaseSettings, loads `config/config.yaml` then applies `JKA_` env var overrides.
- `src/jka_antivirus/logging_setup.py`: Rich console handler + RotatingFileHandler, called once at CLI startup.
- `src/jka_antivirus/db/schema.sql`: Four tables (`scan_runs`, `detections`, `quarantine_items`, `event_log`) with indexes and foreign keys.
- `src/jka_antivirus/db/connection.py`: `init_db`, `get_connection` (async context manager), `get_table_counts`.
- `src/jka_antivirus/cli.py`: Typer app. `jka init-db` and `jka status` are functional; `jka scan` and `jka quarantine list` are stubs.
- `tests/test_config.py` and `tests/test_db.py`: pytest-asyncio test suite covering all Phase 1 code.

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
