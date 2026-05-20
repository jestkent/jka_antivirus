# jka_antivirus Architecture

## Overview

jka_antivirus is a layered, defense-in-depth antivirus engine for Windows 11, written in Python 3.11+.
It is designed to run as a Windows service with a CLI management interface.

## Phase Plan

| Phase | Name | Key Deliverables |
|-------|------|-----------------|
| 1 | Foundation | Config, logging, SQLite schema, CLI skeleton (this phase) |
| 2 | Static Analysis | File type detection, PE parsing, YARA rule engine, hash reputation |
| 3 | Behavioral Analysis | Process monitoring via psutil/ETW, file-system watcher |
| 4 | Network Analysis | Packet capture via scapy, DNS/connection reputation |
| 5 | Cloud Integration | VirusTotal API, threat intelligence feeds |
| 6 | ML Engine | Feature extraction, XGBoost/neural classifier, explainability |
| 7 | Windows Service | NSSM/pywin32 service wrapper, real-time protection, auto-quarantine |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Config | Pydantic v2 BaseSettings + PyYAML |
| CLI | Typer + Rich |
| Database | SQLite via aiosqlite (WAL mode) |
| Logging | Python logging + Rich handler + RotatingFileHandler |
| Testing | pytest + pytest-asyncio |
| Linting | Ruff |
| Type checking | mypy (strict) |

## Project Layout

```
jka_antivirus/
├── src/jka_antivirus/       # Installable Python package
│   ├── config.py            # Settings loader (YAML + env vars)
│   ├── logging_setup.py     # Rich console + rotating file logging
│   ├── cli.py               # Typer CLI entry point
│   └── db/
│       ├── schema.sql       # SQLite DDL (all tables and indexes)
│       └── connection.py    # Async DB helpers (init_db, get_connection)
├── config/config.yaml       # Default runtime configuration
├── data/                    # Runtime data directory (DB, logs, quarantine vault)
├── tests/                   # pytest test suite
└── docs/                    # Architecture and session documentation
```

## Database Schema

Four core tables:

- `scan_runs`: records each scan invocation with timestamps and summary counts.
- `detections`: one row per suspicious file, linked to a scan run, stores hashes, verdict, score, and reasoning.
- `quarantine_items`: tracks files moved to the encrypted vault with original and vault paths.
- `event_log`: append-only journal for structured audit events from any component.

Indexes: `detections.file_hash_sha256`, `detections.detected_at`, `detections.verdict`, `event_log.timestamp`.

Foreign keys are enforced. WAL mode is enabled on every connection for concurrent read performance.

## Configuration

YAML file at `config/config.yaml` provides defaults. Any key can be overridden with an environment variable using prefix `JKA_` and delimiter `__`:

```
JKA_APP__LOG_LEVEL=DEBUG
JKA_DATABASE__PATH=C:\data\jka.db
JKA_QUARANTINE__RETENTION_DAYS=90
```

## CLI Commands

```
jka --help
jka init-db              # Creates DB and schema (idempotent)
jka status               # Prints row counts from all tables
jka scan <path>          # Stub: Phase 2
jka quarantine list      # Stub: Phase 2
```
