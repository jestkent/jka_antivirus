# jka_antivirus

Layered, defense-in-depth antivirus engine for Windows 11, written in Python 3.11+.

**Current phase: Phase 1 (foundation scaffold).** No detection logic is active yet.

## Requirements

- Python 3.11 or newer
- Windows 11 (primary target; core scaffold runs cross-platform)

## Install

```powershell
cd d:\Desktop\jka_antivirus
pip install -e .
```

For development (includes pytest, ruff, mypy):

```powershell
pip install -e ".[dev]"
```

## Quick start

```powershell
# Initialise the SQLite database (idempotent, safe to run multiple times):
jka init-db

# Show database statistics:
jka status

# Scan a path (stub in Phase 1):
jka scan C:\Users\Cerus\Downloads

# List quarantine items (stub in Phase 1):
jka quarantine list

# Print all commands:
jka --help
```

## Configuration

Edit `config/config.yaml` for persistent settings. Override individual keys with environment variables prefixed `JKA_` and separated by `__`:

```powershell
$env:JKA_APP__LOG_LEVEL = "DEBUG"
$env:JKA_DATABASE__PATH = "C:\data\jka.db"
jka status
```

## Development

```powershell
# Run tests:
pytest

# Lint:
ruff check src/ tests/

# Type check:
mypy src/
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full seven-phase build plan.
See [docs/CLAUDE.md](docs/CLAUDE.md) for the Claude Code session guide.

## Project structure

```
jka_antivirus/
├── src/jka_antivirus/   # Installable package
│   ├── config.py        # Settings loader
│   ├── logging_setup.py # Logging configuration
│   ├── cli.py           # CLI entry point (jka command)
│   └── db/              # Database schema and async helpers
├── config/config.yaml   # Runtime configuration defaults
├── data/                # Runtime data (DB, logs, quarantine vault)
├── tests/               # pytest test suite
└── docs/                # Architecture and session documentation
```
