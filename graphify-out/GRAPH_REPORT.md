# Graph Report - .  (2026-05-19)

## Corpus Check
- Corpus is ~3,308 words - fits in a single context window. You may not need a graph.

## Summary
- 111 nodes · 136 edges · 18 communities detected
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 27 edges (avg confidence: 0.79)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_CLI Command Layer|CLI Command Layer]]
- [[_COMMUNITY_Config Models and Loaders|Config Models and Loaders]]
- [[_COMMUNITY_Settings Validation and Tests|Settings Validation and Tests]]
- [[_COMMUNITY_CLI-Config Integration|CLI-Config Integration]]
- [[_COMMUNITY_Table Count Queries|Table Count Queries]]
- [[_COMMUNITY_Database Initialization|Database Initialization]]
- [[_COMMUNITY_Async DB Connection Layer|Async DB Connection Layer]]
- [[_COMMUNITY_Schema Integrity Tests|Schema Integrity Tests]]
- [[_COMMUNITY_Schema DDL and Tables|Schema DDL and Tables]]
- [[_COMMUNITY_Project Docs and Vision|Project Docs and Vision]]
- [[_COMMUNITY_CLI App Structure|CLI App Structure]]
- [[_COMMUNITY_Package Init|Package Init]]
- [[_COMMUNITY_DB Connection Module|DB Connection Module]]
- [[_COMMUNITY_WAL Mode Test|WAL Mode Test]]
- [[_COMMUNITY_DB Package Init|DB Package Init]]
- [[_COMMUNITY_Test Suite Init|Test Suite Init]]
- [[_COMMUNITY_Logger Factory|Logger Factory]]
- [[_COMMUNITY_Event Log Table|Event Log Table]]

## God Nodes (most connected - your core abstractions)
1. `init_db()` - 13 edges
2. `load_settings()` - 10 edges
3. `get_connection()` - 10 edges
4. `get_table_counts()` - 8 edges
5. `load_settings` - 8 edges
6. `Settings` - 6 edges
7. `status()` - 5 edges
8. `init_db_cmd()` - 5 edges
9. `Settings (BaseSettings)` - 5 edges
10. `setup_logging()` - 4 edges

## Surprising Connections (you probably didn't know these)
- `setup_logging` --semantically_similar_to--> `Async-first I/O design principle`  [INFERRED] [semantically similar]
  src/jka_antivirus/logging_setup.py → docs/CLAUDE.md
- `config/config.yaml runtime defaults` --shares_data_with--> `Settings (BaseSettings)`  [INFERRED]
  config/config.yaml → src/jka_antivirus/config.py
- `Async-first I/O design principle` --rationale_for--> `get_connection()`  [EXTRACTED]
  docs/CLAUDE.md → src\jka_antivirus\db\connection.py
- `Defense-in-depth layered AV engine` --rationale_for--> `scan command`  [INFERRED]
  docs/ARCHITECTURE.md → src/jka_antivirus/cli.py
- `config/config.yaml runtime defaults` --shares_data_with--> `load_settings`  [EXTRACTED]
  config/config.yaml → src/jka_antivirus/config.py

## Hyperedges (group relationships)
- **CLI command startup flow: load settings, configure logging, run DB op** — cli_status, config_load_settings, logging_setup_logging, db_connection_get_table_counts [EXTRACTED 1.00]
- **DB schema referential integrity chain: scan_runs -> detections -> quarantine_items** — db_schema_scan_runs, db_schema_detections, db_schema_quarantine_items [EXTRACTED 1.00]
- **Layered config resolution: YAML file -> env var injection -> Pydantic BaseSettings** — config_yaml_runtime, config_load_settings, config_Settings [EXTRACTED 1.00]

## Communities

### Community 0 - "CLI Command Layer"
Cohesion: 0.12
Nodes (14): init_db_cmd(), quarantine_list(), jka_antivirus CLI: typer-based entry point., Scan a file or directory for threats., Show database statistics: scan runs, detections, quarantine items., Create the SQLite database and apply the schema (idempotent)., List quarantined files., scan() (+6 more)

### Community 1 - "Config Models and Loaders"
Cohesion: 0.18
Nodes (13): BaseModel, AppConfig, DatabaseConfig, _default_config_path(), _flatten_yaml(), load_settings(), _load_yaml(), QuarantineConfig (+5 more)

### Community 2 - "Settings Validation and Tests"
Cohesion: 0.16
Nodes (13): BaseSettings, Settings, Tests for the config loader (config.py)., Settings load with defaults when no YAML or env vars are set., Values from a YAML file are picked up by load_settings., JKA_ environment variables override YAML values., An invalid log_level value raises a validation error., retention_days must be >= 1. (+5 more)

### Community 3 - "CLI-Config Integration"
Cohesion: 0.16
Nodes (14): init-db command, status command, AppConfig, DatabaseConfig, QuarantineConfig, Settings (BaseSettings), _default_config_path, _flatten_yaml (+6 more)

### Community 4 - "Table Count Queries"
Cohesion: 0.29
Nodes (7): get_table_counts(), Return row counts for the four core tables. Returns zeros if DB does not exist., test_db module, get_table_counts returns zeros when the database file does not exist., get_table_counts returns zeros for an empty, freshly initialised database., test_get_table_counts_missing_db(), test_get_table_counts_zeros_on_fresh_db()

### Community 5 - "Database Initialization"
Cohesion: 0.33
Nodes (6): init_db(), Create the database file and apply the schema (idempotent via IF NOT EXISTS)., init_db creates the database file., Calling init_db twice does not raise an error (IF NOT EXISTS)., test_init_db_creates_file(), test_init_db_is_idempotent()

### Community 6 - "Async DB Connection Layer"
Cohesion: 0.33
Nodes (6): Async-first I/O design principle, get_connection(), Yield a configured aiosqlite connection with WAL mode and foreign keys active., WAL mode + foreign key enforcement pattern, Required indexes exist after init_db., test_indexes_exist()

### Community 7 - "Schema Integrity Tests"
Cohesion: 0.33
Nodes (5): Tests for the SQLite schema and async connection layer (db/connection.py)., All four schema tables exist after init_db., Foreign key constraints are active: inserting a detection without a scan_run fai, test_all_tables_exist(), test_foreign_keys_enforced()

### Community 8 - "Schema DDL and Tables"
Cohesion: 0.4
Nodes (5): _get_schema_sql(), Read schema.sql from the package, supporting both installed and editable install, detections table, quarantine_items table, scan_runs table

### Community 9 - "Project Docs and Vision"
Cohesion: 0.4
Nodes (4): Defense-in-depth layered AV engine, scan command, CLAUDE.md session guide, jka_antivirus README

### Community 10 - "CLI App Structure"
Cohesion: 0.5
Nodes (4): jka Typer App, main entry point, quarantine sub-app, quarantine list command

### Community 11 - "Package Init"
Cohesion: 1.0
Nodes (1): jka_antivirus: layered Windows antivirus engine.

### Community 12 - "DB Connection Module"
Cohesion: 1.0
Nodes (1): Async SQLite connection layer using aiosqlite.

### Community 13 - "WAL Mode Test"
Cohesion: 1.0
Nodes (2): WAL journal mode is active after connecting via get_connection., test_wal_mode_enabled()

### Community 14 - "DB Package Init"
Cohesion: 1.0
Nodes (1): Database package: schema, async connection layer.

### Community 15 - "Test Suite Init"
Cohesion: 1.0
Nodes (1): Test suite for jka_antivirus Phase 1 scaffold.

### Community 16 - "Logger Factory"
Cohesion: 1.0
Nodes (1): get_logger

### Community 17 - "Event Log Table"
Cohesion: 1.0
Nodes (1): event_log table

## Knowledge Gaps
- **51 isolated node(s):** `jka_antivirus CLI: typer-based entry point.`, `Scan a file or directory for threats.`, `Show database statistics: scan runs, detections, quarantine items.`, `Create the SQLite database and apply the schema (idempotent).`, `List quarantined files.` (+46 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Package Init`** (2 nodes): `jka_antivirus: layered Windows antivirus engine.`, `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DB Connection Module`** (2 nodes): `Async SQLite connection layer using aiosqlite.`, `connection.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `WAL Mode Test`** (2 nodes): `WAL journal mode is active after connecting via get_connection.`, `test_wal_mode_enabled()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DB Package Init`** (2 nodes): `Database package: schema, async connection layer.`, `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Test Suite Init`** (2 nodes): `__init__.py`, `Test suite for jka_antivirus Phase 1 scaffold.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Logger Factory`** (1 nodes): `get_logger`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Event Log Table`** (1 nodes): `event_log table`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `load_settings()` connect `Config Models and Loaders` to `CLI Command Layer`, `Settings Validation and Tests`?**
  _High betweenness centrality (0.327) - this node is a cross-community bridge._
- **Why does `init_db()` connect `Database Initialization` to `CLI Command Layer`, `CLI-Config Integration`, `Table Count Queries`, `Async DB Connection Layer`, `Schema Integrity Tests`, `Schema DDL and Tables`, `DB Connection Module`, `WAL Mode Test`?**
  _High betweenness centrality (0.303) - this node is a cross-community bridge._
- **Why does `init_db_cmd()` connect `CLI Command Layer` to `Config Models and Loaders`, `Database Initialization`?**
  _High betweenness centrality (0.262) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `init_db()` (e.g. with `init_db_cmd()` and `test_init_db_creates_file()`) actually correct?**
  _`init_db()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `load_settings()` (e.g. with `status()` and `init_db_cmd()`) actually correct?**
  _`load_settings()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `get_connection()` (e.g. with `test_all_tables_exist()` and `test_indexes_exist()`) actually correct?**
  _`get_connection()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `get_table_counts()` (e.g. with `status()` and `test_get_table_counts_zeros_on_fresh_db()`) actually correct?**
  _`get_table_counts()` has 3 INFERRED edges - model-reasoned connections that need verification._