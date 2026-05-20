-- jka_antivirus SQLite schema
-- All tables use INTEGER PRIMARY KEY (rowid alias) for maximum insert speed.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- scan_runs: one row per invocation of the scan engine
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT    NOT NULL,
    finished_at    TEXT,
    files_scanned  INTEGER NOT NULL DEFAULT 0,
    threats_found  INTEGER NOT NULL DEFAULT 0,
    status         TEXT    NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running', 'completed', 'failed', 'cancelled'))
);

-- ---------------------------------------------------------------------------
-- detections: one row per suspicious file found during a scan
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id        INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    file_path          TEXT    NOT NULL,
    file_hash_sha256   TEXT    NOT NULL,
    file_hash_md5      TEXT    NOT NULL,
    verdict            TEXT    NOT NULL DEFAULT 'unknown'
                       CHECK (verdict IN ('clean', 'suspicious', 'malicious', 'unknown')),
    score              REAL    NOT NULL DEFAULT 0.0,
    reasoning_json     TEXT    NOT NULL DEFAULT '{}',
    detected_at        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detections_sha256
    ON detections(file_hash_sha256);

CREATE INDEX IF NOT EXISTS idx_detections_detected_at
    ON detections(detected_at);

CREATE INDEX IF NOT EXISTS idx_detections_verdict
    ON detections(verdict);

-- ---------------------------------------------------------------------------
-- quarantine_items: tracks files moved to the encrypted vault
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quarantine_items (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id   INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    original_path  TEXT    NOT NULL,
    vault_path     TEXT    NOT NULL,
    encrypted_key  TEXT    NOT NULL,
    quarantined_at TEXT    NOT NULL,
    restored_at    TEXT
);

-- ---------------------------------------------------------------------------
-- event_log: append-only structured event journal
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT    NOT NULL,
    level        TEXT    NOT NULL DEFAULT 'INFO'
                 CHECK (level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    message      TEXT    NOT NULL,
    payload_json TEXT    NOT NULL DEFAULT '{}',
    timestamp    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_log_timestamp
    ON event_log(timestamp);
