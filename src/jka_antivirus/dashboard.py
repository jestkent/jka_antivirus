"""Browser dashboard: FastAPI app exposing scan data from the SQLite DB."""
# ruff: noqa: E501

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from jka_antivirus.db.connection import get_connection

app = FastAPI(title="jka_antivirus Dashboard", docs_url=None, redoc_url=None)

_db_path: Path = Path("data/jka.db")


def configure(db_path: Path) -> None:
    """Set the DB path before the server starts (called from CLI)."""
    global _db_path
    _db_path = db_path


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def api_stats() -> dict[str, int]:
    if not _db_path.exists():
        return {"scan_runs": 0, "detections": 0, "quarantine_items": 0}
    async with get_connection(_db_path) as conn:
        counts: dict[str, int] = {}
        for table in ("scan_runs", "detections", "quarantine_items"):
            cur = await conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            row = await cur.fetchone()
            counts[table] = row[0] if row else 0
        cur = await conn.execute(
            "SELECT COALESCE(SUM(files_scanned), 0) FROM scan_runs"
        )
        row = await cur.fetchone()
        counts["files_scanned_total"] = row[0] if row else 0
    return counts


@app.get("/api/scans")
async def api_scans(limit: int = Query(default=25, le=200)) -> list[dict[str, Any]]:
    if not _db_path.exists():
        return []
    async with get_connection(_db_path) as conn:
        cur = await conn.execute(
            """
            SELECT id, started_at, finished_at, files_scanned, threats_found, status
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cur.fetchall()
    return [
        {
            "id": r[0],
            "started_at": r[1],
            "finished_at": r[2],
            "files_scanned": r[3],
            "threats_found": r[4],
            "status": r[5],
        }
        for r in rows
    ]


@app.get("/api/detections")
async def api_detections(
    limit: int = Query(default=100, le=500),
    verdict: str | None = Query(default=None),
    scan_run_id: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    if not _db_path.exists():
        return []
    where_clauses: list[str] = []
    params: list[Any] = []
    if verdict:
        where_clauses.append("verdict = ?")
        params.append(verdict)
    if scan_run_id is not None:
        where_clauses.append("scan_run_id = ?")
        params.append(scan_run_id)
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    params.append(limit)
    async with get_connection(_db_path) as conn:
        cur = await conn.execute(
            f"""
            SELECT id, scan_run_id, file_path, file_hash_sha256,
                   verdict, score, reasoning_json, detected_at
            FROM detections
            {where_sql}
            ORDER BY detected_at DESC
            LIMIT ?
            """,  # noqa: S608
            params,
        )
        rows = await cur.fetchall()
    return [
        {
            "id": r[0],
            "scan_run_id": r[1],
            "file_path": r[2],
            "sha256": r[3],
            "verdict": r[4],
            "score": r[5],
            "reasoning": _safe_json(r[6]),
            "detected_at": r[7],
        }
        for r in rows
    ]


@app.get("/api/detections/{detection_id}")
async def api_detection_detail(detection_id: int) -> dict[str, Any]:
    if not _db_path.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    async with get_connection(_db_path) as conn:
        cur = await conn.execute(
            """
            SELECT id, scan_run_id, file_path, file_hash_sha256, file_hash_md5,
                   verdict, score, reasoning_json, detected_at
            FROM detections WHERE id = ?
            """,
            (detection_id,),
        )
        row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return {
        "id": row[0],
        "scan_run_id": row[1],
        "file_path": row[2],
        "sha256": row[3],
        "md5": row[4],
        "verdict": row[5],
        "score": row[6],
        "reasoning": _safe_json(row[7]),
        "detected_at": row[8],
    }


def _safe_json(raw: str | None) -> object:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jka_antivirus Dashboard</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3d;
    --text: #e2e8f0; --muted: #64748b; --accent: #6366f1;
    --red: #ef4444; --yellow: #f59e0b; --green: #22c55e; --blue: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  a { color: var(--accent); text-decoration: none; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  header span.sub { color: var(--muted); font-size: 12px; }
  .badge-live { background: var(--green); color: #000; font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 99px; }
  main { max-width: 1300px; margin: 0 auto; padding: 24px; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
  .card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px; }
  .card .value { font-size: 32px; font-weight: 700; }
  .card .value.red { color: var(--red); }
  .card .value.green { color: var(--green); }
  .card .value.accent { color: var(--accent); }
  .section-title { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 12px; }
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 28px; }
  .panel-header { padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  .panel-header h2 { font-size: 14px; font-weight: 600; }
  .filter-row { padding: 10px 18px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  select, input { background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 5px 10px; font-size: 13px; }
  select:focus, input:focus { outline: 1px solid var(--accent); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 14px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: 9px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .verdict { display: inline-block; padding: 2px 9px; border-radius: 99px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .verdict.malicious { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
  .verdict.suspicious { background: rgba(245,158,11,0.15); color: var(--yellow); border: 1px solid rgba(245,158,11,0.3); }
  .verdict.clean { background: rgba(34,197,94,0.12); color: var(--green); border: 1px solid rgba(34,197,94,0.25); }
  .verdict.completed { background: rgba(99,102,241,0.12); color: var(--accent); border: 1px solid rgba(99,102,241,0.25); }
  .verdict.running { background: rgba(59,130,246,0.12); color: var(--blue); border: 1px solid rgba(59,130,246,0.25); }
  .score-bar { display: flex; align-items: center; gap: 8px; }
  .score-bar .bar { flex: 1; height: 5px; background: var(--border); border-radius: 99px; overflow: hidden; }
  .score-bar .fill { height: 100%; border-radius: 99px; }
  .detail-modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; align-items: center; justify-content: center; }
  .detail-modal.open { display: flex; }
  .modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; width: 700px; max-width: 95vw; max-height: 80vh; overflow-y: auto; padding: 24px; }
  .modal-box h3 { font-size: 16px; font-weight: 700; margin-bottom: 16px; }
  .modal-box .close-btn { float: right; cursor: pointer; color: var(--muted); font-size: 20px; line-height: 1; }
  .kv { display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; margin-bottom: 16px; }
  .kv .k { color: var(--muted); font-size: 12px; }
  .kv .v { font-size: 12px; word-break: break-all; }
  pre.reasoning { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-size: 12px; color: var(--text); overflow-x: auto; white-space: pre-wrap; }
  .empty { padding: 40px; text-align: center; color: var(--muted); }
  .refresh-note { color: var(--muted); font-size: 11px; }
  @media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<header>
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <rect width="28" height="28" rx="8" fill="#6366f1"/>
    <path d="M14 5L20 8.5V15.5C20 18.5 17.5 21.2 14 22C10.5 21.2 8 18.5 8 15.5V8.5L14 5Z" fill="white" opacity="0.9"/>
  </svg>
  <h1>jka_antivirus</h1>
  <span class="sub">Dashboard</span>
  <span class="badge-live">LIVE</span>
</header>

<main>
  <div class="stats" id="stats">
    <div class="card"><div class="label">Total Scans</div><div class="value accent" id="s-runs">—</div></div>
    <div class="card"><div class="label">Files Scanned</div><div class="value" id="s-files">—</div></div>
    <div class="card"><div class="label">Threats Found</div><div class="value red" id="s-threats">—</div></div>
    <div class="card"><div class="label">Quarantined</div><div class="value green" id="s-quarantine">—</div></div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <h2>Recent Scan Runs</h2>
      <span class="refresh-note" id="refresh-note">auto-refresh 10s</span>
    </div>
    <table id="scans-table">
      <thead><tr><th>ID</th><th>Started</th><th>Finished</th><th>Files</th><th>Threats</th><th>Status</th></tr></thead>
      <tbody id="scans-body"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>

  <div class="panel">
    <div class="panel-header"><h2>Detections</h2></div>
    <div class="filter-row">
      <select id="f-verdict" onchange="loadDetections()">
        <option value="">All verdicts</option>
        <option value="malicious">Malicious</option>
        <option value="suspicious">Suspicious</option>
      </select>
      <input id="f-run" type="number" placeholder="Scan run ID" oninput="loadDetections()" style="width:140px">
      <input id="f-search" type="text" placeholder="Filter by filename..." oninput="filterTable()" style="width:220px">
    </div>
    <table id="det-table">
      <thead><tr><th>ID</th><th>File</th><th>Verdict</th><th>Score</th><th>Detected</th><th>Run</th></tr></thead>
      <tbody id="det-body"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>
</main>

<div class="detail-modal" id="modal" onclick="closeModal(event)">
  <div class="modal-box" id="modal-box">
    <span class="close-btn" onclick="closeModal()">&times;</span>
    <h3 id="modal-title">Detection Detail</h3>
    <div class="kv" id="modal-kv"></div>
    <div class="section-title" style="margin-top:12px">Engine Reasoning</div>
    <pre class="reasoning" id="modal-reasoning"></pre>
  </div>
</div>

<script>
let _detRows = [];

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.json();
}

async function loadStats() {
  const d = await fetchJSON('/api/stats');
  if (!d) return;
  document.getElementById('s-runs').textContent = d.scan_runs ?? 0;
  document.getElementById('s-files').textContent = (d.files_scanned_total ?? 0).toLocaleString();
  document.getElementById('s-threats').textContent = d.detections ?? 0;
  document.getElementById('s-quarantine').textContent = d.quarantine_items ?? 0;
}

function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleString();
}

function verdictBadge(v) {
  return `<span class="verdict ${v}">${v}</span>`;
}

function scoreBar(score) {
  const pct = Math.round(score * 100);
  const color = score >= 0.75 ? '#ef4444' : score >= 0.3 ? '#f59e0b' : '#22c55e';
  return `<div class="score-bar">
    <div class="bar"><div class="fill" style="width:${pct}%;background:${color}"></div></div>
    <span style="color:${color};font-size:12px;font-weight:600;min-width:34px">${pct}%</span>
  </div>`;
}

async function loadScans() {
  const rows = await fetchJSON('/api/scans?limit=25');
  const tbody = document.getElementById('scans-body');
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No scan runs yet. Run <code>jka scan &lt;path&gt;</code> to get started.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td style="color:var(--muted)">#${r.id}</td>
      <td>${fmtDate(r.started_at)}</td>
      <td>${fmtDate(r.finished_at)}</td>
      <td>${(r.files_scanned ?? 0).toLocaleString()}</td>
      <td style="color:${r.threats_found > 0 ? 'var(--red)' : 'var(--green)'};font-weight:600">${r.threats_found}</td>
      <td>${verdictBadge(r.status)}</td>
    </tr>`).join('');
}

async function loadDetections() {
  const verdict = document.getElementById('f-verdict').value;
  const runId = document.getElementById('f-run').value;
  let url = '/api/detections?limit=200';
  if (verdict) url += '&verdict=' + encodeURIComponent(verdict);
  if (runId) url += '&scan_run_id=' + encodeURIComponent(runId);
  const rows = await fetchJSON(url);
  _detRows = rows || [];
  renderDetections(_detRows);
}

function renderDetections(rows) {
  const tbody = document.getElementById('det-body');
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No detections match the current filter.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const fname = r.file_path ? r.file_path.replace(/\\\\/g, '/').split('/').pop() : '—';
    return `<tr style="cursor:pointer" onclick="openModal(${r.id})">
      <td style="color:var(--muted)">#${r.id}</td>
      <td title="${r.file_path}">${fname}</td>
      <td>${verdictBadge(r.verdict)}</td>
      <td style="min-width:130px">${scoreBar(r.score ?? 0)}</td>
      <td>${fmtDate(r.detected_at)}</td>
      <td style="color:var(--muted)">#${r.scan_run_id}</td>
    </tr>`;
  }).join('');
}

function filterTable() {
  const q = document.getElementById('f-search').value.toLowerCase();
  if (!q) { renderDetections(_detRows); return; }
  renderDetections(_detRows.filter(r => r.file_path && r.file_path.toLowerCase().includes(q)));
}

async function openModal(id) {
  const d = await fetchJSON('/api/detections/' + id);
  if (!d) return;
  document.getElementById('modal-title').textContent = 'Detection #' + d.id;
  const fname = d.file_path ? d.file_path.replace(/\\\\/g, '/').split('/').pop() : '—';
  document.getElementById('modal-kv').innerHTML = `
    <span class="k">File</span><span class="v" title="${d.file_path}">${fname}</span>
    <span class="k">Full path</span><span class="v">${d.file_path ?? '—'}</span>
    <span class="k">Verdict</span><span class="v">${verdictBadge(d.verdict)}</span>
    <span class="k">Score</span><span class="v">${scoreBar(d.score ?? 0)}</span>
    <span class="k">SHA-256</span><span class="v" style="font-family:monospace;font-size:11px">${d.sha256 ?? '—'}</span>
    <span class="k">MD5</span><span class="v" style="font-family:monospace;font-size:11px">${d.md5 ?? '—'}</span>
    <span class="k">Detected</span><span class="v">${fmtDate(d.detected_at)}</span>
    <span class="k">Scan run</span><span class="v">#${d.scan_run_id}</span>
  `;
  document.getElementById('modal-reasoning').textContent =
    JSON.stringify(d.reasoning, null, 2);
  document.getElementById('modal').classList.add('open');
}

function closeModal(e) {
  if (!e || e.target === document.getElementById('modal') || e.target.classList.contains('close-btn')) {
    document.getElementById('modal').classList.remove('open');
  }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

async function refresh() {
  await Promise.all([loadStats(), loadScans(), loadDetections()]);
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    return HTMLResponse(_HTML)
