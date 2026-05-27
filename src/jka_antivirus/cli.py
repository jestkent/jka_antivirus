"""jka_antivirus CLI: typer-based entry point."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from jka_antivirus.config import load_settings
from jka_antivirus.db.connection import get_table_counts, init_db
from jka_antivirus.logging_setup import setup_logging

app = typer.Typer(
    name="jka",
    help="jka_antivirus: layered Windows antivirus engine.",
    add_completion=True,
)
quarantine_app = typer.Typer(help="Quarantine vault management (Phase 3+).")
app.add_typer(quarantine_app, name="quarantine")

console = Console()
logger = logging.getLogger(__name__)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to config.yaml."),
]


# ---------------------------------------------------------------------------
# jka scan
# ---------------------------------------------------------------------------
@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="File or directory path to scan.")],
    config: ConfigOption = None,
    blocklist: Annotated[
        Path | None,
        typer.Option("--blocklist", "-b", help="Extra SHA256 blocklist JSON file."),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", "-r", help="Directory of YARA .yar rule files."),
    ] = None,
) -> None:
    """Scan a file or directory for threats using hash, PE, and YARA engines."""
    from jka_antivirus.scanner import ScanProgressCallback, run_scan  # noqa: PLC0415

    if not path.exists():
        console.print(f"[red]Path does not exist:[/red] {path}")
        raise typer.Exit(1)

    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")

    db_path = settings.database.path
    if not db_path.exists():
        console.print("[yellow]Database not found. Running init-db first...[/yellow]")
        asyncio.run(init_db(db_path))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_progress(current: int, total: int, current_path: Path) -> None:
            progress.update(
                task,
                total=total,
                completed=current,
                description=f"[cyan]{current_path.name}[/cyan]",
            )

        callback: ScanProgressCallback = on_progress
        summary = asyncio.run(
            run_scan(
                target=path,
                db_path=db_path,
                blocklist_path=blocklist,
                rules_dir=rules,
                on_progress=callback,
                workers=settings.scan.workers,
            )
        )

    color = "red" if summary.threats_found > 0 else "green"
    console.print(
        f"\n[bold]Scan complete.[/bold] "
        f"Files scanned: [cyan]{summary.files_scanned}[/cyan]  "
        f"Threats found: [{color}]{summary.threats_found}[/{color}]"
    )
    if summary.threats_found > 0:
        console.print(
            f"[dim]Run [bold]jka status[/bold] or query the database "
            f"(scan_run_id={summary.run_id}) for details.[/dim]"
        )


# ---------------------------------------------------------------------------
# jka status
# ---------------------------------------------------------------------------
@app.command()
def status(config: ConfigOption = None) -> None:
    """Show database statistics: scan runs, detections, quarantine items."""
    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")

    counts = asyncio.run(get_table_counts(settings.database.path))

    table = Table(title="jka_antivirus Status", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Scan runs", str(counts.get("scan_runs", 0)))
    table.add_row("Detections", str(counts.get("detections", 0)))
    table.add_row("Quarantine items", str(counts.get("quarantine_items", 0)))
    table.add_row("Event log entries", str(counts.get("event_log", 0)))

    console.print(table)
    console.print(f"[dim]Database: {settings.database.path}[/dim]")


# ---------------------------------------------------------------------------
# jka init-db
# ---------------------------------------------------------------------------
@app.command(name="init-db")
def init_db_cmd(config: ConfigOption = None) -> None:
    """Create the SQLite database and apply the schema (idempotent)."""
    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")

    db_path = settings.database.path
    console.print(f"Initialising database at [bold]{db_path}[/bold] ...")
    asyncio.run(init_db(db_path))
    console.print("[green]Database ready.[/green] All tables and indexes created.")


# ---------------------------------------------------------------------------
# jka scan-threats  (targeted high-risk location scan)
# ---------------------------------------------------------------------------

# Directories where trojans, RATs, worms, and ransomware typically hide
# on Windows — writable by users, often ignored by quick Defender scans.
_THREAT_PATHS = [
    Path(r"C:\Users") / "{user}" / "AppData" / "Roaming",
    Path(r"C:\Users") / "{user}" / "AppData" / "Local" / "Temp",
    Path(r"C:\Users") / "{user}" / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache",
    Path(r"C:\Users") / "{user}" / "AppData" / "Roaming"
    / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    Path(r"C:\Windows") / "Temp",
    Path(r"C:\Windows") / "System32" / "Tasks",
    Path(r"C:\Windows") / "System32" / "drivers",
    Path(r"C:\ProgramData"),
    Path(r"C:\Users") / "Public",
    Path(r"C:\Temp"),
]


def _resolve_threat_paths() -> list[Path]:
    import os  # noqa: PLC0415
    user = os.environ.get("USERNAME", os.environ.get("USER", ""))
    resolved: list[Path] = []
    for p in _THREAT_PATHS:
        final = Path(str(p).replace("{user}", user))
        if final.exists():
            resolved.append(final)
    return resolved


@app.command(name="scan-threats")
def scan_threats(
    config: ConfigOption = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", "-r", help="Directory of YARA .yar rule files."),
    ] = None,
    blocklist: Annotated[
        Path | None,
        typer.Option("--blocklist", "-b", help="Extra SHA256 blocklist JSON file."),
    ] = None,
) -> None:
    """Scan high-risk Windows locations where trojans, RATs, and worms typically hide."""
    from jka_antivirus.scanner import ScanProgressCallback, run_scan  # noqa: PLC0415

    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")

    db_path = settings.database.path
    if not db_path.exists():
        asyncio.run(init_db(db_path))

    targets = _resolve_threat_paths()
    if not targets:
        console.print("[red]No threat paths found on this system.[/red]")
        raise typer.Exit(1)

    # Default to bundled rules dir when --rules not supplied
    rules_dir = rules
    if rules_dir is None:
        here = Path(__file__).parent
        for _ in range(6):
            candidate = here.parent / "rules"
            if candidate.exists():
                rules_dir = candidate
                break
            here = here.parent

    console.print("[bold]Scanning high-risk locations...[/bold]")
    for p in targets:
        console.print(f"  [dim]{p}[/dim]")
    console.print()

    total_threats = 0
    total_files = 0

    for target in targets:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"[cyan]{target.name}[/cyan]", total=None)

            from rich.progress import TaskID  # noqa: PLC0415

            def _make_cb(tid: TaskID) -> ScanProgressCallback:
                def _cb(current: int, total: int, current_path: Path) -> None:
                    desc = f"[cyan]{current_path.name}[/cyan]"
                    progress.update(tid, total=total, completed=current, description=desc)
                return _cb

            callback: ScanProgressCallback = _make_cb(task_id)
            summary = asyncio.run(
                run_scan(
                    target=target,
                    db_path=db_path,
                    blocklist_path=blocklist,
                    rules_dir=rules_dir,
                    on_progress=callback,
                    workers=settings.scan.workers,
                )
            )

        color = "red" if summary.threats_found > 0 else "green"
        console.print(
            f"  {target.name}: files=[cyan]{summary.files_scanned}[/cyan]  "
            f"threats=[{color}]{summary.threats_found}[/{color}]"
        )
        total_threats += summary.threats_found
        total_files += summary.files_scanned

    console.print()
    color = "red" if total_threats > 0 else "green"
    console.print(
        f"[bold]Done.[/bold] Total files: [cyan]{total_files}[/cyan]  "
        f"Total threats: [{color}]{total_threats}[/{color}]"
    )
    if total_threats > 0:
        console.print("[dim]Open the dashboard to review detections: jka dashboard[/dim]")


# ---------------------------------------------------------------------------
# jka watch
# ---------------------------------------------------------------------------
@app.command()
def watch(
    path: Annotated[Path, typer.Argument(help="Directory to monitor for new/changed files.")],
    config: ConfigOption = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", "-r", help="Directory of YARA .yar rule files."),
    ] = None,
    blocklist: Annotated[
        Path | None,
        typer.Option("--blocklist", "-b", help="Extra SHA256 blocklist JSON file."),
    ] = None,
) -> None:
    """Watch a directory and auto-scan every new or modified file in real time."""
    import queue  # noqa: PLC0415
    import threading  # noqa: PLC0415

    from watchdog.events import FileSystemEvent, FileSystemEventHandler  # noqa: PLC0415
    from watchdog.observers import Observer  # noqa: PLC0415

    from jka_antivirus.scanner import _SKIP_EXTENSIONS, run_scan  # noqa: PLC0415

    if not path.exists() or not path.is_dir():
        console.print(f"[red]Path must be an existing directory:[/red] {path}")
        raise typer.Exit(1)

    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")

    db_path = settings.database.path
    if not db_path.exists():
        asyncio.run(init_db(db_path))

    pending: queue.Queue[Path] = queue.Queue()

    class _Handler(FileSystemEventHandler):
        def _enqueue(self, event: FileSystemEvent) -> None:
            p = Path(str(event.src_path))
            if p.is_file() and p.suffix.lower() not in _SKIP_EXTENSIONS:
                pending.put(p)

        def on_created(self, event: FileSystemEvent) -> None:
            self._enqueue(event)

        def on_modified(self, event: FileSystemEvent) -> None:
            self._enqueue(event)

    observer = Observer()
    observer.schedule(_Handler(), str(path), recursive=True)
    observer.start()

    console.print(
        f"[bold green]Watching[/bold green] [cyan]{path}[/cyan]  "
        f"(Ctrl+C to stop)"
    )

    stop_event = threading.Event()

    def _scan_loop() -> None:
        while not stop_event.is_set():
            try:
                file_path = pending.get(timeout=1)
            except queue.Empty:
                continue
            console.print(f"  [yellow]scan[/yellow] {file_path.name}")
            try:
                summary = asyncio.run(
                    run_scan(
                        target=file_path,
                        db_path=db_path,
                        blocklist_path=blocklist,
                        rules_dir=rules,
                        workers=settings.scan.workers,
                    )
                )
                color = "red" if summary.threats_found else "green"
                verdict_label = "THREAT" if summary.threats_found else "clean"
                console.print(
                    f"  [{color}]{verdict_label}[/{color}] {file_path.name}"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Watch scan failed for %s: %s", file_path, exc)

    scan_thread = threading.Thread(target=_scan_loop, daemon=True)
    scan_thread.start()

    try:
        while observer.is_alive():
            observer.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        observer.stop()
        observer.join()
        console.print("\n[dim]Watch stopped.[/dim]")


# ---------------------------------------------------------------------------
# jka dashboard
# ---------------------------------------------------------------------------
@app.command()
def dashboard(
    config: ConfigOption = None,
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on.")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind.")] = "127.0.0.1",
) -> None:
    """Start the browser dashboard (opens at http://localhost:<port>)."""
    import webbrowser  # noqa: PLC0415

    import uvicorn  # noqa: PLC0415

    from jka_antivirus.dashboard import app as dash_app  # noqa: PLC0415
    from jka_antivirus.dashboard import configure

    settings = load_settings(config)
    setup_logging(settings.app.log_level, log_dir=settings.app.data_dir / "logs")
    configure(settings.database.path)

    url = f"http://{host}:{port}"
    console.print(f"[bold]jka_antivirus Dashboard[/bold] running at [cyan]{url}[/cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    webbrowser.open(url)
    uvicorn.run(dash_app, host=host, port=port, log_level="warning")


# ---------------------------------------------------------------------------
# jka quarantine list
# ---------------------------------------------------------------------------
@quarantine_app.command(name="list")
def quarantine_list() -> None:
    """List quarantined files."""
    console.print("[yellow]Quarantine engine arrives in Phase 3.[/yellow]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    app()


if __name__ == "__main__":
    main()
