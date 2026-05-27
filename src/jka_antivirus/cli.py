"""jka_antivirus CLI: typer-based entry point."""

from __future__ import annotations

import asyncio
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
