"""jka_antivirus CLI: typer-based entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from jka_antivirus.config import load_settings
from jka_antivirus.db.connection import get_table_counts, init_db
from jka_antivirus.logging_setup import setup_logging

app = typer.Typer(
    name="jka",
    help="jka_antivirus: layered Windows antivirus engine.",
    add_completion=True,
)
quarantine_app = typer.Typer(help="Quarantine vault management (Phase 2+).")
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
) -> None:
    """Scan a file or directory for threats."""
    console.print(
        "[yellow]Static scan engine arrives in Phase 2.[/yellow]"
        f" (target: {path})"
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
# jka quarantine list
# ---------------------------------------------------------------------------
@quarantine_app.command(name="list")
def quarantine_list() -> None:
    """List quarantined files."""
    console.print("[yellow]Quarantine engine arrives in Phase 2.[/yellow]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    app()


if __name__ == "__main__":
    main()
