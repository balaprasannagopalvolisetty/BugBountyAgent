from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from aegis_bounty import __version__
from aegis_bounty.config import load_config
from aegis_bounty.orchestrator import ScanOrchestrator
from aegis_bounty.reporting import write_reports
from aegis_bounty.storage import EvidenceStore
from aegis_bounty.tool_catalog import TOOL_CATALOG, executable_tools

app = typer.Typer(
    name="aegis",
    help="Scope-locked assistant for authorized web security assessment.",
    no_args_is_help=True,
)
console = Console()


def _load(path: Path):  # type: ignore[no-untyped-def]
    try:
        return load_config(path)
    except (ValueError, ValidationError) as exc:
        console.print(f"[bold red]Configuration refused:[/bold red] {exc}")
        raise typer.Exit(2) from exc


@app.command()
def validate(
    config: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
) -> None:
    """Validate authorization, scope, and safety limits without network access."""
    parsed = _load(config)
    dry_run = ScanOrchestrator(parsed, config.parent).dry_run()
    console.print("[bold green]Configuration and authorization are valid.[/bold green]")
    console.print_json(json.dumps(dry_run))


@app.command()
def doctor() -> None:
    """Show runtime and optional integration readiness."""
    table = Table(title=f"Aegis {__version__} readiness")
    table.add_column("Capability")
    table.add_column("Status")
    table.add_column("Details")
    for executable in ("amass", "nuclei"):
        path = shutil.which(executable)
        table.add_row(executable, "ready" if path else "optional", path or "not installed")
    for tool in executable_tools():
        path = tool.installed_path()
        table.add_row(
            tool.name,
            "ready" if path else tool.integration.value,
            path or "not installed",
        )
    key = bool(os.environ.get("OPENAI_API_KEY"))
    table.add_row(
        "OpenAI",
        "ready" if key else "optional",
        "OPENAI_API_KEY set" if key else "AI triage disabled without key",
    )
    console.print(table)


@app.command("tools")
def tools_command(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the catalog as machine-readable JSON.")
    ] = False,
) -> None:
    """List requested security tools, integration status, and safety posture."""
    if as_json:
        console.print_json(json.dumps([tool.as_json() for tool in TOOL_CATALOG]))
        return
    table = Table(title="Aegis external tool catalog")
    table.add_column("Tool")
    table.add_column("Kind")
    table.add_column("Integration")
    table.add_column("Installed")
    table.add_column("Purpose")
    for tool in TOOL_CATALOG:
        installed = tool.installed_path()
        table.add_row(
            tool.name,
            tool.kind.value,
            tool.integration.value,
            installed or ("n/a" if tool.executable is None else "no"),
            tool.purpose,
        )
    console.print(table)
    console.print(
        "[yellow]External and not-auto-run tools are never launched by `aegis scan`. "
        "Their own traffic and workflow settings remain the operator's responsibility.[/yellow]"
    )


@app.command()
def scan(
    config: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Validate and print the plan only.")
    ] = False,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Disable AI triage for this run.")] = False,
) -> None:
    """Run an authorized, budgeted assessment."""
    parsed = _load(config)
    orchestrator = ScanOrchestrator(parsed, config.parent)
    if dry_run:
        console.print_json(json.dumps(orchestrator.dry_run()))
        return
    console.print(
        f"[bold cyan]Starting authorized assessment[/bold cyan] for {parsed.project} "
        f"(budget: {parsed.scan.max_requests} requests, {parsed.scan.requests_per_second:g} req/s/host)"
    )
    try:
        summary = asyncio.run(orchestrator.run(disable_ai=no_ai))
    except KeyboardInterrupt as exc:
        console.print("[yellow]Stopped by operator.[/yellow]")
        raise typer.Exit(130) from exc
    console.print(f"[bold green]Completed scan {summary.scan_id}[/bold green]")
    console.print(
        f"Assets {summary.assets} | Endpoints {summary.endpoints} | Requests {summary.requests} | "
        f"Observations {summary.observations} | Chain hypotheses {summary.chains}"
    )
    for path in summary.report_paths:
        console.print(f"  {path}")


@app.command("report")
def report_command(
    database: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Regenerate reports from an evidence database."""
    with EvidenceStore(database) as store:
        scan_id = store.latest_scan_id()
        paths = write_reports(
            store,
            scan_id,
            output or database.parent,
            ["json", "markdown", "html"],
        )
    for path in paths:
        console.print(path.resolve())


if __name__ == "__main__":
    app()
