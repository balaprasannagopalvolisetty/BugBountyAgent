from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from aegis_bounty import __version__
from aegis_bounty.authorization import (
    AuthorizationProfile,
    load_authorization,
    save_authorization,
)
from aegis_bounty.config import AppConfig, AuthorizationConfig, TargetConfig, load_config
from aegis_bounty.orchestrator import ScanOrchestrator
from aegis_bounty.reporting import write_reports
from aegis_bounty.scope import ScopeViolation, normalize_url
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


def _prompt_and_save_authorization(hostname: str) -> AuthorizationProfile:
    console.print(
        f"[bold]One-time authorization setup for exact host {hostname}[/bold]\n"
        "Aegis cannot independently verify permission; enter the real program or written authorization."
    )
    reference = typer.prompt("Program URL or written authorization reference")
    authorized_by = typer.prompt("Authorizing program or organization")
    expires_at = typer.prompt("Authorization expiration (ISO 8601, e.g. 2026-12-31T23:59:59Z)")
    confirmed = typer.confirm(
        f"I confirm I am authorized to assess {hostname} under that reference",
        default=False,
    )
    try:
        authorization = AuthorizationConfig.model_validate(
            {
                "confirmed": confirmed,
                "reference": reference,
                "authorized_by": authorized_by,
                "expires_at": expires_at,
            }
        )
    except ValidationError as exc:
        console.print(f"[bold red]Authorization refused:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    profile = AuthorizationProfile(hostname=hostname, authorization=authorization)
    path = save_authorization(profile)
    console.print(f"[green]Saved exact-host authorization profile:[/green] {path}")
    return profile


def _save_supplied_authorization(
    hostname: str,
    reference: str | None,
    authorized_by: str | None,
    expires_at: str | None,
    confirmed: bool,
) -> AuthorizationProfile | None:
    supplied = (reference, authorized_by, expires_at)
    if not any(value is not None for value in supplied) and not confirmed:
        return None
    if not all(value is not None for value in supplied) or not confirmed:
        console.print(
            "[bold red]Authorization refused:[/bold red] Non-interactive setup requires "
            "--authorization-reference, --authorized-by, --authorization-expires-at, and "
            "--confirm-authorization together."
        )
        raise typer.Exit(2)
    try:
        authorization = AuthorizationConfig.model_validate(
            {
                "confirmed": True,
                "reference": reference,
                "authorized_by": authorized_by,
                "expires_at": expires_at,
            }
        )
    except ValidationError as exc:
        console.print(f"[bold red]Authorization refused:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    profile = AuthorizationProfile(hostname=hostname, authorization=authorization)
    path = save_authorization(profile)
    console.print(f"[green]Saved exact-host authorization profile:[/green] {path}")
    return profile


def _authorization_for(
    hostname: str,
    reauthorize: bool = False,
    *,
    reference: str | None = None,
    authorized_by: str | None = None,
    expires_at: str | None = None,
    confirmed: bool = False,
) -> AuthorizationProfile:
    supplied = _save_supplied_authorization(
        hostname, reference, authorized_by, expires_at, confirmed
    )
    if supplied is not None:
        return supplied
    if not reauthorize:
        try:
            profile = load_authorization(hostname)
        except (ValueError, ValidationError) as exc:
            console.print(f"[yellow]Stored authorization cannot be used: {exc}[/yellow]")
        else:
            if profile is not None:
                return profile
    return _prompt_and_save_authorization(hostname)


def _run_orchestrator(orchestrator: ScanOrchestrator, parsed: AppConfig, no_ai: bool) -> None:
    console.print(
        f"[bold cyan]Starting authorized assessment[/bold cyan] for {parsed.project} "
        f"(budget: {parsed.scan.max_requests} requests, "
        f"{parsed.scan.requests_per_second:g} req/s/host)"
    )
    try:
        summary = asyncio.run(orchestrator.run(disable_ai=no_ai))
    except ModuleNotFoundError as exc:
        if exc.name and (exc.name == "dns" or exc.name.startswith("cryptography")):
            console.print(
                f"[bold red]Missing runtime dependency:[/bold red] {exc.name}\n"
                "Activate the project virtual environment and refresh it with:\n"
                "  [cyan]python -m pip install -e '.[dev]'[/cyan]"
            )
            raise typer.Exit(2) from exc
        raise
    except KeyboardInterrupt as exc:
        console.print("[yellow]Stopped by operator.[/yellow]")
        raise typer.Exit(130) from exc
    console.print(f"[bold green]Completed scan {summary.scan_id}[/bold green]")
    console.print(
        f"Assets {summary.assets} | Endpoints {summary.endpoints} | Requests {summary.requests} | "
        f"Network hosts {summary.network_hosts} | Observations {summary.observations} | "
        f"Chain hypotheses {summary.chains} | Coverage {summary.coverage_score}%"
    )
    for path in summary.report_paths:
        console.print(f"  {path}")


@app.command("init-target")
def init_target(
    target: Annotated[str, typer.Argument(help="One authorized HTTP(S) target URL.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Configuration file to create.")
    ] = Path("scope.yaml"),
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing output file.")
    ] = False,
) -> None:
    """Create a locked exact-host configuration from one target URL."""
    try:
        normalized = normalize_url(target)
    except (ScopeViolation, ValueError) as exc:
        console.print(f"[bold red]Invalid target URL:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    hostname = urlsplit(normalized).hostname
    if not hostname:  # normalize_url already enforces this; retained for type narrowing.
        raise typer.Exit(2)
    if output.exists() and not force:
        console.print(
            f"[bold red]Refusing to overwrite {output}.[/bold red] Use --force intentionally."
        )
        raise typer.Exit(2)
    target_port = urlsplit(normalized).port
    allowed_ports = [80, 443]
    if target_port is not None and target_port not in allowed_ports:
        allowed_ports.append(target_port)
        allowed_ports.sort()
    expires = (datetime.now(UTC) + timedelta(days=30)).replace(microsecond=0)
    starter = {
        "project": hostname,
        "target": {
            "seeds": [normalized],
            # include_domains is deliberately omitted; TargetConfig derives this exact host.
            "exclude_domains": [],
            "exclude_paths": ["/logout", "/delete-account"],
            "allowed_ports": allowed_ports,
            "allow_private_networks": False,
        },
        "authorization": {
            "confirmed": False,
            "reference": "REPLACE-WITH-PROGRAM-URL-OR-WRITTEN-AUTHORIZATION-ID",
            "authorized_by": "REPLACE-ME",
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        },
        "scan": {
            "max_requests": 250,
            "max_pages_per_host": 40,
            "max_depth": 3,
            "concurrency": 4,
            "requests_per_second": 1.5,
            "timeout_seconds": 12,
            "user_agent": "AegisBountyAI/0.5 authorized-security-research",
            "active_validation": False,
            "discover_subdomains": False,
            "use_nuclei": False,
            "nuclei_severities": ["info", "low", "medium", "high", "critical"],
        },
        "ai": {
            "enabled": False,
            "provider": "openai",
            "triage_model": "gpt-5.6-terra",
            "reasoning_model": "gpt-5.6-sol",
            "max_observations": 25,
            "redact_secrets": True,
        },
        "output": {"directory": "runs", "formats": ["json", "markdown", "html"]},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(starter, sort_keys=False), encoding="utf-8")
    console.print(f"[bold green]Created exact-host configuration:[/bold green] {output}")
    console.print(f"Target: {normalized}\nDerived scope: {hostname} (no wildcard subdomains)")
    console.print(
        f"Complete the authorization section, then run: [cyan]aegis validate {output}[/cyan]"
    )


@app.command("authorize")
def authorize_target(
    target: Annotated[str, typer.Argument(help="Exact HTTP(S) target URL to authorize.")],
) -> None:
    """Create or replace a stored exact-host authorization profile."""
    try:
        normalized = normalize_url(target)
    except (ScopeViolation, ValueError) as exc:
        console.print(f"[bold red]Invalid target URL:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    hostname = urlsplit(normalized).hostname
    if not hostname:
        raise typer.Exit(2)
    _prompt_and_save_authorization(hostname)


@app.command("scan-url")
def scan_url(
    target: Annotated[str, typer.Argument(help="One authorized HTTP(S) target URL.")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the derived plan without network access.")
    ] = False,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Disable AI triage.")] = False,
    reauthorize: Annotated[
        bool,
        typer.Option("--reauthorize", help="Replace the stored authorization for this host."),
    ] = False,
    authorization_reference: Annotated[
        str | None,
        typer.Option(
            "--authorization-reference",
            help="Program URL or written authorization reference for non-interactive setup.",
        ),
    ] = None,
    authorized_by: Annotated[
        str | None,
        typer.Option(
            "--authorized-by",
            help="Authorizing program or organization for non-interactive setup.",
        ),
    ] = None,
    authorization_expires_at: Annotated[
        str | None,
        typer.Option(
            "--authorization-expires-at",
            help="ISO 8601 authorization expiration for non-interactive setup.",
        ),
    ] = None,
    confirm_authorization: Annotated[
        bool,
        typer.Option(
            "--confirm-authorization",
            help="Confirm explicit authorization when supplying metadata non-interactively.",
        ),
    ] = False,
) -> None:
    """Scan one URL directly, prompting for authorization only on first use."""
    try:
        normalized = normalize_url(target)
    except (ScopeViolation, ValueError) as exc:
        console.print(f"[bold red]Invalid target URL:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    hostname = urlsplit(normalized).hostname
    if not hostname:
        raise typer.Exit(2)
    profile = _authorization_for(
        hostname,
        reauthorize,
        reference=authorization_reference,
        authorized_by=authorized_by,
        expires_at=authorization_expires_at,
        confirmed=confirm_authorization,
    )
    parsed = AppConfig(
        project=hostname,
        target=TargetConfig(seeds=[normalized]),
        authorization=profile.authorization,
    )
    orchestrator = ScanOrchestrator(parsed, Path.cwd())
    if dry_run:
        console.print_json(json.dumps(orchestrator.dry_run()))
        return
    _run_orchestrator(orchestrator, parsed, no_ai)


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
    for module, package in (("dns", "dnspython"), ("cryptography", "cryptography")):
        available = importlib.util.find_spec(module) is not None
        table.add_row(
            package,
            "ready" if available else "missing",
            "Python runtime dependency" if available else "run: python -m pip install -e '.[dev]'",
        )
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
    _run_orchestrator(orchestrator, parsed, no_ai)


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
