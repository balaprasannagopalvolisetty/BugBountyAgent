from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import cast

from aegis_bounty.models import SEVERITY_ORDER, ChainHypothesis, Observation
from aegis_bounty.storage import EvidenceStore


def _sorted_observations(items: list[Observation]) -> list[Observation]:
    return sorted(items, key=lambda item: (-SEVERITY_ORDER[item.severity], item.url, item.title))


def render_markdown(data: dict[str, object]) -> str:
    scan = cast(dict[str, object], data["scan"])
    observations_raw = cast(list[object], data["observations"])
    chains_raw = cast(list[object], data["chains"])
    assets = cast(list[object], data["assets"])
    exchanges = cast(list[object], data["exchanges"])
    observations = [Observation.model_validate(item) for item in observations_raw]
    chains = [ChainHypothesis.model_validate(item) for item in chains_raw]
    counts = Counter(item.severity.value for item in observations)
    lines = [
        f"# Aegis assessment report: {scan['project']}",
        "",
        f"- Scan ID: `{data['scan_id']}`",
        f"- Started: {scan['started_at']}",
        f"- Finished: {scan['finished_at'] or 'incomplete'}",
        f"- Assets: {len(assets)}",
        f"- Captured exchanges: {len(exchanges)}",
        f"- Observations: {len(observations)}",
        "",
        "> Observations and chain hypotheses require human validation. Scanner or AI output alone is not proof of exploitability.",
        "",
        "## Severity summary",
        "",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity.title()}: {counts[severity]}")
    lines.extend(["", "## Observations", ""])
    for item in _sorted_observations(observations):
        lines.extend(
            [
                f"### [{item.severity.value.upper()}] {item.title}",
                "",
                f"- URL: `{item.url}`",
                f"- Detection confidence: {item.confidence.value}",
                f"- Exploitability: {item.exploitability.value}",
                f"- Source: {item.source}",
                f"- Evidence ID: `{item.fingerprint}`",
                "",
                item.evidence,
                "",
                f"Remediation: {item.remediation}",
                "",
            ]
        )
    lines.extend(["## Chain hypotheses", ""])
    if not chains:
        lines.extend(["No compatible evidence chains were identified.", ""])
    for chain in chains:
        lines.extend(
            [
                f"### {chain.title}",
                "",
                f"Confidence: {chain.confidence.value}",
                "",
                chain.rationale,
                "",
                f"Potential impact: {chain.potential_impact}",
                "",
                "Validation steps:",
                "",
            ]
        )
        lines.extend(f"1. {step}" for step in chain.validation_steps)
        lines.extend(
            ["", "Evidence: " + ", ".join(f"`{item}`" for item in chain.observation_ids), ""]
        )
    return "\n".join(lines)


def render_html(markdown_text: str, project: str) -> str:
    # A dependency-free readable HTML view; Markdown remains the canonical narrative report.
    escaped = html.escape(markdown_text)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis report — {html.escape(project)}</title>
<style>body{{font:16px/1.55 system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#0b1220;color:#dbeafe}}pre{{white-space:pre-wrap;background:#111c31;padding:1.5rem;border-radius:12px;border:1px solid #243554}}a{{color:#7dd3fc}}</style>
</head><body><pre>{escaped}</pre></body></html>"""


def write_reports(
    store: EvidenceStore, scan_id: str, directory: Path, formats: list[str]
) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    data = store.export(scan_id)
    project = str(data["scan"]["project"])  # type: ignore[index]
    markdown = render_markdown(data)
    paths: list[Path] = []
    if "json" in formats:
        path = directory / "report.json"
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        paths.append(path)
    if "markdown" in formats:
        path = directory / "report.md"
        path.write_text(markdown, encoding="utf-8")
        paths.append(path)
    if "html" in formats:
        path = directory / "report.html"
        path.write_text(render_html(markdown, project), encoding="utf-8")
        paths.append(path)
    return paths
