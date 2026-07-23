from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from aegis_bounty.models import Asset, Confidence, Observation, Severity
from aegis_bounty.scope import ScopePolicy, ScopeViolation, normalize_hostname


class ReconEngine:
    def __init__(self, scope: ScopePolicy, workspace: Path):
        self.scope = scope
        self.workspace = workspace

    async def discover(self, seeds: list[str], enabled: bool) -> tuple[list[Asset], list[str]]:
        seed_hosts = {
            normalize_hostname(urlsplit(self.scope.require_url(seed)).hostname or "")
            for seed in seeds
        }
        candidates: dict[str, str] = {host: "seed" for host in seed_hosts}
        messages: list[str] = []
        if enabled:
            roots = sorted({rule.removeprefix("*.") for rule in self.scope.config.include_domains})
            for root in roots:
                for tool, args in (
                    ("subfinder", ["-d", root, "-all", "-silent"]),
                    ("amass", ["enum", "-passive", "-d", root]),
                ):
                    found, message = await self._run_lines(tool, args)
                    if message:
                        messages.append(message)
                    for value in found:
                        try:
                            host = normalize_hostname(value)
                        except ScopeViolation:
                            continue
                        if self.scope.hostname_allowed(host).allowed:
                            candidates.setdefault(host, tool)
        assets: list[Asset] = []
        for host, source in sorted(candidates.items()):
            try:
                addresses = await self.scope.resolve_public(host)
                assets.append(Asset(hostname=host, source=source, addresses=addresses))
            except ScopeViolation as exc:
                messages.append(str(exc))
        return assets, messages

    async def _run_lines(self, executable: str, args: list[str]) -> tuple[list[str], str | None]:
        path = shutil.which(executable)
        if not path:
            return [], f"optional discovery tool not installed: {executable}"
        process = await asyncio.create_subprocess_exec(
            path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.workspace,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            detail = stderr.decode(errors="replace")[-1_000:]
            return [], f"{executable} failed ({process.returncode}): {detail}"
        return stdout.decode(errors="replace").splitlines(), None


class NucleiAdapter:
    def __init__(self, scope: ScopePolicy, workspace: Path, rate_limit: float):
        self.scope = scope
        self.workspace = workspace
        self.rate_limit = max(1, int(rate_limit))

    async def scan(
        self, urls: list[str], severities: list[str]
    ) -> tuple[list[Observation], list[str]]:
        path = shutil.which("nuclei")
        if not path:
            return [], ["Nuclei was enabled but its executable is not installed"]
        scoped = sorted({self.scope.require_url(url) for url in urls})
        if not scoped:
            return [], []
        targets = self.workspace / "nuclei-targets.txt"
        targets.write_text("\n".join(scoped) + "\n", encoding="utf-8")
        process = await asyncio.create_subprocess_exec(
            path,
            "-l",
            str(targets),
            "-jsonl",
            "-rl",
            str(self.rate_limit),
            "-severity",
            ",".join(severities),
            "-disable-update-check",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.workspace,
        )
        stdout, stderr = await process.communicate()
        errors: list[str] = []
        if process.returncode != 0:
            errors.append(
                f"Nuclei failed ({process.returncode}): {stderr.decode(errors='replace')[-1_000:]}"
            )
        observations: list[Observation] = []
        for line in stdout.decode(errors="replace").splitlines():
            try:
                item = json.loads(line)
                matched = str(item.get("matched-at") or item.get("host") or "")
                if not self.scope.url_allowed(matched).allowed:
                    continue
                info = item.get("info") or {}
                severity_value = str(info.get("severity", "info")).lower()
                severity = (
                    Severity(severity_value)
                    if severity_value in Severity._value2member_map_
                    else Severity.INFO
                )
                observations.append(
                    Observation(
                        kind="nuclei_template_match",
                        title=str(info.get("name") or item.get("template-id") or "Nuclei match"),
                        url=matched,
                        severity=severity,
                        confidence=Confidence.MODERATE,
                        evidence=f"Template {item.get('template-id', 'unknown')} matched. Validate manually before reporting.",
                        remediation=str(
                            info.get("remediation")
                            or "Review vendor guidance and validate the affected component."
                        ),
                        source="nuclei",
                        metadata={
                            "template_id": item.get("template-id"),
                            "matcher": item.get("matcher-name"),
                        },
                    )
                )
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        return observations, errors
