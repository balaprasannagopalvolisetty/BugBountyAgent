from __future__ import annotations

import os
import shutil

from aegis_bounty.config import AppConfig
from aegis_bounty.models import (
    CoverageGap,
    CoverageStatus,
    Endpoint,
    GapAnalysis,
    NetworkProfile,
    Observation,
    Severity,
    ToolCoverage,
)
from aegis_bounty.tool_catalog import TOOL_CATALOG, Integration


def build_gap_analysis(
    config: AppConfig,
    *,
    endpoints: list[Endpoint],
    request_count: int,
    network_profiles: list[NetworkProfile],
    observations: list[Observation],
    errors: list[str],
    ai_disabled: bool,
) -> GapAnalysis:
    gaps: list[CoverageGap] = []

    mapped_addresses = sum(bool(profile.addresses) for profile in network_profiles)
    gaps.append(
        CoverageGap(
            area="DNS and address mapping",
            status=(
                CoverageStatus.COVERED
                if network_profiles and mapped_addresses == len(network_profiles)
                else CoverageStatus.PARTIAL
            ),
            evidence=f"Mapped {mapped_addresses} of {len(network_profiles)} discovered hosts to addresses.",
            recommendation="Review unresolved hosts and compare passive DNS history when program rules permit.",
        )
    )

    tls_hosts = sum(bool(profile.tls) for profile in network_profiles)
    gaps.append(
        CoverageGap(
            area="TLS transport and certificate posture",
            status=CoverageStatus.COVERED if tls_hosts else CoverageStatus.NOT_RUN,
            priority=Severity.MEDIUM if not tls_hosts else Severity.INFO,
            evidence=f"Captured TLS metadata for {tls_hosts} host(s).",
            recommendation="Map certificate trust, lifetime, protocol, cipher, SANs, and key strength on every authorized HTTPS host.",
        )
    )

    budget_exhausted = request_count >= config.scan.max_requests
    crawl_status = CoverageStatus.PARTIAL if budget_exhausted or errors else CoverageStatus.COVERED
    gaps.append(
        CoverageGap(
            area="Unauthenticated HTTP application crawl",
            status=crawl_status,
            priority=Severity.MEDIUM if budget_exhausted else Severity.INFO,
            evidence=(
                f"Captured {request_count} exchanges and mapped {len(endpoints)} endpoints; "
                f"generated {len(observations)} observations; request budget "
                f"exhausted={budget_exhausted}, crawl errors={len(errors)}."
            ),
            recommendation="Resolve crawl errors or raise the authorized request budget when coverage was truncated.",
        )
    )

    script_endpoints = sum("script" in endpoint.tags for endpoint in endpoints)
    js_discoveries = sum("javascript-discovery" in endpoint.tags for endpoint in endpoints)
    gaps.append(
        CoverageGap(
            area="JavaScript and client-side endpoint discovery",
            status=CoverageStatus.COVERED if script_endpoints else CoverageStatus.PARTIAL,
            evidence=f"Observed {script_endpoints} script assets and {js_discoveries} endpoint candidates extracted from JavaScript.",
            recommendation="Add browser-rendered crawling for route state, dynamically loaded bundles, and authenticated client traffic.",
        )
    )

    subfinder_installed = shutil.which("subfinder") is not None
    amass_installed = shutil.which("amass") is not None
    if config.scan.discover_subdomains and (subfinder_installed or amass_installed):
        subdomain_status = CoverageStatus.COVERED
        subdomain_evidence = "Passive subdomain discovery was enabled with an available enumerator."
    elif config.scan.discover_subdomains:
        subdomain_status = CoverageStatus.UNAVAILABLE
        subdomain_evidence = (
            "Subdomain discovery was enabled, but Subfinder and Amass were unavailable."
        )
    else:
        subdomain_status = CoverageStatus.NOT_RUN
        subdomain_evidence = "Subdomain discovery was disabled; exact-host scope was retained."
    gaps.append(
        CoverageGap(
            area="Authorized subdomain discovery",
            status=subdomain_status,
            priority=Severity.MEDIUM,
            evidence=subdomain_evidence,
            recommendation="Enable passive discovery only when the authorization explicitly covers subdomains.",
        )
    )

    gaps.append(
        CoverageGap(
            area="Read-only active validation",
            status=(
                CoverageStatus.COVERED if config.scan.active_validation else CoverageStatus.NOT_RUN
            ),
            priority=Severity.MEDIUM,
            evidence=f"Active validation enabled={config.scan.active_validation}.",
            recommendation="Enable only low-impact checks allowed by the program, then manually validate material signals.",
        )
    )

    nuclei_installed = shutil.which("nuclei") is not None
    if config.scan.use_nuclei and nuclei_installed:
        template_status = CoverageStatus.COVERED
    elif config.scan.use_nuclei:
        template_status = CoverageStatus.UNAVAILABLE
    else:
        template_status = CoverageStatus.NOT_RUN
    gaps.append(
        CoverageGap(
            area="Known-vulnerability template coverage",
            status=template_status,
            priority=Severity.MEDIUM,
            evidence=f"Nuclei enabled={config.scan.use_nuclei}, installed={nuclei_installed}.",
            recommendation="Review templates for scope and impact before enabling Nuclei.",
        )
    )

    ai_available = bool(os.environ.get("OPENAI_API_KEY"))
    ai_used = config.ai.enabled and ai_available and not ai_disabled
    gaps.append(
        CoverageGap(
            area="Evidence-based AI triage",
            status=(
                CoverageStatus.COVERED
                if ai_used
                else CoverageStatus.UNAVAILABLE
                if config.ai.enabled and not ai_available
                else CoverageStatus.NOT_RUN
            ),
            priority=Severity.LOW,
            evidence=f"AI enabled={config.ai.enabled}, credential available={ai_available}, disabled for run={ai_disabled}.",
            recommendation="Use AI only as a prioritization aid; retain human evidence validation.",
        )
    )

    gaps.extend(
        [
            CoverageGap(
                area="Authenticated roles and authorization boundaries",
                status=CoverageStatus.NOT_RUN,
                priority=Severity.HIGH,
                evidence="No authenticated browser session, role matrix, or test-account workflow was supplied.",
                recommendation="Test with authorized accounts across distinct roles to assess IDOR, privilege boundaries, and session behavior.",
            ),
            CoverageGap(
                area="Business logic and state transitions",
                status=CoverageStatus.NOT_RUN,
                priority=Severity.HIGH,
                evidence="Aegis did not submit forms or mutate application state.",
                recommendation="Map critical workflows and manually test invariant violations using dedicated test data.",
            ),
            CoverageGap(
                area="Directory and content wordlist discovery",
                status=CoverageStatus.NOT_RUN,
                priority=Severity.MEDIUM,
                evidence=f"dirsearch installed={shutil.which('dirsearch') is not None}; it is not auto-run by Aegis.",
                recommendation="Use a bounded, reviewed wordlist only if active path discovery is permitted.",
            ),
        ]
    )

    tool_coverage = _tool_coverage(config)
    scoreable = [
        gap for gap in gaps if gap.status not in {CoverageStatus.EXCLUDED, CoverageStatus.REFERENCE}
    ]
    points = sum(
        1.0
        if gap.status is CoverageStatus.COVERED
        else 0.5
        if gap.status is CoverageStatus.PARTIAL
        else 0.0
        for gap in scoreable
    )
    coverage_score = round(100 * points / len(scoreable)) if scoreable else 0
    covered_areas = sum(
        gap.status in {CoverageStatus.COVERED, CoverageStatus.PARTIAL} for gap in scoreable
    )
    return GapAnalysis(
        coverage_score=coverage_score,
        covered_areas=covered_areas,
        total_areas=len(scoreable),
        gaps=gaps,
        tools=tool_coverage,
    )


def _tool_coverage(config: AppConfig) -> list[ToolCoverage]:
    coverage: list[ToolCoverage] = []
    for tool in TOOL_CATALOG:
        installed = tool.installed_path() is not None
        if tool.integration is Integration.REFERENCE_ONLY:
            status = CoverageStatus.REFERENCE
            evidence = f"Registered analyst reference: {tool.homepage}"
        elif tool.integration is Integration.BLOCKED_AUTO:
            status = CoverageStatus.EXCLUDED
            evidence = f"Intentionally excluded from automatic execution. {tool.safety_note}"
        elif tool.integration is Integration.INTEGRATED:
            enabled = tool.slug == "subfinder" and config.scan.discover_subdomains
            status = (
                CoverageStatus.COVERED
                if installed and enabled
                else CoverageStatus.UNAVAILABLE
                if enabled
                else CoverageStatus.NOT_RUN
            )
            evidence = f"Installed={installed}, enabled={enabled}. {tool.safety_note}"
        else:
            status = CoverageStatus.NOT_RUN if installed else CoverageStatus.UNAVAILABLE
            evidence = f"External tool installed={installed}; not executed by the Aegis pipeline. {tool.safety_note}"
        coverage.append(
            ToolCoverage(
                slug=tool.slug,
                name=tool.name,
                status=status,
                installed=installed,
                evidence=evidence,
            )
        )
    return coverage
