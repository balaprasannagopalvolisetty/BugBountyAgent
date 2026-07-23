from __future__ import annotations

from aegis_bounty.config import AppConfig
from aegis_bounty.gap_analysis import build_gap_analysis
from aegis_bounty.models import CoverageStatus, Endpoint, NetworkProfile, TLSProfile
from aegis_bounty.tool_catalog import TOOL_CATALOG


def test_gap_analysis_reports_network_and_manual_coverage(
    app_config: AppConfig, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("aegis_bounty.gap_analysis.shutil.which", lambda _name: None)
    analysis = build_gap_analysis(
        app_config,
        endpoints=[Endpoint(url="https://example.com/")],
        request_count=1,
        network_profiles=[
            NetworkProfile(
                hostname="example.com",
                addresses=["93.184.216.34"],
                tls=[TLSProfile(verified=True, protocol="TLSv1.3")],
            )
        ],
        observations=[],
        errors=[],
        ai_disabled=True,
    )

    gaps = {gap.area: gap for gap in analysis.gaps}
    assert gaps["DNS and address mapping"].status is CoverageStatus.COVERED
    assert gaps["TLS transport and certificate posture"].status is CoverageStatus.COVERED
    assert gaps["Authenticated roles and authorization boundaries"].status is CoverageStatus.NOT_RUN
    assert 0 <= analysis.coverage_score <= 100
    assert len(analysis.tools) == len(TOOL_CATALOG) == 10
    assert (
        next(tool for tool in analysis.tools if tool.slug == "scan4all").status
        is CoverageStatus.EXCLUDED
    )
