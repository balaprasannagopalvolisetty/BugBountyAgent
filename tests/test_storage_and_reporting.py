from __future__ import annotations

from pathlib import Path

from aegis_bounty.models import (
    Asset,
    Confidence,
    CoverageGap,
    CoverageStatus,
    GapAnalysis,
    NetworkProfile,
    Observation,
    Severity,
    TLSProfile,
)
from aegis_bounty.reporting import write_reports
from aegis_bounty.storage import EvidenceStore


def test_store_deduplicates_and_writes_reports(tmp_path: Path) -> None:
    database = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(database)
    store.start_scan("scan1", "project", "2026-01-01T00:00:00+00:00")
    store.add_asset(
        "scan1", Asset(hostname="example.com", source="seed", addresses=["93.184.216.34"])
    )
    item = Observation(
        kind="test",
        title="Test item",
        url="https://example.com/",
        severity=Severity.LOW,
        confidence=Confidence.STRONG,
        evidence="evidence",
    )
    assert store.add_observations("scan1", [item, item]) == 1
    store.add_network_profile(
        "scan1",
        NetworkProfile(
            hostname="example.com",
            addresses=["93.184.216.34"],
            dns_records={"A": ["93.184.216.34"]},
            tls=[TLSProfile(verified=True, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")],
        ),
    )
    store.add_gap_analysis(
        "scan1",
        GapAnalysis(
            coverage_score=50,
            covered_areas=1,
            total_areas=2,
            gaps=[
                CoverageGap(
                    area="Network mapping",
                    status=CoverageStatus.COVERED,
                    evidence="One host mapped.",
                    recommendation="Review the map.",
                )
            ],
        ),
    )
    store.finish_scan("scan1", "2026-01-01T00:01:00+00:00")
    paths = write_reports(store, "scan1", tmp_path / "reports", ["json", "markdown", "html"])
    store.close()
    assert {path.name for path in paths} == {"report.json", "report.md", "report.html"}
    report = (tmp_path / "reports" / "report.md").read_text(encoding="utf-8")
    assert "human validation" in report
    assert "Detection confidence" in report
    assert "Exploitability" in report
    assert "Network layer map" in report
    assert "TLSv1.3" in report
    assert "Coverage gap analysis" in report
    assert "score measures assessment coverage" in report
