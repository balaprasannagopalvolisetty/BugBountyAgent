from __future__ import annotations

from aegis_bounty.models import Observation
from aegis_bounty.triage import collapse_host_observations


def test_collapses_host_policy_duplicates_and_retains_urls() -> None:
    items = [
        Observation(
            kind="missing_security_header",
            title="Missing Content-Security-Policy",
            url=f"https://example.com/{path}",
            evidence=f"missing on {path}",
        )
        for path in ("one", "two")
    ]
    collapsed = collapse_host_observations(items)
    assert len(collapsed) == 1
    assert collapsed[0].metadata["collapsed_count"] == 2
    assert collapsed[0].metadata["affected_urls"] == [
        "https://example.com/one",
        "https://example.com/two",
    ]


def test_does_not_collapse_endpoint_specific_observations() -> None:
    items = [
        Observation(kind="information_disclosure", title="Trace", url=url, evidence=url)
        for url in ("https://example.com/one", "https://example.com/two")
    ]
    assert collapse_host_observations(items) == items
