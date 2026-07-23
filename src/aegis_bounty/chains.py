from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from aegis_bounty.models import ChainHypothesis, Confidence, Observation


class ChainEngine:
    """Build hypotheses from compatible evidence without claiming exploitability."""

    def build(self, observations: list[Observation]) -> list[ChainHypothesis]:
        by_host: defaultdict[str, list[Observation]] = defaultdict(list)
        for item in observations:
            by_host[urlsplit(item.url).hostname or ""].append(item)
        chains: list[ChainHypothesis] = []
        for host, items in sorted(by_host.items()):
            kinds = {item.kind for item in items}
            if "external_redirect" in kinds and "cors_origin_reflection" in kinds:
                selected = [
                    item.fingerprint
                    for item in items
                    if item.kind in {"external_redirect", "cors_origin_reflection"}
                ]
                chains.append(
                    ChainHypothesis(
                        title=f"Cross-origin trust-boundary hypothesis on {host}",
                        observation_ids=selected,
                        rationale="The host emitted both an external redirect signal and arbitrary-origin CORS behavior. They may be unrelated; authentication-flow review is required.",
                        potential_impact="If the same trust decision protects sensitive authenticated data, cross-origin exposure or token-flow abuse may be possible.",
                        validation_steps=[
                            "Map the documented authentication and redirect allowlists without changing an account.",
                            "Verify whether the CORS-enabled response contains user-specific or sensitive data using a dedicated test account.",
                            "Confirm that redirect and CORS behavior occur in the same security context.",
                        ],
                        confidence=Confidence.TENTATIVE,
                    )
                )
            if "information_disclosure" in kinds and "exposed_api_surface" in kinds:
                selected = [
                    item.fingerprint
                    for item in items
                    if item.kind in {"information_disclosure", "exposed_api_surface"}
                ]
                chains.append(
                    ChainHypothesis(
                        title=f"API-assisted information exposure hypothesis on {host}",
                        observation_ids=selected,
                        rationale="An API surface and diagnostic disclosure were observed on the same host; the evidence does not yet prove they are connected.",
                        potential_impact="Schema or implementation details could make a separately confirmed flaw easier to understand or reproduce.",
                        validation_steps=[
                            "Confirm whether the API surface is intentionally public.",
                            "Reproduce the diagnostic disclosure with the least-privileged test account and a read-only request.",
                            "Document exactly which non-public details are revealed and why they matter.",
                        ],
                        confidence=Confidence.TENTATIVE,
                    )
                )
        return chains
