from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from aegis_bounty.models import Observation

HOST_SCOPED_KINDS = {"missing_security_header", "technology_disclosure"}


def collapse_host_observations(items: list[Observation]) -> list[Observation]:
    """Collapse policy-level duplicates while retaining every affected URL in metadata."""
    grouped: defaultdict[tuple[str, str, str], list[Observation]] = defaultdict(list)
    passthrough: list[Observation] = []
    for item in items:
        if item.kind not in HOST_SCOPED_KINDS:
            passthrough.append(item)
            continue
        host = urlsplit(item.url).hostname or ""
        grouped[(item.kind, item.title, host)].append(item)

    collapsed: list[Observation] = []
    for group in grouped.values():
        representative = group[0]
        affected_urls = sorted({item.url for item in group})
        if len(affected_urls) == 1:
            collapsed.append(representative)
            continue
        data = representative.model_dump()
        data["fingerprint"] = ""
        data["evidence"] = (
            f"{representative.evidence}\nCollapsed {len(affected_urls)} matching responses on this host."
        )
        metadata = dict(representative.metadata)
        metadata["affected_urls"] = affected_urls
        metadata["collapsed_count"] = len(affected_urls)
        data["metadata"] = metadata
        collapsed.append(Observation.model_validate(data))
    return passthrough + collapsed
