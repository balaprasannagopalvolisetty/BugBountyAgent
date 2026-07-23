from __future__ import annotations

from aegis_bounty.chains import ChainEngine
from aegis_bounty.models import Observation


def make(kind: str) -> Observation:
    return Observation(kind=kind, title=kind, url="https://api.example.com/x", evidence=kind)


def test_chain_engine_labels_hypotheses() -> None:
    chains = ChainEngine().build([make("information_disclosure"), make("exposed_api_surface")])
    assert len(chains) == 1
    assert chains[0].confidence.value == "tentative"
    assert "does not yet prove" in chains[0].rationale


def test_unrelated_hosts_do_not_chain() -> None:
    first = make("information_disclosure")
    second = make("exposed_api_surface").model_copy(update={"url": "https://other.example.com/"})
    assert ChainEngine().build([first, second]) == []
