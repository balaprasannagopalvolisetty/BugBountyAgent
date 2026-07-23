from __future__ import annotations

from types import SimpleNamespace

import pytest

from aegis_bounty.config import AIConfig
from aegis_bounty.llm import OpenAITriage, redact
from aegis_bounty.models import Observation


def test_redacts_common_secrets() -> None:
    value = redact("Authorization: Bearer abc123 token=verysecret sk-abcdefghijklmnop")
    assert "abc123" not in value
    assert "verysecret" not in value
    assert "sk-abcdefghijklmnop" not in value


class FakeResponses:
    async def create(self, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            output_text='{"items":[{"source_fingerprint":"PLACEHOLDER","assessment":"signal only","severity":"info","confidence":"tentative","rationale":"insufficient evidence","safe_validation":["Review headers"]}]}'
        )


class FakeClient:
    def __init__(self) -> None:
        self.responses = FakeResponses()


@pytest.mark.asyncio
async def test_ai_ignores_unknown_fingerprint() -> None:
    item = Observation(kind="test", title="test", url="https://example.com", evidence="x")
    triage = OpenAITriage(AIConfig(enabled=True), client=FakeClient())  # type: ignore[arg-type]
    assert await triage.analyze([item]) == []
