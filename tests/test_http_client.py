from __future__ import annotations

import httpx
import pytest

from aegis_bounty.config import TargetConfig
from aegis_bounty.http_client import SafeHttpClient
from aegis_bounty.scope import ScopePolicy


@pytest.mark.asyncio
async def test_safe_http_client_redacts_secrets_and_enforces_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = ScopePolicy(
        TargetConfig(
            seeds=["https://example.com"],
            include_domains=["example.com"],
            allowed_ports=[443],
        )
    )

    async def public(_hostname: str) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(scope, "resolve_public", public)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            headers={"set-cookie": "session=supersecret; Path=/; HttpOnly"},
            text="ok",
        )

    client = SafeHttpClient(scope, "Aegis authorized test", 2, 100, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        _response, exchange = await client.request(
            "GET", "https://example.com/", headers={"Authorization": "Bearer secret"}
        )
        assert exchange.request_headers["authorization"] == "[REDACTED]"
        assert "supersecret" not in exchange.response_headers["set-cookie"]
        assert "HttpOnly" in exchange.response_headers["set-cookie"]
        with pytest.raises(RuntimeError, match="budget"):
            await client.request("GET", "https://example.com/again")
        with pytest.raises(ValueError, match="read-only"):
            await client.request("POST", "https://example.com/")
    finally:
        await client.client.aclose()
