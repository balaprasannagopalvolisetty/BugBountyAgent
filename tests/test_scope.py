from __future__ import annotations

import socket

import pytest

from aegis_bounty.config import TargetConfig
from aegis_bounty.scope import ScopePolicy, ScopeViolation, normalize_url


def test_normalize_url_removes_fragment_and_default_port() -> None:
    assert normalize_url("HTTPS://ExAmPle.com:443/a?b=1#frag") == "https://example.com/a?b=1"


def test_exact_and_wildcard_scope(target_config: TargetConfig) -> None:
    scope = ScopePolicy(target_config)
    assert scope.hostname_allowed("example.com").allowed
    assert scope.hostname_allowed("api.example.com").allowed
    assert not scope.hostname_allowed("notexample.com").allowed
    assert not scope.hostname_allowed("admin.example.com").allowed
    assert not scope.hostname_allowed("x.blocked.example.com").allowed


def test_scope_rejects_excluded_path_and_port(target_config: TargetConfig) -> None:
    scope = ScopePolicy(target_config)
    assert not scope.url_allowed("https://example.com/logout?yes=1").allowed
    assert not scope.url_allowed("https://example.com:9443/").allowed
    with pytest.raises(ScopeViolation):
        scope.require_url("file:///etc/passwd")


@pytest.mark.asyncio
async def test_dns_guard_rejects_private_address(
    target_config: TargetConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = ScopePolicy(target_config)

    def fake_getaddrinfo(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScopeViolation, match="non-public"):
        await scope.resolve_public("example.com")


@pytest.mark.asyncio
async def test_dns_guard_can_allow_private_address(
    target_config: TargetConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = target_config.model_copy(update={"allow_private_networks": True})
    scope = ScopePolicy(config)

    def fake_getaddrinfo(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert await scope.resolve_public("example.com") == ["10.0.0.2"]
