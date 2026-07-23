from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_bounty.config import AuthorizationConfig, TargetConfig, load_config


def test_refuses_unconfirmed_authorization() -> None:
    with pytest.raises(ValidationError, match="confirmed must be true"):
        AuthorizationConfig(
            confirmed=False,
            reference="program-123",
            authorized_by="security",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )


def test_refuses_expired_authorization() -> None:
    with pytest.raises(ValidationError, match="expired"):
        AuthorizationConfig(
            confirmed=True,
            reference="program-123",
            authorized_by="security",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )


def test_load_config_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- not\n- an\n- object\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML object"):
        load_config(path)


def test_derives_exact_hostname_when_only_seed_url_is_given() -> None:
    target = TargetConfig(seeds=["https://vast.ai/"])
    assert target.include_domains == ["vast.ai"]


def test_does_not_derive_wildcard_subdomains() -> None:
    target = TargetConfig(seeds=["https://app.example.com/path"])
    assert target.include_domains == ["app.example.com"]
    assert "*.example.com" not in target.include_domains
