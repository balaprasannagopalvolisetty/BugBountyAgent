from __future__ import annotations

from datetime import datetime

import pytest

from aegis_bounty.config import (
    AIConfig,
    AppConfig,
    AuthorizationConfig,
    OutputConfig,
    ScanConfig,
    TargetConfig,
)


@pytest.fixture
def target_config() -> TargetConfig:
    return TargetConfig(
        seeds=["https://example.com"],
        include_domains=["example.com", "*.example.com"],
        exclude_domains=["admin.example.com", "*.blocked.example.com"],
        exclude_paths=["/logout", "/danger"],
        allowed_ports=[80, 443, 8443],
    )


@pytest.fixture
def app_config(target_config: TargetConfig) -> AppConfig:
    return AppConfig(
        project="test-project",
        target=target_config,
        authorization=AuthorizationConfig(
            confirmed=True,
            reference="https://hackerone.example/program-scope",
            authorized_by="Example Security",
            expires_at=datetime.fromisoformat("2099-12-31T23:59:59+00:00"),
        ),
        scan=ScanConfig(max_requests=10, max_pages_per_host=5, concurrency=1),
        ai=AIConfig(enabled=False),
        output=OutputConfig(directory="runs"),
    )
