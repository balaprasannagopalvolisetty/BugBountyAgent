from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class AuthorizationConfig(BaseModel):
    confirmed: bool = False
    reference: str
    authorized_by: str
    expires_at: datetime

    @model_validator(mode="after")
    def must_be_valid(self) -> AuthorizationConfig:
        if not self.confirmed:
            raise ValueError("authorization.confirmed must be true before scanning")
        placeholders = {"replace-me", "replace-with-program-url-or-written-authorization-id"}
        if self.reference.strip().lower() in placeholders or len(self.reference.strip()) < 5:
            raise ValueError("authorization.reference must identify the real program or permission")
        if (
            self.authorized_by.strip().lower() in placeholders
            or len(self.authorized_by.strip()) < 2
        ):
            raise ValueError("authorization.authorized_by must identify the authorizer")
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires.astimezone(UTC) <= datetime.now(UTC):
            raise ValueError("authorization has expired")
        return self


class TargetConfig(BaseModel):
    seeds: list[str] = Field(min_length=1)
    include_domains: list[str] = Field(default_factory=list)
    exclude_domains: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    allow_private_networks: bool = False

    @model_validator(mode="after")
    def derive_exact_scope_from_seeds(self) -> TargetConfig:
        if self.include_domains:
            return self
        derived: set[str] = set()
        for seed in self.seeds:
            candidate = seed if "://" in seed else f"https://{seed}"
            hostname = urlsplit(candidate).hostname
            if not hostname:
                raise ValueError(f"cannot derive a hostname from target seed: {seed}")
            try:
                derived.add(hostname.rstrip(".").lower().encode("idna").decode("ascii"))
            except UnicodeError as exc:
                raise ValueError(f"invalid hostname in target seed: {seed}") from exc
        self.include_domains = sorted(derived)
        return self

    @field_validator("allowed_ports")
    @classmethod
    def valid_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("allowed_ports entries must be between 1 and 65535")
        return sorted(set(value))


class ScanConfig(BaseModel):
    max_requests: int = Field(default=250, ge=1, le=100_000)
    max_pages_per_host: int = Field(default=40, ge=1, le=10_000)
    max_depth: int = Field(default=3, ge=0, le=12)
    concurrency: int = Field(default=4, ge=1, le=50)
    requests_per_second: float = Field(default=1.5, gt=0, le=50)
    timeout_seconds: float = Field(default=12, gt=0, le=120)
    user_agent: str = "AegisBountyAI/0.4 authorized-security-research"
    active_validation: bool = False
    discover_subdomains: bool = False
    use_nuclei: bool = False
    nuclei_severities: list[str] = Field(
        default_factory=lambda: ["info", "low", "medium", "high", "critical"]
    )

    @field_validator("user_agent")
    @classmethod
    def descriptive_agent(cls, value: str) -> str:
        if len(value.strip()) < 12:
            raise ValueError("user_agent must be descriptive")
        return value


class AIConfig(BaseModel):
    enabled: bool = False
    provider: Literal["openai"] = "openai"
    triage_model: str = "gpt-5.6-terra"
    reasoning_model: str = "gpt-5.6-sol"
    max_observations: int = Field(default=25, ge=1, le=200)
    redact_secrets: bool = True


class OutputConfig(BaseModel):
    directory: Path = Path("runs")
    formats: list[Literal["json", "markdown", "html"]] = Field(default_factory=list)

    @model_validator(mode="after")
    def default_formats(self) -> OutputConfig:
        if not self.formats:
            self.formats = ["json", "markdown", "html"]
        return self


class AppConfig(BaseModel):
    project: str = Field(min_length=1, max_length=100)
    target: TargetConfig
    authorization: AuthorizationConfig
    scan: ScanConfig = Field(default_factory=ScanConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def load_config(path: Path) -> AppConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"configuration not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("configuration must be a YAML object")
    return AppConfig.model_validate(raw)
