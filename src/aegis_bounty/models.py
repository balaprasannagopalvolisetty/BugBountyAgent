from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    TENTATIVE = "tentative"
    MODERATE = "moderate"
    STRONG = "strong"
    CONFIRMED = "confirmed"


class Exploitability(StrEnum):
    UNDEMONSTRATED = "undemonstrated"
    UNLIKELY = "unlikely"
    PLAUSIBLE = "plausible"
    LIKELY = "likely"
    CONFIRMED = "confirmed"


class Observation(BaseModel):
    kind: str
    title: str
    url: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE
    exploitability: Exploitability = Exploitability.UNDEMONSTRATED
    evidence: str
    remediation: str = "Review the affected behavior and apply defense in depth."
    source: str = "aegis"
    request_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    fingerprint: str = ""

    @field_validator("evidence")
    @classmethod
    def cap_evidence(cls, value: str) -> str:
        return value[:12_000]

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            stable = json.dumps(
                [self.kind, self.title, self.url, self.evidence],
                separators=(",", ":"),
                sort_keys=True,
            )
            self.fingerprint = hashlib.sha256(stable.encode()).hexdigest()[:24]


class HttpExchange(BaseModel):
    request_id: str
    method: str
    url: str
    status_code: int
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    elapsed_ms: int = 0
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    source_url: str | None = None
    depth: int = 0
    tags: set[str] = Field(default_factory=set)


class Asset(BaseModel):
    hostname: str
    source: str
    addresses: list[str] = Field(default_factory=list)


class ChainHypothesis(BaseModel):
    title: str
    observation_ids: list[str]
    rationale: str
    potential_impact: str
    validation_steps: list[str]
    confidence: Confidence = Confidence.TENTATIVE


class ScanSummary(BaseModel):
    scan_id: str
    project: str
    started_at: datetime
    finished_at: datetime
    assets: int
    endpoints: int
    requests: int
    observations: int
    chains: int
    report_paths: list[str] = Field(default_factory=list)
