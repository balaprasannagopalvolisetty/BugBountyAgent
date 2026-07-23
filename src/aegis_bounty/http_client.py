from __future__ import annotations

import hashlib
import re
import time
from urllib.parse import urlsplit

import httpx

from aegis_bounty.models import HttpExchange
from aegis_bounty.rate_limit import HostRateLimiter
from aegis_bounty.scope import ScopePolicy

SENSITIVE_REQUEST_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
SENSITIVE_RESPONSE_HEADERS = {"set-cookie"}


def _redact_headers(headers: httpx.Headers, sensitive: set[str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.multi_items():
        lowered = key.lower()
        if lowered == "set-cookie":
            # Preserve security attributes while removing the cookie value.
            redacted[key] = re.sub(r"^([^=;]+)=[^;]*", r"\1=[REDACTED]", value)[:2_000]
        elif lowered in sensitive:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value[:2_000]
    return redacted


class SafeHttpClient:
    def __init__(
        self,
        scope: ScopePolicy,
        user_agent: str,
        timeout_seconds: float,
        requests_per_second: float,
        max_requests: int,
    ):
        self.scope = scope
        self.limiter = HostRateLimiter(requests_per_second)
        self.max_requests = max_requests
        self.request_count = 0
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds),
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
            },
        )

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response, HttpExchange]:
        normalized = self.scope.require_url(url)
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("Aegis network client permits only read-only HTTP methods")
        if self.request_count >= self.max_requests:
            raise RuntimeError("global request budget exhausted")
        hostname = urlsplit(normalized).hostname or ""
        await self.scope.resolve_public(hostname)
        await self.limiter.wait(hostname)
        self.request_count += 1
        started = time.perf_counter()
        response = await self.client.request(method.upper(), normalized, headers=headers)
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        raw_id = f"{method.upper()}\n{normalized}\n{self.request_count}"
        request_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]
        content_type = response.headers.get("content-type", "")
        textual = any(
            marker in content_type.lower() for marker in ("text", "json", "xml", "javascript")
        )
        preview = (
            response.text[:25_000] if textual else f"[binary body: {len(response.content)} bytes]"
        )
        exchange = HttpExchange(
            request_id=request_id,
            method=method.upper(),
            url=normalized,
            status_code=response.status_code,
            request_headers=_redact_headers(response.request.headers, SENSITIVE_REQUEST_HEADERS),
            response_headers=_redact_headers(response.headers, SENSITIVE_RESPONSE_HEADERS),
            body_preview=preview,
            elapsed_ms=elapsed_ms,
        )
        return response, exchange
