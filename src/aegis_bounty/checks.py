from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from aegis_bounty.models import (
    Confidence,
    Exploitability,
    HttpExchange,
    Observation,
    Severity,
)

DOCUMENT_SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.LOW),
    "x-content-type-options": ("X-Content-Type-Options", Severity.INFO),
    "referrer-policy": ("Referrer-Policy", Severity.INFO),
}

DISCLOSURE_PATTERNS = {
    "stack trace": re.compile(
        r"(?i)(traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+:\d+\))"
    ),
    "database error": re.compile(
        r"(?is)(you have an error in your sql syntax.{0,160}(?:mysql|mariadb)"
        r"|postgres(?:ql)?(?:\s+(?:query|database|driver))?\s+(?:error|exception)\b"
        r"|psycopg\d*(?:\.[\w]+)*\.(?:error|\w+error)\b"
        r"|sqlstate\[[0-9a-z]{5}\]|ora-\d{5}\b|sqlite(?:3)?(?:error|exception|\s+error)\b)"
    ),
    "debug mode": re.compile(r"(?i)(werkzeug debugger|django debug|debug mode is on)"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

EXPOSED_DOC_PATHS = {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json", "/graphql"}


def analyze_exchange(exchange: HttpExchange) -> list[Observation]:
    observations: list[Observation] = []
    headers = {key.lower(): value for key, value in exchange.response_headers.items()}
    url_parts = urlsplit(exchange.url)
    media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    preview = exchange.body_preview.lstrip()[:1_000].lower()
    is_document = media_type in {"text/html", "application/xhtml+xml"} or preview.startswith(
        ("<!doctype html", "<html")
    )

    if url_parts.scheme == "https":
        if "strict-transport-security" not in headers:
            observations.append(
                Observation(
                    kind="missing_security_header",
                    title="Missing Strict-Transport-Security",
                    url=exchange.url,
                    severity=Severity.LOW,
                    confidence=Confidence.STRONG,
                    exploitability=Exploitability.UNDEMONSTRATED,
                    evidence=(
                        f"HTTPS response {exchange.request_id} did not include "
                        "Strict-Transport-Security. This is a host-level hardening signal."
                    ),
                    remediation="Evaluate and deploy an appropriate Strict-Transport-Security policy.",
                    request_id=exchange.request_id,
                )
            )
        if is_document:
            for header, (display, severity) in DOCUMENT_SECURITY_HEADERS.items():
                if header in headers:
                    continue
                observations.append(
                    Observation(
                        kind="missing_security_header",
                        title=f"Missing {display}",
                        url=exchange.url,
                        severity=severity,
                        confidence=Confidence.STRONG,
                        exploitability=Exploitability.UNDEMONSTRATED,
                        evidence=(
                            f"HTML document response {exchange.request_id} did not include {display}. "
                            "No exploitability is established by absence alone."
                        ),
                        remediation=f"Evaluate and deploy an appropriate {display} policy.",
                        request_id=exchange.request_id,
                    )
                )

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    versioned_server = bool(server and re.search(r"(?:/|\s)v?\d+(?:\.\d+)+", server))
    if powered_by or versioned_server:
        disclosed = "; ".join(
            filter(
                None,
                [
                    f"Server: {server}" if server else "",
                    f"X-Powered-By: {powered_by}" if powered_by else "",
                ],
            )
        )
        observations.append(
            Observation(
                kind="technology_disclosure",
                title="Technology details disclosed in headers",
                url=exchange.url,
                severity=Severity.INFO,
                confidence=Confidence.STRONG,
                exploitability=Exploitability.UNLIKELY,
                evidence=disclosed,
                remediation="Remove unnecessary version and framework disclosure from response headers.",
                request_id=exchange.request_id,
            )
        )

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookie_name = set_cookie.split("=", 1)[0].strip() or "cookie"
        lowered_cookie = set_cookie.lower()
        if url_parts.scheme == "https" and "secure" not in lowered_cookie:
            observations.append(
                Observation(
                    kind="cookie_security",
                    title=f"Cookie {cookie_name} lacks the Secure attribute",
                    url=exchange.url,
                    severity=Severity.LOW,
                    confidence=Confidence.STRONG,
                    exploitability=Exploitability.UNDEMONSTRATED,
                    evidence=f"Redacted Set-Cookie metadata from {exchange.request_id}: {set_cookie}",
                    remediation="Mark cookies transported over HTTPS as Secure.",
                    request_id=exchange.request_id,
                )
            )
        if "httponly" not in lowered_cookie:
            observations.append(
                Observation(
                    kind="cookie_security",
                    title=f"Cookie {cookie_name} lacks the HttpOnly attribute",
                    url=exchange.url,
                    severity=Severity.LOW,
                    confidence=Confidence.MODERATE,
                    exploitability=Exploitability.UNDEMONSTRATED,
                    evidence=f"Redacted Set-Cookie metadata from {exchange.request_id}: {set_cookie}",
                    remediation="Mark non-script-readable session and authentication cookies as HttpOnly.",
                    request_id=exchange.request_id,
                )
            )
        if "samesite" not in lowered_cookie:
            observations.append(
                Observation(
                    kind="cookie_security",
                    title=f"Cookie {cookie_name} lacks an explicit SameSite attribute",
                    url=exchange.url,
                    severity=Severity.INFO,
                    confidence=Confidence.STRONG,
                    exploitability=Exploitability.UNDEMONSTRATED,
                    evidence=f"Redacted Set-Cookie metadata from {exchange.request_id}: {set_cookie}",
                    remediation="Set SameSite=Lax or Strict unless a reviewed cross-site flow requires None.",
                    request_id=exchange.request_id,
                )
            )
    cors_origin = headers.get("access-control-allow-origin")
    cors_credentials = headers.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*" and cors_credentials == "true":
        observations.append(
            Observation(
                kind="cors_misconfiguration",
                title="Contradictory credentialed wildcard CORS policy",
                url=exchange.url,
                severity=Severity.LOW,
                confidence=Confidence.MODERATE,
                exploitability=Exploitability.UNLIKELY,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                remediation="Use an explicit allowlist and never combine wildcard origins with credentials.",
                request_id=exchange.request_id,
            )
        )

    for label, pattern in DISCLOSURE_PATTERNS.items():
        match = pattern.search(exchange.body_preview)
        if match:
            sample = match.group(0)[:500].replace("\n", " ")
            observations.append(
                Observation(
                    kind="information_disclosure",
                    title=f"Response contains {label}",
                    url=exchange.url,
                    severity=Severity.MEDIUM if label == "private key" else Severity.LOW,
                    confidence=Confidence.STRONG,
                    exploitability=(
                        Exploitability.PLAUSIBLE
                        if label == "private key"
                        else Exploitability.UNDEMONSTRATED
                    ),
                    evidence=f"Matched in response {exchange.request_id}: {sample}",
                    remediation="Return generic client-facing errors and keep secrets and diagnostics server-side.",
                    request_id=exchange.request_id,
                )
            )

    if url_parts.path.rstrip("/") in EXPOSED_DOC_PATHS and exchange.status_code < 400:
        observations.append(
            Observation(
                kind="exposed_api_surface",
                title="Potential API documentation or query endpoint exposed",
                url=exchange.url,
                severity=Severity.INFO,
                confidence=Confidence.MODERATE,
                exploitability=Exploitability.UNDEMONSTRATED,
                evidence=f"{url_parts.path} returned HTTP {exchange.status_code}.",
                remediation="Confirm the endpoint is intended to be public and restrict sensitive schemas or consoles.",
                request_id=exchange.request_id,
            )
        )

    location = headers.get("location")
    if location:
        destination = urljoin(exchange.url, location)
        destination_host = urlsplit(destination).hostname
        if destination_host and destination_host != url_parts.hostname:
            observations.append(
                Observation(
                    kind="external_redirect",
                    title="Response redirects to an external host",
                    url=exchange.url,
                    severity=Severity.INFO,
                    confidence=Confidence.MODERATE,
                    exploitability=Exploitability.UNDEMONSTRATED,
                    evidence=f"Location points to {destination}. This alone does not prove an open redirect.",
                    remediation="Ensure redirect destinations are fixed or validated against a strict allowlist.",
                    request_id=exchange.request_id,
                )
            )
    return observations


def analyze_active_cors(
    baseline: HttpExchange, probe: HttpExchange, origin: str
) -> list[Observation]:
    headers = {key.lower(): value for key, value in probe.response_headers.items()}
    reflected = headers.get("access-control-allow-origin") == origin
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if not reflected:
        return []
    severity = Severity.MEDIUM if credentials else Severity.LOW
    return [
        Observation(
            kind="cors_origin_reflection",
            title="Arbitrary CORS origin appears to be reflected",
            url=baseline.url,
            severity=severity,
            confidence=Confidence.STRONG,
            exploitability=Exploitability.PLAUSIBLE
            if credentials
            else Exploitability.UNDEMONSTRATED,
            evidence=(
                f"Probe {probe.request_id} sent Origin: {origin}; response allowed that origin"
                + (" with credentials." if credentials else ".")
            ),
            remediation="Use an exact, minimal origin allowlist and disable credentialed cross-origin access unless required.",
            request_id=probe.request_id,
        )
    ]
