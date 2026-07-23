from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from aegis_bounty.config import TargetConfig


class ScopeViolation(ValueError):
    """Raised when a candidate target is outside the declared authorization."""


def normalize_hostname(hostname: str) -> str:
    value = hostname.strip().rstrip(".").lower()
    if not value:
        raise ScopeViolation("URL does not contain a hostname")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeViolation(f"invalid hostname: {hostname}") from exc


def normalize_url(raw: str) -> str:
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScopeViolation(f"unsupported URL scheme: {parts.scheme}")
    host = normalize_hostname(parts.hostname or "")
    port = parts.port
    default_port = 80 if parts.scheme.lower() == "http" else 443
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopePolicy:
    def __init__(self, config: TargetConfig):
        self.config = config
        self.includes = tuple(
            normalize_hostname(rule.removeprefix("*.")) for rule in config.include_domains
        )
        self.include_wildcards = tuple(
            normalize_hostname(rule[2:]) for rule in config.include_domains if rule.startswith("*.")
        )
        self.include_exact = tuple(
            normalize_hostname(rule) for rule in config.include_domains if not rule.startswith("*.")
        )
        self.excludes = tuple(
            normalize_hostname(rule.removeprefix("*.")) for rule in config.exclude_domains
        )
        self.exclude_wildcards = tuple(
            normalize_hostname(rule[2:]) for rule in config.exclude_domains if rule.startswith("*.")
        )
        self.exclude_exact = tuple(
            normalize_hostname(rule) for rule in config.exclude_domains if not rule.startswith("*.")
        )

    @staticmethod
    def _matches(host: str, exact: tuple[str, ...], wildcards: tuple[str, ...]) -> bool:
        return host in exact or any(host.endswith(f".{suffix}") for suffix in wildcards)

    def hostname_allowed(self, hostname: str) -> ScopeDecision:
        host = normalize_hostname(hostname)
        if self._matches(host, self.exclude_exact, self.exclude_wildcards):
            return ScopeDecision(False, "hostname matches an exclusion rule")
        if not self._matches(host, self.include_exact, self.include_wildcards):
            return ScopeDecision(False, "hostname is not covered by include_domains")
        return ScopeDecision(True, "hostname is in scope")

    def url_allowed(self, raw_url: str) -> ScopeDecision:
        try:
            url = normalize_url(raw_url)
            parts = urlsplit(url)
        except (ScopeViolation, ValueError) as exc:
            return ScopeDecision(False, str(exc))
        host_decision = self.hostname_allowed(parts.hostname or "")
        if not host_decision.allowed:
            return host_decision
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in self.config.allowed_ports:
            return ScopeDecision(False, f"port {port} is not allowed")
        if any(parts.path.startswith(prefix) for prefix in self.config.exclude_paths):
            return ScopeDecision(False, "path matches an exclusion rule")
        return ScopeDecision(True, "URL is in scope")

    def require_url(self, raw_url: str) -> str:
        normalized = normalize_url(raw_url)
        decision = self.url_allowed(normalized)
        if not decision.allowed:
            raise ScopeViolation(f"{normalized}: {decision.reason}")
        return normalized

    async def resolve_public(self, hostname: str) -> list[str]:
        host = normalize_hostname(hostname)
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            )
        except socket.gaierror as exc:
            raise ScopeViolation(f"DNS resolution failed for {host}: {exc}") from exc
        addresses = sorted({str(info[4][0]) for info in infos})
        if not addresses:
            raise ScopeViolation(f"DNS returned no addresses for {host}")
        if self.config.allow_private_networks:
            return addresses
        rejected = [address for address in addresses if not ipaddress.ip_address(address).is_global]
        if rejected:
            raise ScopeViolation(
                f"{host} resolved to non-public address(es): {', '.join(rejected)}"
            )
        return addresses
