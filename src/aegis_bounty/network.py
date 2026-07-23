from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aegis_bounty.models import (
    Asset,
    Confidence,
    Exploitability,
    NetworkProfile,
    Observation,
    Severity,
    TLSProfile,
)

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")
PROVIDER_MARKERS = {
    "cloudflare": "Cloudflare",
    "amazonaws.com": "Amazon Web Services",
    "awsdns-": "Amazon Route 53",
    "vercel-dns.com": "Vercel",
    "fastly.net": "Fastly",
    "azure": "Microsoft Azure",
    "googlehosted.com": "Google Cloud",
    "cloudfront.net": "Amazon CloudFront",
}


class NetworkMapper:
    def __init__(self, timeout_seconds: float, concurrency: int = 6):
        self.timeout_seconds = timeout_seconds
        self.semaphore = asyncio.Semaphore(concurrency)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout_seconds

    async def map(
        self, assets: list[Asset], urls: list[str]
    ) -> tuple[list[NetworkProfile], list[Observation], list[str]]:
        tls_ports: defaultdict[str, set[int]] = defaultdict(set)
        for raw_url in urls:
            parts = urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
            if parts.scheme == "https" and parts.hostname:
                tls_ports[parts.hostname].add(parts.port or 443)
        results = await asyncio.gather(
            *(self._map_asset(asset, tls_ports[asset.hostname]) for asset in assets)
        )
        profiles: list[NetworkProfile] = []
        observations: list[Observation] = []
        errors: list[str] = []
        for profile, profile_observations, profile_errors in results:
            profiles.append(profile)
            observations.extend(profile_observations)
            errors.extend(profile_errors)
        return profiles, observations, errors

    async def _map_asset(
        self, asset: Asset, tls_ports: set[int]
    ) -> tuple[NetworkProfile, list[Observation], list[str]]:
        async with self.semaphore:
            dns_records = await self._dns_records(asset.hostname)
            provider_hints = self._provider_hints(dns_records)
            tls_profiles: list[TLSProfile] = []
            errors: list[str] = []
            for port in sorted(tls_ports):
                try:
                    tls_profiles.append(await self._tls_profile(asset.hostname, port))
                except (OSError, TimeoutError, ssl.SSLError, ValueError) as exc:
                    errors.append(
                        f"TLS mapping {asset.hostname}:{port}: {type(exc).__name__}: {exc}"
                    )
            profile = NetworkProfile(
                hostname=asset.hostname,
                addresses=asset.addresses,
                dns_records=dns_records,
                provider_hints=provider_hints,
                tls=tls_profiles,
            )
            return profile, network_observations(profile), errors

    async def _dns_records(self, hostname: str) -> dict[str, list[str]]:
        answers = await asyncio.gather(
            *(self._resolve_record(hostname, record_type) for record_type in DNS_RECORD_TYPES)
        )
        return {
            record_type: values
            for record_type, values in zip(DNS_RECORD_TYPES, answers, strict=True)
            if values
        }

    async def _resolve_record(self, hostname: str, record_type: str) -> list[str]:
        try:
            answer = await self.resolver.resolve(hostname, record_type, raise_on_no_answer=False)
        except dns.exception.DNSException:
            return []
        return sorted({item.to_text().strip('"') for item in answer})

    @staticmethod
    def _provider_hints(records: dict[str, list[str]]) -> list[str]:
        haystack = " ".join(value.lower() for values in records.values() for value in values)
        return sorted(
            {provider for marker, provider in PROVIDER_MARKERS.items() if marker in haystack}
        )

    async def _tls_profile(self, hostname: str, port: int) -> TLSProfile:
        verification_error: str | None = None
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2", "http/1.1"])
            ssl_object, certificate = await self._tls_connect(hostname, port, context)
            verified = True
        except ssl.SSLCertVerificationError as exc:
            verification_error = str(exc)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["h2", "http/1.1"])
            ssl_object, certificate = await self._tls_connect(hostname, port, context)
            verified = False
        parsed = x509.load_der_x509_certificate(certificate)
        try:
            sans = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_dns_names = sorted(sans.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            san_dns_names = []
        public_key = parsed.public_key()
        key_bits = (
            public_key.key_size
            if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
            else None
        )
        cipher_info = ssl_object.cipher()
        signature_hash = (
            parsed.signature_hash_algorithm.name if parsed.signature_hash_algorithm else None
        )
        return TLSProfile(
            port=port,
            verified=verified,
            verification_error=verification_error,
            protocol=ssl_object.version(),
            cipher=cipher_info[0] if cipher_info else None,
            alpn_protocol=ssl_object.selected_alpn_protocol(),
            subject=parsed.subject.rfc4514_string(),
            issuer=parsed.issuer.rfc4514_string(),
            san_dns_names=san_dns_names,
            not_before=parsed.not_valid_before_utc,
            not_after=parsed.not_valid_after_utc,
            serial_number=format(parsed.serial_number, "x"),
            signature_hash=signature_hash,
            public_key_type=type(public_key).__name__,
            public_key_bits=key_bits,
            certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        )

    async def _tls_connect(
        self, hostname: str, port: int, context: ssl.SSLContext
    ) -> tuple[ssl.SSLObject, bytes]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=context, server_hostname=hostname),
            timeout=self.timeout_seconds,
        )
        del reader
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if not isinstance(ssl_object, ssl.SSLObject):
                raise ssl.SSLError("TLS handshake did not return an SSL object")
            certificate = ssl_object.getpeercert(binary_form=True)
            if not certificate:
                raise ssl.SSLError("peer did not provide a certificate")
            return ssl_object, certificate
        finally:
            writer.close()
            await writer.wait_closed()


def network_observations(profile: NetworkProfile) -> list[Observation]:
    observations: list[Observation] = []
    for tls in profile.tls:
        url = f"https://{profile.hostname}:{tls.port}/"
        if not tls.verified:
            observations.append(
                Observation(
                    kind="tls_verification",
                    title="TLS certificate verification failed",
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.STRONG,
                    exploitability=Exploitability.PLAUSIBLE,
                    evidence=tls.verification_error or "Certificate chain was not trusted.",
                    remediation="Deploy a trusted certificate chain matching the assessed hostname.",
                    source="network-mapper",
                )
            )
        if tls.not_after:
            days_remaining = (tls.not_after.astimezone(UTC) - datetime.now(UTC)).days
            if days_remaining < 0:
                severity = Severity.HIGH
                title = "TLS certificate has expired"
            elif days_remaining < 14:
                severity = Severity.MEDIUM
                title = "TLS certificate expires within 14 days"
            elif days_remaining < 30:
                severity = Severity.LOW
                title = "TLS certificate expires within 30 days"
            else:
                severity = None
                title = ""
            if severity:
                observations.append(
                    Observation(
                        kind="tls_expiration",
                        title=title,
                        url=url,
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        exploitability=Exploitability.PLAUSIBLE,
                        evidence=f"Certificate expiration: {tls.not_after.isoformat()} ({days_remaining} days remaining).",
                        remediation="Renew and deploy the certificate before expiration.",
                        source="network-mapper",
                    )
                )
        if tls.protocol in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
            observations.append(
                Observation(
                    kind="weak_tls_protocol",
                    title=f"Legacy TLS protocol negotiated: {tls.protocol}",
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    exploitability=Exploitability.PLAUSIBLE,
                    evidence=f"The TLS handshake negotiated {tls.protocol} with cipher {tls.cipher}.",
                    remediation="Disable legacy SSL/TLS versions and require TLS 1.2 or newer.",
                    source="network-mapper",
                )
            )
        if tls.signature_hash and tls.signature_hash.lower() in {"md5", "sha1"}:
            observations.append(
                Observation(
                    kind="weak_certificate_signature",
                    title=f"Certificate uses weak {tls.signature_hash.upper()} signature",
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    exploitability=Exploitability.PLAUSIBLE,
                    evidence=f"Certificate signature hash: {tls.signature_hash}.",
                    remediation="Replace the certificate with one signed using SHA-256 or stronger.",
                    source="network-mapper",
                )
            )
        if (
            tls.public_key_type
            and "RSA" in tls.public_key_type
            and (tls.public_key_bits or 0) < 2048
        ):
            observations.append(
                Observation(
                    kind="weak_certificate_key",
                    title="TLS certificate uses an undersized RSA key",
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    exploitability=Exploitability.PLAUSIBLE,
                    evidence=f"RSA public key size: {tls.public_key_bits} bits.",
                    remediation="Use an RSA key of at least 2048 bits or a modern elliptic-curve key.",
                    source="network-mapper",
                )
            )
    return observations
