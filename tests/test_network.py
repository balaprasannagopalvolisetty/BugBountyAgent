from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegis_bounty.models import NetworkProfile, TLSProfile
from aegis_bounty.network import network_observations


def test_healthy_tls_profile_has_no_network_observations() -> None:
    profile = NetworkProfile(
        hostname="example.com",
        tls=[
            TLSProfile(
                verified=True,
                protocol="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                not_after=datetime.now(UTC) + timedelta(days=90),
                signature_hash="sha256",
                public_key_type="RSAPublicKey",
                public_key_bits=2048,
            )
        ],
    )
    assert network_observations(profile) == []


def test_weak_tls_profile_emits_transport_observations() -> None:
    profile = NetworkProfile(
        hostname="example.com",
        tls=[
            TLSProfile(
                verified=False,
                verification_error="self-signed certificate",
                protocol="TLSv1.1",
                cipher="OLD-CIPHER",
                not_after=datetime.now(UTC) - timedelta(days=1),
                signature_hash="sha1",
                public_key_type="RSAPublicKey",
                public_key_bits=1024,
            )
        ],
    )
    kinds = {item.kind for item in network_observations(profile)}
    assert kinds == {
        "tls_verification",
        "tls_expiration",
        "weak_tls_protocol",
        "weak_certificate_signature",
        "weak_certificate_key",
    }
