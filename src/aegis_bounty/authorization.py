from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path

import yaml
from pydantic import BaseModel

from aegis_bounty.config import AuthorizationConfig


class AuthorizationProfile(BaseModel):
    hostname: str
    authorization: AuthorizationConfig


def authorization_home() -> Path:
    override = os.environ.get("AEGIS_CONFIG_HOME")
    return Path(override).expanduser() if override else Path.home() / ".aegis"


def authorization_path(hostname: str) -> Path:
    safe_hostname = hostname.rstrip(".").lower().encode("idna").decode("ascii")
    return authorization_home() / "authorizations" / f"{safe_hostname}.yaml"


def load_authorization(hostname: str) -> AuthorizationProfile | None:
    path = authorization_path(hostname)
    if not path.exists():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"invalid authorization profile: {path}")
    profile = AuthorizationProfile.model_validate(raw)
    if profile.hostname != hostname.rstrip(".").lower():
        raise ValueError(f"authorization profile hostname mismatch: {path}")
    return profile


def save_authorization(profile: AuthorizationProfile) -> Path:
    path = authorization_path(profile.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = profile.model_dump(mode="json")
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with suppress(OSError):
        path.chmod(0o600)
    return path
