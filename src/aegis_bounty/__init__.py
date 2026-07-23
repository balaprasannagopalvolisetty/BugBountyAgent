"""Aegis Bounty AI: scope-safe web assessment assistance."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aegis-bounty-ai")
except PackageNotFoundError:  # pragma: no cover - editable source tree
    __version__ = "0.1.0"

__all__ = ["__version__"]
