"""Foretaster: security scanner for AI agent configurations and MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("foretaster")
except PackageNotFoundError:  # pragma: no cover - only when run from an uninstalled checkout
    __version__ = "0.0.0"

__all__ = ["__version__"]
