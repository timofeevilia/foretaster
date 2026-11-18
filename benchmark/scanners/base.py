"""What the runner needs from any scanner under test."""

from typing import Any, NamedTuple, Protocol

from foretaster.models import Severity

Servers = dict[str, list[dict[str, Any]]]
"""Tool lists by server name: one scan's worth of input."""


class Flag(NamedTuple):
    """A scanner's verdict on one tool."""

    severity: Severity
    labels: tuple[str, ...]
    """Rule IDs or threat names, for the per-rule breakdown."""
    detail: str = ""


Verdicts = dict[tuple[str, str], Flag]
"""Flags keyed by ``(server, tool name)``. Tools the scanner passed are absent."""


class Scanner(Protocol):
    name: str
    version: str
    notes: tuple[str, ...]

    def scan_many(self, batches: list[Servers]) -> list[Verdicts]:
        """Scan each batch as an independent agent and return one verdict map per batch."""
        ...
