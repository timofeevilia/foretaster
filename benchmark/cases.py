"""What a benchmark suite hands to the runner."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

SPLITS = ("dev", "test")


@dataclass(frozen=True)
class CleanServer:
    """A real server's tool list, as published. Nothing in it should be flagged."""

    name: str
    tools: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class PoisonedTool:
    """A malicious tool definition meant to sit next to ``server``'s real tools."""

    case_id: str
    server: str
    tool: dict[str, Any]
    category: str
    technique: str


@dataclass(frozen=True)
class Suite:
    name: str
    description: str
    source: str
    revision: str
    licence: str
    servers: tuple[CleanServer, ...]
    poisoned: tuple[PoisonedTool, ...]
    notes: tuple[str, ...] = field(default=())


def split_of(server: str) -> str:
    """Assign a server, and every case built on it, to ``dev`` or ``test``.

    The split is by server so that near-identical cases never straddle it, and
    it depends only on the server name, so it is stable across runs and
    machines. Rules may be tuned on ``dev``; ``test`` is for reporting.
    """
    digest = hashlib.sha256(server.encode("utf-8")).digest()
    return SPLITS[digest[0] % 2]
