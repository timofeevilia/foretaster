"""Data models shared by collectors, rules and reports.

All models are immutable: a scan is a pure function of its inputs, and nothing
downstream may alter what was read from disk.
"""

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict


class Client(StrEnum):
    """Agent applications whose configuration formats are understood."""

    CLAUDE_DESKTOP = "claude-desktop"
    CLAUDE_CODE = "claude-code"
    CURSOR = "cursor"
    VSCODE = "vscode"
    WINDSURF = "windsurf"
    GENERIC = "generic"


class Scope(StrEnum):
    """Where a configuration applies."""

    USER = "user"
    PROJECT = "project"


class Transport(StrEnum):
    """How the agent reaches an MCP server."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    UNKNOWN = "unknown"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ServerDefinition(_Model):
    """One MCP server entry as declared in an agent configuration file.

    ``env`` and ``headers`` routinely hold credentials. Rules need the raw
    values to detect them; anything that prints a server must redact.
    """

    name: str
    transport: Transport
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}
    enabled: bool = True
    pointer: str
    """RFC 6901 JSON pointer to the entry inside its file."""
    line: int | None = None
    """1-based line of the entry in the file, when it could be located."""
    raw: dict[str, Any] = {}
    """The entry exactly as parsed, for rules that inspect client-specific keys."""


class ConfigProblem(_Model):
    """Something in a configuration file that could not be interpreted."""

    pointer: str
    message: str


class AgentConfig(_Model):
    """A parsed agent configuration file."""

    client: Client
    scope: Scope
    path: Path
    servers: tuple[ServerDefinition, ...] = ()
    problems: tuple[ConfigProblem, ...] = ()
