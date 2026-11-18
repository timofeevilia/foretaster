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


class ProblemKind(StrEnum):
    MALFORMED = "malformed"
    DUPLICATE_KEY = "duplicate-key"


class ConfigProblem(_Model):
    """Something in a configuration file that could not be interpreted."""

    pointer: str
    message: str
    kind: ProblemKind = ProblemKind.MALFORMED


class AgentConfig(_Model):
    """A parsed agent configuration file."""

    client: Client
    scope: Scope
    path: Path
    servers: tuple[ServerDefinition, ...] = ()
    problems: tuple[ConfigProblem, ...] = ()


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Position in the ordering, 0 being the most severe."""
        return list(Severity).index(self)


class Location(_Model):
    """Where a finding was observed."""

    path: Path
    pointer: str = ""
    line: int | None = None


class ToolDefinition(_Model):
    """One tool as advertised by an MCP server. All of it is untrusted text."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = {}


class ServerInventory(_Model):
    """What a server advertises to the model: its tools and instructions."""

    server: str
    origin: Location
    """The config entry or manifest file this inventory was obtained from."""
    instructions: str | None = None
    tools: tuple[ToolDefinition, ...] = ()
    open_remote: bool = False
    """True when a network server listed its tools to a client that sent no credentials."""


class Finding(_Model):
    """One issue reported by a rule.

    ``evidence`` is shown to users and written to reports, so rules must
    redact credentials before putting anything there.
    """

    rule_id: str
    title: str
    severity: Severity
    message: str
    location: Location
    server: str | None = None
    tool: str | None = None
    evidence: str | None = None
    remediation: str
    references: tuple[str, ...] = ()
