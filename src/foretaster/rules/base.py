"""Rule interface."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from foretaster.models import (
    AgentConfig,
    Finding,
    Location,
    ServerDefinition,
    ServerInventory,
    Severity,
    ToolDefinition,
)
from foretaster.redact import scrub
from foretaster.textscan import printable, schema_texts

if TYPE_CHECKING:
    from foretaster.baseline import Baseline

# Verified against the OWASP MCP Top 10 project repository (2025 list, beta).
OWASP_MCP = {
    "MCP01": "OWASP MCP01:2025 Token Mismanagement & Secret Exposure",
    "MCP02": "OWASP MCP02:2025 Privilege Escalation via Scope Creep",
    "MCP03": "OWASP MCP03:2025 Tool Poisoning",
    "MCP04": "OWASP MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "OWASP MCP05:2025 Command Injection & Execution",
    "MCP06": "OWASP MCP06:2025 Intent Flow Subversion",
    "MCP07": "OWASP MCP07:2025 Insufficient Authentication & Authorization",
    "MCP08": "OWASP MCP08:2025 Lack of Audit and Telemetry",
    "MCP09": "OWASP MCP09:2025 Shadow MCP Servers",
    "MCP10": "OWASP MCP10:2025 Context Injection & Over-Sharing",
}


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = ()


class TextItem(NamedTuple):
    """A piece of untrusted text and where it came from."""

    inventory: ServerInventory
    tool: ToolDefinition | None
    pointer: str
    label: str
    text: str


class ScanTarget(NamedTuple):
    """Everything a scan knows about. Rules must treat it as read-only."""

    configs: tuple[AgentConfig, ...]
    inventories: tuple[ServerInventory, ...] = ()
    baseline: "Baseline | None" = None

    def texts(self) -> Iterator[TextItem]:
        """Yield every piece of server-supplied text that a model would read."""
        for inventory in self.inventories:
            base = inventory.origin.pointer
            if inventory.instructions:
                yield TextItem(
                    inventory,
                    None,
                    f"{base}/instructions",
                    "server instructions",
                    inventory.instructions,
                )
            for index, tool in enumerate(inventory.tools):
                prefix = f"{base}/tools/{index}"
                if tool.description:
                    yield TextItem(
                        inventory,
                        tool,
                        f"{prefix}/description",
                        "tool description",
                        tool.description,
                    )
                for suffix, text in schema_texts(tool.input_schema):
                    yield TextItem(
                        inventory, tool, f"{prefix}/inputSchema{suffix}", "parameter schema", text
                    )

    def servers(self) -> Iterator[tuple[AgentConfig, ServerDefinition]]:
        for config in self.configs:
            for server in config.servers:
                yield config, server


class Rule(ABC):
    meta: ClassVar[RuleMeta]

    @abstractmethod
    def check(self, target: ScanTarget) -> Iterator[Finding]:
        """Yield a finding for every violation in ``target``."""

    def make(
        self,
        path: Path,
        message: str,
        *,
        pointer: str = "",
        line: int | None = None,
        server: str | None = None,
        tool: str | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Build a finding carrying this rule's metadata.

        Message and evidence may quote configuration or server text, so both
        are escaped to visible characters and scrubbed of recognisable
        credentials here. A rule cannot leak either by accident.
        """
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=severity or self.meta.severity,
            message=scrub(printable(message)),
            location=Location(path=path, pointer=pointer, line=line),
            server=server,
            tool=tool,
            evidence=scrub(printable(evidence)) if evidence else None,
            remediation=self.meta.remediation,
            references=self.meta.references,
        )

    def finding(
        self,
        config: AgentConfig,
        message: str,
        *,
        server: ServerDefinition | None = None,
        pointer: str | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Build a finding about a configuration file or one of its servers."""
        if pointer is None:
            pointer = server.pointer if server else ""
        return self.make(
            config.path,
            message,
            pointer=pointer,
            line=server.line if server else None,
            server=server.name if server else None,
            evidence=evidence,
            severity=severity,
        )

    def text_finding(
        self,
        item: TextItem,
        message: str,
        *,
        evidence: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Build a finding about something a server advertises."""
        origin = item.inventory.origin
        return self.make(
            origin.path,
            message,
            pointer=item.pointer,
            line=origin.line,
            server=item.inventory.server,
            tool=item.tool.name if item.tool else None,
            evidence=evidence,
            severity=severity,
        )
