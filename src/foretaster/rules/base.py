"""Rule interface."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import ClassVar, NamedTuple

from foretaster.models import AgentConfig, Finding, Location, ServerDefinition, Severity
from foretaster.redact import scrub

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


class ScanTarget(NamedTuple):
    """Everything a scan knows about. Rules must treat it as read-only."""

    configs: tuple[AgentConfig, ...]

    def servers(self) -> Iterator[tuple[AgentConfig, ServerDefinition]]:
        for config in self.configs:
            for server in config.servers:
                yield config, server


class Rule(ABC):
    meta: ClassVar[RuleMeta]

    @abstractmethod
    def check(self, target: ScanTarget) -> Iterator[Finding]:
        """Yield a finding for every violation in ``target``."""

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
        """Build a finding carrying this rule's metadata.

        Message and evidence are scrubbed of recognisable credentials here, so
        a rule that quotes configuration text cannot leak them by accident.
        """
        if pointer is None:
            pointer = server.pointer if server else ""
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=severity or self.meta.severity,
            message=scrub(message),
            location=Location(
                path=config.path, pointer=pointer, line=server.line if server else None
            ),
            server=server.name if server else None,
            evidence=scrub(evidence) if evidence else None,
            remediation=self.meta.remediation,
            references=self.meta.references,
        )
