"""Report model and renderers."""

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from foretaster import __version__
from foretaster.discovery import LoadFailure
from foretaster.engine import ScanResult
from foretaster.models import AgentConfig, Finding, Severity


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolInfo(_Model):
    name: Literal["foretaster"] = "foretaster"
    version: str


class Summary(_Model):
    configs: int
    servers: int
    findings: dict[Severity, int]


class ReportError(_Model):
    """Something that kept the scan from being complete."""

    kind: Literal["config", "rule"]
    subject: str
    message: str


class Report(_Model):
    """The full outcome of a scan. Contains no timestamps, so equal inputs give equal reports."""

    schema_version: Literal["1"] = "1"
    tool: ToolInfo
    summary: Summary
    scanned: tuple[Path, ...]
    findings: tuple[Finding, ...]
    errors: tuple[ReportError, ...]

    def worst(self) -> Severity | None:
        return self.findings[0].severity if self.findings else None


def build_report(
    configs: Sequence[AgentConfig], failures: Sequence[LoadFailure], result: ScanResult
) -> Report:
    counts = {severity: 0 for severity in Severity}
    for finding in result.findings:
        counts[finding.severity] += 1
    errors = [
        ReportError(kind="config", subject=str(failure.candidate.path), message=failure.reason)
        for failure in failures
    ] + [
        ReportError(kind="rule", subject=error.rule_id, message=error.message)
        for error in result.rule_errors
    ]
    return Report(
        tool=ToolInfo(version=__version__),
        summary=Summary(
            configs=len(configs),
            servers=sum(len(config.servers) for config in configs),
            findings=counts,
        ),
        scanned=tuple(config.path for config in configs),
        findings=result.findings,
        errors=tuple(errors),
    )


__all__ = ["Report", "ReportError", "Summary", "ToolInfo", "build_report"]
