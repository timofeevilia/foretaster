"""Human-readable report."""

from rich.console import Console
from rich.markup import escape

from foretaster.models import Finding, Severity
from foretaster.report import Report

_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


_ERROR_LABEL = {
    "config": "Could not parse",
    "server": "Could not connect to server",
    "rule": "Rule failed",
}


def render_console(report: Report, console: Console) -> None:
    for finding in report.findings:
        _render_finding(finding, console)
    for error in report.errors:
        label = _ERROR_LABEL[error.kind]
        console.print(f"[red]{label}[/red] {escape(error.subject)}: {escape(error.message)}")
    if report.errors:
        console.print()

    summary = report.summary
    counts = ", ".join(
        f"{count} {severity.value}" for severity, count in summary.findings.items() if count
    )
    console.print(
        f"Scanned {summary.configs} configuration file(s), {summary.servers} server(s), "
        f"{summary.tools} tool(s). " + (f"Findings: {counts}." if counts else "No findings.")
    )
    if report.errors:
        console.print(f"[red]{len(report.errors)} error(s): the scan is incomplete.[/red]")


def _render_finding(finding: Finding, console: Console) -> None:
    style = _STYLE[finding.severity]
    location = str(finding.location.path)
    if finding.location.line:
        location += f":{finding.location.line}"
    if finding.server and finding.tool:
        location += f" (server {finding.server!r}, tool {finding.tool!r})"
    elif finding.server:
        location += f" (server {finding.server!r})"
    console.print(
        f"[{style}]{finding.severity.value.upper()}[/{style}] "
        f"[bold]{finding.rule_id}[/bold] {escape(finding.title)}"
    )
    console.print(f"  {escape(location)}", soft_wrap=True)
    console.print(f"  {escape(finding.message)}")
    if finding.evidence:
        console.print(f"  Evidence: {escape(finding.evidence)}")
    console.print(f"  Fix: {escape(finding.remediation)}")
    for reference in finding.references:
        console.print(f"  [dim]{escape(reference)}[/dim]")
    console.print()
