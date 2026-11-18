"""Command-line interface."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from foretaster import __version__
from foretaster.config_loader import ConfigLoadError, load_config
from foretaster.discovery import Candidate, DiscoveryResult, LoadFailure, discover
from foretaster.engine import run_rules
from foretaster.models import AgentConfig, Client, Scope, Severity
from foretaster.report import Report, build_report
from foretaster.report.console import render_console
from foretaster.rules import ALL_RULES, ScanTarget

EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2


class OutputFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"


class FailOn(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NEVER = "never"


app = typer.Typer(
    name="foretaster",
    help="Security scanner for AI agent configurations and MCP servers.",
    no_args_is_help=True,
    add_completion=False,
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"foretaster {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_print_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Security scanner for AI agent configurations and MCP servers."""


@app.command()
def version() -> None:
    """Show the installed Foretaster version."""
    typer.echo(f"foretaster {__version__}")


@app.command(name="discover")
def discover_command(
    project_dir: Annotated[
        Path,
        typer.Option(
            "--project-dir",
            help="Directory to search for project-level configuration.",
            file_okay=False,
            exists=True,
        ),
    ] = Path("."),
    as_json: Annotated[bool, typer.Option("--json", help="Print machine-readable JSON.")] = False,
) -> None:
    """List agent configuration files and the MCP servers they declare.

    Reads files only. No server is started or contacted, and no environment
    values, arguments or URLs are printed.
    """
    result = discover(cwd=project_dir)
    if as_json:
        typer.echo(json.dumps(_summary(result), indent=2))
    else:
        _print_table(result)


def _summary(result: DiscoveryResult) -> dict[str, object]:
    return {
        "configs": [
            {
                "client": config.client.value,
                "scope": config.scope.value,
                "path": str(config.path),
                "servers": [
                    {
                        "name": server.name,
                        "transport": server.transport.value,
                        "enabled": server.enabled,
                        "line": server.line,
                    }
                    for server in config.servers
                ],
                "problems": [
                    {"pointer": problem.pointer, "message": problem.message}
                    for problem in config.problems
                ],
            }
            for config in result.configs
        ],
        "failures": [
            {
                "client": failure.candidate.client.value,
                "path": str(failure.candidate.path),
                "reason": failure.reason,
            }
            for failure in result.failures
        ],
    }


def _print_table(result: DiscoveryResult) -> None:
    console = Console()
    if not result.configs and not result.failures:
        console.print("No agent configuration files found.")
        return
    table = Table(title="Agent configurations")
    for column in ("Client", "Scope", "File", "Servers", "Problems"):
        table.add_column(column)
    for config in result.configs:
        names = ", ".join(
            escape(server.name) + ("" if server.enabled else " (disabled)")
            for server in config.servers
        )
        table.add_row(
            config.client.value,
            config.scope.value,
            escape(str(config.path)),
            names or "-",
            str(len(config.problems)) if config.problems else "-",
        )
    if result.configs:
        console.print(table)
    for failure in result.failures:
        console.print(
            f"[red]Could not parse[/red] {escape(str(failure.candidate.path))}: "
            f"{escape(failure.reason)}"
        )


@app.command()
def scan(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Configuration files to scan. Omit to scan every configuration found.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    project_dir: Annotated[
        Path,
        typer.Option(
            "--project-dir",
            help="Directory to search for project-level configuration.",
            file_okay=False,
            exists=True,
        ),
    ] = Path("."),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to a file.", dir_okay=False),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit with status 1 at or above this severity."),
    ] = FailOn.HIGH,
) -> None:
    """Scan agent configurations for security problems.

    Reads files only: no server is started or contacted. Exit status is 0 when
    clean, 1 when findings reach --fail-on, 2 when the scan was incomplete.
    """
    configs, failures = _load(paths, project_dir)
    report = build_report(configs, failures, run_rules(ScanTarget(tuple(configs))))

    if output_format is OutputFormat.JSON:
        text = report.model_dump_json(indent=2) + "\n"
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            typer.echo(text, nl=False)
    elif output:
        with output.open("w", encoding="utf-8") as stream:
            render_console(report, Console(file=stream, no_color=True, width=100))
    else:
        render_console(report, Console())

    raise typer.Exit(_exit_code(report, fail_on))


@app.command(name="rules")
def rules_command() -> None:
    """List the built-in rules."""
    table = Table(title="Rules")
    for column in ("ID", "Severity", "Title", "Reference"):
        table.add_column(column)
    for rule in ALL_RULES:
        meta = rule.meta
        table.add_row(meta.id, meta.severity.value, meta.title, "\n".join(meta.references) or "-")
    Console().print(table)


def _load(
    paths: list[Path] | None, project_dir: Path
) -> tuple[list[AgentConfig], list[LoadFailure]]:
    if not paths:
        result = discover(cwd=project_dir)
        return list(result.configs), list(result.failures)
    configs: list[AgentConfig] = []
    failures: list[LoadFailure] = []
    for path in paths:
        try:
            configs.append(load_config(path))
        except ConfigLoadError as exc:
            failures.append(LoadFailure(Candidate(Client.GENERIC, Scope.USER, path), exc.reason))
    return configs, failures


def _exit_code(report: Report, fail_on: FailOn) -> int:
    if report.errors:
        return EXIT_INCOMPLETE
    worst = report.worst()
    if worst is None or fail_on is FailOn.NEVER:
        return 0
    return EXIT_FINDINGS if worst.rank <= Severity(fail_on.value).rank else 0
