"""Command-line interface."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NamedTuple

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from foretaster import __version__
from foretaster.baseline import Baseline, build_baseline, dump_baseline, load_baseline
from foretaster.config_loader import ConfigLoadError, load_config
from foretaster.discovery import Candidate, DiscoveryResult, LoadFailure, discover
from foretaster.engine import run_rules
from foretaster.live import DEFAULT_TIMEOUT, ConnectionFailure, ConnectUnavailableError, collect
from foretaster.llm import Model, Reviewer, VerdictCache, default_cache_path
from foretaster.llm.anthropic_model import DEFAULT_MODEL, AnthropicModel, LlmUnavailableError
from foretaster.models import AgentConfig, Client, Scope, ServerInventory, Severity
from foretaster.report import Report, build_report
from foretaster.report.console import render_console
from foretaster.report.html import render_html
from foretaster.report.sarif import render_sarif
from foretaster.rules import ALL_RULES, OPTIONAL_RULES, LlmReview, Rule, ScanTarget
from foretaster.tool_manifest import load_tool_manifest

EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2


class OutputFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


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
    tools: Annotated[
        list[Path] | None,
        typer.Option(
            "--tools",
            help="Saved tool list of a server (a tools/list result) to scan. Repeatable.",
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
    connect: Annotated[
        bool,
        typer.Option(
            "--connect",
            help="Start or contact each configured server and scan the tools it advertises. "
            "This runs the commands in your configuration. No tool is ever called.",
        ),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds to wait for each server with --connect.", min=1),
    ] = DEFAULT_TIMEOUT,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            help="Compare tool definitions with a file written by `foretaster baseline`.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    llm: Annotated[
        bool,
        typer.Option(
            "--llm",
            help="Also have a language model read every tool definition. This sends tool "
            "names, descriptions and parameter texts to the Claude API and needs "
            "ANTHROPIC_API_KEY. Configuration files are never sent.",
        ),
    ] = False,
    llm_model: Annotated[
        str,
        typer.Option("--llm-model", help="Model for --llm.", envvar="FORETASTER_LLM_MODEL"),
    ] = DEFAULT_MODEL,
    llm_cache: Annotated[
        bool,
        typer.Option(
            "--llm-cache/--no-llm-cache",
            help="Remember the model's verdicts so that unchanged tools are not sent again.",
        ),
    ] = True,
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
    """Scan agent configurations and tool descriptions for security problems.

    Reads files only, unless --connect is given, and sends nothing anywhere,
    unless --llm is given. Exit status is 0 when clean, 1 when findings reach
    --fail-on, 2 when the scan was incomplete.
    """
    gathered = _gather(paths, tools, project_dir, connect, timeout)
    reviewer: Reviewer | None = None
    rules: list[Rule] | None = None
    if llm:
        try:
            model = _make_model(llm_model)
        except LlmUnavailableError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(EXIT_INCOMPLETE) from exc
        reviewer = Reviewer(model, VerdictCache(default_cache_path() if llm_cache else None))
        rules = [rule() for rule in ALL_RULES] + [LlmReview(reviewer)]
    known: Baseline | None = None
    if baseline:
        try:
            known = load_baseline(baseline)
        except ConfigLoadError as exc:
            gathered.failures.append(
                LoadFailure(Candidate(Client.GENERIC, Scope.USER, baseline), exc.reason)
            )
    target = ScanTarget(tuple(gathered.configs), tuple(gathered.inventories), known)
    report = build_report(
        gathered.configs,
        gathered.failures,
        run_rules(target, rules),
        gathered.inventories,
        gathered.unreachable,
    )
    if reviewer is not None:
        typer.echo(_llm_note(reviewer), err=True)

    if output_format is OutputFormat.CONSOLE:
        if output:
            with output.open("w", encoding="utf-8") as stream:
                render_console(report, Console(file=stream, no_color=True, width=100))
        else:
            render_console(report, Console())
    else:
        if output_format is OutputFormat.JSON:
            text = report.model_dump_json(indent=2) + "\n"
        elif output_format is OutputFormat.SARIF:
            text = render_sarif(report)
        else:
            text = render_html(report)
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            typer.echo(text, nl=False)

    raise typer.Exit(_exit_code(report, fail_on))


def _make_model(name: str) -> Model:
    """Build the reviewer model. Raises ``LlmUnavailableError`` when it cannot be used."""
    try:
        return AnthropicModel(name)
    except LlmUnavailableError:
        raise
    except Exception as exc:
        # The client library refuses to start without credentials.
        raise LlmUnavailableError(
            f"the LLM review could not start: {exc}. Set ANTHROPIC_API_KEY to a Claude API key."
        ) from exc


def _llm_note(reviewer: Reviewer) -> str:
    stats = reviewer.stats
    if not stats.items:
        return (
            "LLM review: nothing to review. The model reads tool definitions, "
            "which a scan has only with --connect or --tools."
        )
    sent = stats.items - stats.cached - stats.failed
    return (
        f"LLM review by {reviewer.model.identity}: {stats.items} tool definition(s), "
        f"{sent} sent in {stats.requests} request(s), {stats.cached} answered from the cache, "
        f"{stats.failed} not reviewed."
    )


@app.command(name="baseline")
def baseline_command(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Configuration files whose servers to record. Used with --connect.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    tools: Annotated[
        list[Path] | None,
        typer.Option(
            "--tools",
            help="Saved tool list of a server to record. Repeatable.",
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
    connect: Annotated[
        bool,
        typer.Option(
            "--connect",
            help="Start or contact each configured server and record the tools it advertises. "
            "This runs the commands in your configuration.",
        ),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds to wait for each server with --connect.", min=1),
    ] = DEFAULT_TIMEOUT,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Where to write the baseline.", dir_okay=False),
    ] = Path(".foretaster-baseline.json"),
) -> None:
    """Record the tool definitions servers advertise now, for later comparison.

    Review the tools first: a baseline says "this is what I approved". Only
    digests are stored, so the file is safe to commit. Nothing is written if any
    source could not be read, because a partial baseline would be misleading.
    """
    gathered = _gather(paths, tools, project_dir, connect, timeout)
    problems = [f"{failure.candidate.path}: {failure.reason}" for failure in gathered.failures]
    problems += [f"server {failure.server}: {failure.reason}" for failure in gathered.unreachable]
    if not gathered.inventories and not problems:
        problems.append("no tool definitions to record; pass --tools or --connect")
    if problems:
        for problem in problems:
            typer.echo(f"Error: {problem}", err=True)
        raise typer.Exit(EXIT_INCOMPLETE)
    recorded = build_baseline(gathered.inventories)
    output.write_text(dump_baseline(recorded), encoding="utf-8")
    count = sum(len(server.tools) for server in recorded.servers.values())
    typer.echo(f"Recorded {count} tool(s) of {len(recorded.servers)} server(s) in {output}")


class _Gathered(NamedTuple):
    configs: list[AgentConfig]
    failures: list[LoadFailure]
    inventories: list[ServerInventory]
    unreachable: tuple[ConnectionFailure, ...]


def _gather(
    paths: list[Path] | None,
    tools: list[Path] | None,
    project_dir: Path,
    connect: bool,
    timeout: float,
) -> _Gathered:
    configs, failures = _load(paths, project_dir, discover_all=not paths and not tools)
    inventories = _load_manifests(tools or [], failures)
    unreachable: tuple[ConnectionFailure, ...] = ()
    if connect:
        try:
            live = collect(configs, timeout=timeout)
        except ConnectUnavailableError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(EXIT_INCOMPLETE) from exc
        inventories.extend(live.inventories)
        unreachable = live.failures
    return _Gathered(configs, failures, inventories, unreachable)


@app.command(name="rules")
def rules_command() -> None:
    """List the built-in rules."""
    table = Table(title="Rules")
    for column in ("ID", "Severity", "Title", "Reference"):
        table.add_column(column)
    for rule in (*ALL_RULES, *OPTIONAL_RULES):
        meta = rule.meta
        title = meta.title + (" (only with --llm)" if rule in OPTIONAL_RULES else "")
        table.add_row(meta.id, meta.severity.value, title, "\n".join(meta.references) or "-")
    Console().print(table)


def _load_manifests(paths: list[Path], failures: list[LoadFailure]) -> list[ServerInventory]:
    inventories: list[ServerInventory] = []
    for path in paths:
        try:
            inventories.extend(load_tool_manifest(path))
        except ConfigLoadError as exc:
            failures.append(LoadFailure(Candidate(Client.GENERIC, Scope.USER, path), exc.reason))
    return inventories


def _load(
    paths: list[Path] | None, project_dir: Path, *, discover_all: bool
) -> tuple[list[AgentConfig], list[LoadFailure]]:
    if discover_all:
        result = discover(cwd=project_dir)
        return list(result.configs), list(result.failures)
    configs: list[AgentConfig] = []
    failures: list[LoadFailure] = []
    for path in paths or []:
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
