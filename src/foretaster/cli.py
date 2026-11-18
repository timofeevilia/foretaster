"""Command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from foretaster import __version__
from foretaster.discovery import DiscoveryResult, discover

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
