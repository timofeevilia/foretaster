"""Command-line interface."""

from typing import Annotated

import typer

from foretaster import __version__

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
