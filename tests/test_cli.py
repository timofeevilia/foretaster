import subprocess
import sys

from typer.testing import CliRunner

from foretaster import __version__
from foretaster.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"foretaster {__version__}"


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"foretaster {__version__}"


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_module_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "foretaster", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == f"foretaster {__version__}"
