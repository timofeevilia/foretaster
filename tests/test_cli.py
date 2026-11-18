import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from foretaster import __version__
from foretaster.cli import app

runner = CliRunner()

SECRET = "sk-live-do-not-print"  # noqa: S105 - fake value asserting redaction


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated home directory that discovery treats as the real one."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("APPDATA", str(home / ".config"))
    monkeypatch.setenv("COLUMNS", "200")
    return tmp_path


def write_project(root: Path) -> Path:
    project = root / "project"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor/mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {"command": "npx", "args": [SECRET], "env": {"KEY": SECRET}},
                    "off": {"url": f"https://example.com/?key={SECRET}", "disabled": True},
                    "broken": "nope",
                }
            }
        )
    )
    (project / ".mcp.json").write_text("{ not json")
    return project


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


def test_discover_nothing_found(machine: Path) -> None:
    result = runner.invoke(app, ["discover", "--project-dir", str(machine)])
    assert result.exit_code == 0
    assert "No agent configuration files found." in result.output


def test_discover_table(machine: Path) -> None:
    project = write_project(machine)
    result = runner.invoke(app, ["discover", "--project-dir", str(project)])
    assert result.exit_code == 0
    assert "cursor" in result.output
    assert "files, off (disabled)" in result.output
    assert "Could not parse" in result.output
    assert SECRET not in result.output


def test_discover_only_failures(machine: Path) -> None:
    (machine / ".mcp.json").write_text("[]")
    result = runner.invoke(app, ["discover", "--project-dir", str(machine)])
    assert result.exit_code == 0
    assert "Could not parse" in result.output
    assert "Agent configurations" not in result.output


def test_discover_json(machine: Path) -> None:
    project = write_project(machine)
    result = runner.invoke(app, ["discover", "--project-dir", str(project), "--json"])
    assert result.exit_code == 0
    assert SECRET not in result.output
    payload = json.loads(result.output)
    (config,) = payload["configs"]
    assert config["client"] == "cursor"
    assert config["scope"] == "project"
    assert config["servers"] == [
        {"name": "files", "transport": "stdio", "enabled": True, "line": 1},
        {"name": "off", "transport": "http", "enabled": False, "line": 1},
    ]
    assert config["problems"] == [
        {"pointer": "/mcpServers/broken", "message": "server entry is not an object"}
    ]
    (failure,) = payload["failures"]
    assert failure["client"] == "claude-code"
    assert "invalid JSON" in failure["reason"]


def test_discover_rejects_missing_directory(machine: Path) -> None:
    result = runner.invoke(app, ["discover", "--project-dir", str(machine / "absent")])
    assert result.exit_code != 0
