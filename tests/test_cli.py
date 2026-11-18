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
                    "files": {"command": "npx", "args": ["pkg", SECRET], "env": {"KEY": SECRET}},
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


CLEAN = {"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git==2025.1.14"]}}}
MEDIUM_ONLY = {"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}
RISKY = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "some-server@1.0.0", "/"]},
        "hub": {"command": "x", "env": {"GITHUB_TOKEN": "ghp_" + "a1B2" * 9}},
    }
}


def write_config(root: Path, data: object, name: str = "mcp.json") -> str:
    path = root / name
    path.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))
    return str(path)


def test_scan_clean_file(machine: Path) -> None:
    result = runner.invoke(app, ["scan", write_config(machine, CLEAN)])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_scan_reports_findings_without_leaking_secrets(machine: Path) -> None:
    result = runner.invoke(app, ["scan", write_config(machine, RISKY)])
    assert result.exit_code == 1
    assert "FT-C006" in result.output
    assert "FT-C001" in result.output
    assert "ghp_***" in result.output
    assert "a1B2a1B2" not in result.output


@pytest.mark.parametrize(
    ("fail_on", "exit_code"),
    [("critical", 0), ("high", 0), ("medium", 1), ("info", 1), ("never", 0)],
)
def test_scan_fail_on_threshold(machine: Path, fail_on: str, exit_code: int) -> None:
    path = write_config(machine, MEDIUM_ONLY)
    result = runner.invoke(app, ["scan", path, "--fail-on", fail_on])
    assert result.exit_code == exit_code


def test_scan_unparseable_file_is_incomplete(machine: Path) -> None:
    good = write_config(machine, CLEAN)
    bad = write_config(machine, "{ not json", "bad.json")
    result = runner.invoke(app, ["scan", good, bad, "--fail-on", "never"])
    assert result.exit_code == 2
    assert "Could not parse" in result.output
    assert "the scan is incomplete" in result.output


def test_scan_json_output(machine: Path) -> None:
    result = runner.invoke(app, ["scan", write_config(machine, RISKY), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["summary"]["servers"] == 2
    assert payload["summary"]["findings"]["high"] == 2
    assert [finding["rule_id"] for finding in payload["findings"]] == ["FT-C006", "FT-C001"]
    assert "a1B2a1B2" not in result.output


@pytest.mark.parametrize("output_format", ["json", "console"])
def test_scan_output_file(machine: Path, output_format: str) -> None:
    target = machine / "report.out"
    result = runner.invoke(
        app,
        ["scan", write_config(machine, RISKY), "--format", output_format, "-o", str(target)],
    )
    assert result.exit_code == 1
    assert result.output == ""
    text = target.read_text()
    assert "FT-C006" in text
    assert "\x1b[" not in text
    if output_format == "json":
        assert json.loads(text)["schema_version"] == "1"


def test_scan_discovers_project_configs(machine: Path) -> None:
    project = write_project(machine)
    result = runner.invoke(app, ["scan", "--project-dir", str(project), "--format", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["summary"]["configs"] == 1
    assert {finding["rule_id"] for finding in payload["findings"]} >= {"FT-C000", "FT-C001"}
    assert payload["errors"][0]["kind"] == "config"
    assert SECRET not in result.output


def test_scan_rejects_missing_file(machine: Path) -> None:
    result = runner.invoke(app, ["scan", str(machine / "absent.json")])
    assert result.exit_code == 2
    assert "Scanned" not in result.output


def test_rules_command() -> None:
    result = runner.invoke(app, ["rules"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    for rule_id in ("FT-C000", "FT-C001", "FT-C006"):
        assert rule_id in result.output
