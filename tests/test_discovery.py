import json
from pathlib import Path

import pytest

from foretaster.discovery import candidate_paths, discover
from foretaster.models import Client, Scope

HOME = Path("/h")
CWD = Path("/w")


def paths(platform: str, env: dict[str, str] | None = None) -> dict[tuple[Client, Scope], Path]:
    candidates = candidate_paths(platform=platform, home=HOME, cwd=CWD, env=env or {})
    return {(c.client, c.scope): c.path for c in candidates}


def test_linux_locations() -> None:
    found = paths("linux")
    assert (
        found[Client.CLAUDE_DESKTOP, Scope.USER]
        == HOME / ".config/Claude/claude_desktop_config.json"
    )
    assert found[Client.VSCODE, Scope.USER] == HOME / ".config/Code/User/mcp.json"
    assert found[Client.CLAUDE_CODE, Scope.USER] == HOME / ".claude.json"
    assert found[Client.CLAUDE_CODE, Scope.PROJECT] == CWD / ".mcp.json"
    assert found[Client.CURSOR, Scope.USER] == HOME / ".cursor/mcp.json"
    assert found[Client.CURSOR, Scope.PROJECT] == CWD / ".cursor/mcp.json"
    assert found[Client.VSCODE, Scope.PROJECT] == CWD / ".vscode/mcp.json"
    assert found[Client.WINDSURF, Scope.USER] == HOME / ".codeium/windsurf/mcp_config.json"


def test_linux_respects_xdg_config_home() -> None:
    found = paths("linux", {"XDG_CONFIG_HOME": "/xdg"})
    assert found[Client.CLAUDE_DESKTOP, Scope.USER] == Path(
        "/xdg/Claude/claude_desktop_config.json"
    )


def test_macos_locations() -> None:
    found = paths("darwin")
    base = HOME / "Library/Application Support"
    assert found[Client.CLAUDE_DESKTOP, Scope.USER] == base / "Claude/claude_desktop_config.json"
    assert found[Client.VSCODE, Scope.USER] == base / "Code/User/mcp.json"


def test_windows_locations() -> None:
    with_appdata = paths("win32", {"APPDATA": "/appdata"})
    assert with_appdata[Client.CLAUDE_DESKTOP, Scope.USER] == Path(
        "/appdata/Claude/claude_desktop_config.json"
    )
    fallback = paths("win32")
    assert fallback[Client.CLAUDE_DESKTOP, Scope.USER] == (
        HOME / "AppData/Roaming/Claude/claude_desktop_config.json"
    )


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_discover_parses_existing_files(tmp_path: Path) -> None:
    home, cwd = tmp_path / "home", tmp_path / "work"
    write(home / ".cursor/mcp.json", json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    write(cwd / ".vscode/mcp.json", json.dumps({"servers": {"b": {"url": "https://x"}}}))
    write(cwd / ".mcp.json", "{ not json")

    result = discover(platform="linux", home=home, cwd=cwd, env={})

    assert [(c.client, c.scope) for c in result.configs] == [
        (Client.CURSOR, Scope.USER),
        (Client.VSCODE, Scope.PROJECT),
    ]
    (failure,) = result.failures
    assert failure.candidate.path == cwd / ".mcp.json"
    assert "invalid JSON" in failure.reason


def test_discover_reads_each_file_once(tmp_path: Path) -> None:
    write(tmp_path / ".cursor/mcp.json", "{}")
    result = discover(platform="linux", home=tmp_path, cwd=tmp_path, env={})
    assert len(result.configs) == 1
    assert result.configs[0].scope is Scope.USER


def test_discover_defaults_use_real_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    write(tmp_path / ".claude.json", "{}")
    result = discover()
    assert [c.client for c in result.configs] == [Client.CLAUDE_CODE]
