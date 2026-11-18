"""Locate agent configuration files on the local machine."""

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from foretaster.config_loader import ConfigLoadError, load_config
from foretaster.models import AgentConfig, Client, Scope


class Candidate(NamedTuple):
    """A place where a client is known to keep MCP configuration."""

    client: Client
    scope: Scope
    path: Path


class LoadFailure(NamedTuple):
    """A configuration file that exists but could not be parsed."""

    candidate: Candidate
    reason: str


class DiscoveryResult(NamedTuple):
    configs: tuple[AgentConfig, ...]
    failures: tuple[LoadFailure, ...]


def candidate_paths(
    *, platform: str, home: Path, cwd: Path, env: Mapping[str, str]
) -> list[Candidate]:
    """List every known configuration location for the given platform.

    Paths are returned whether or not they exist.
    """
    if platform == "darwin":
        app_config = home / "Library" / "Application Support"
    elif platform == "win32":
        app_config = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
    else:
        xdg = env.get("XDG_CONFIG_HOME")
        app_config = Path(xdg) if xdg else home / ".config"

    user, project = Scope.USER, Scope.PROJECT
    return [
        Candidate(
            Client.CLAUDE_DESKTOP, user, app_config / "Claude" / "claude_desktop_config.json"
        ),
        Candidate(Client.CLAUDE_CODE, user, home / ".claude.json"),
        Candidate(Client.CLAUDE_CODE, project, cwd / ".mcp.json"),
        Candidate(Client.CURSOR, user, home / ".cursor" / "mcp.json"),
        Candidate(Client.CURSOR, project, cwd / ".cursor" / "mcp.json"),
        Candidate(Client.VSCODE, user, app_config / "Code" / "User" / "mcp.json"),
        Candidate(Client.VSCODE, project, cwd / ".vscode" / "mcp.json"),
        Candidate(Client.WINDSURF, user, home / ".codeium" / "windsurf" / "mcp_config.json"),
    ]


def discover(
    *,
    platform: str | None = None,
    home: Path | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> DiscoveryResult:
    """Find and parse every agent configuration present on this machine."""
    candidates = candidate_paths(
        platform=platform or sys.platform,
        home=home or Path.home(),
        cwd=cwd or Path.cwd(),
        env=os.environ if env is None else env,
    )
    configs: list[AgentConfig] = []
    failures: list[LoadFailure] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate.path.exists():
            continue
        resolved = candidate.path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            configs.append(
                load_config(candidate.path, client=candidate.client, scope=candidate.scope)
            )
        except ConfigLoadError as exc:
            failures.append(LoadFailure(candidate, exc.reason))
    return DiscoveryResult(tuple(configs), tuple(failures))
