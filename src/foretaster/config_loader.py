"""Parse agent configuration files into :class:`AgentConfig`.

Parsing is strictly passive: nothing is executed, no environment variable is
expanded and no path mentioned inside a file is opened. Malformed entries are
reported as :class:`ConfigProblem` instead of aborting, because a file that
confuses the scanner is exactly the file worth reporting on.
"""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from foretaster.jsonc import strip_jsonc
from foretaster.models import (
    AgentConfig,
    Client,
    ConfigProblem,
    ProblemKind,
    Scope,
    ServerDefinition,
    Transport,
)

MAX_CONFIG_BYTES = 5 * 1024 * 1024

_TRANSPORT_ALIASES = {
    "stdio": Transport.STDIO,
    "http": Transport.HTTP,
    "streamable-http": Transport.HTTP,
    "streamable_http": Transport.HTTP,
    "streamablehttp": Transport.HTTP,
    "sse": Transport.SSE,
}
_URL_KEYS = ("url", "serverUrl", "httpUrl")


class ConfigLoadError(Exception):
    """A configuration file could not be read or is not a JSON object."""

    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


def load_config(
    path: Path, *, client: Client | None = None, scope: Scope = Scope.USER
) -> AgentConfig:
    """Read and parse one configuration file.

    ``client`` is guessed from the file name and contents when omitted.
    """
    return parse_config(read_text(path), path=path, client=client, scope=scope)


def parse_config(
    text: str, *, path: Path, client: Client | None = None, scope: Scope = Scope.USER
) -> AgentConfig:
    """Parse configuration text. ``path`` is recorded but never opened."""
    problems: list[ConfigProblem] = []

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        # Parsers disagree on which duplicate wins, so the client may see a
        # different server than a reviewer does.
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                problems.append(
                    ConfigProblem(
                        pointer="",
                        kind=ProblemKind.DUPLICATE_KEY,
                        message=f"duplicate key {key!r}: clients may disagree on which value wins",
                    )
                )
            result[key] = value
        return result

    try:
        data = json.loads(strip_jsonc(text), object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ConfigLoadError(path, f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigLoadError(path, "top-level value is not a JSON object")

    client = client or guess_client(path, data)
    servers: list[ServerDefinition] = []
    for pointer, container in _server_containers(data, client):
        if not isinstance(container, dict):
            problems.append(ConfigProblem(pointer=pointer, message="expected an object of servers"))
            continue
        for name, entry in container.items():
            entry_pointer = f"{pointer}/{_escape_pointer(name)}"
            if not isinstance(entry, dict):
                problems.append(
                    ConfigProblem(pointer=entry_pointer, message="server entry is not an object")
                )
                continue
            servers.append(_parse_server(name, entry, entry_pointer, text, problems))

    return AgentConfig(
        client=client,
        scope=scope,
        path=path,
        servers=tuple(servers),
        problems=tuple(problems),
    )


def guess_client(path: Path, data: dict[str, Any]) -> Client:
    """Infer the client from the file name, falling back to the file's shape."""
    name = path.name
    parent = path.parent.name
    if name == "claude_desktop_config.json":
        return Client.CLAUDE_DESKTOP
    if name in {".claude.json", ".mcp.json"}:
        return Client.CLAUDE_CODE
    if name == "mcp_config.json":
        return Client.WINDSURF
    if parent == ".cursor":
        return Client.CURSOR
    if parent == ".vscode" or ("servers" in data and "mcpServers" not in data):
        return Client.VSCODE
    return Client.GENERIC


def read_text(path: Path) -> str:
    """Read a UTF-8 file, refusing anything that is not a regular file of sane size."""
    try:
        if not path.is_file():
            raise ConfigLoadError(path, "not a regular file")
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigLoadError(path, f"file is {size} bytes, limit is {MAX_CONFIG_BYTES}")
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigLoadError(path, f"cannot read file: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigLoadError(path, "file is not valid UTF-8") from exc


def _server_containers(data: dict[str, Any], client: Client) -> Iterator[tuple[str, Any]]:
    """Yield ``(pointer, value)`` for every place servers may be declared."""
    if "mcpServers" in data:
        yield "/mcpServers", data["mcpServers"]
    if "servers" in data:
        yield "/servers", data["servers"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and "servers" in mcp:
        yield "/mcp/servers", mcp["servers"]
    projects = data.get("projects")
    if client is Client.CLAUDE_CODE and isinstance(projects, dict):
        for project_path, project in projects.items():
            if isinstance(project, dict) and "mcpServers" in project:
                pointer = f"/projects/{_escape_pointer(project_path)}/mcpServers"
                yield pointer, project["mcpServers"]


def _parse_server(
    name: str,
    entry: dict[str, Any],
    pointer: str,
    text: str,
    problems: list[ConfigProblem],
) -> ServerDefinition:
    command = _optional_str(entry, "command", pointer, problems)
    url = next(
        (value for key in _URL_KEYS if (value := _optional_str(entry, key, pointer, problems))),
        None,
    )
    return ServerDefinition(
        name=name,
        transport=_transport(entry, command, url, pointer, problems),
        command=command,
        args=_str_list(entry.get("args"), f"{pointer}/args", problems),
        env=_str_map(entry.get("env"), f"{pointer}/env", problems),
        url=url,
        headers=_str_map(entry.get("headers"), f"{pointer}/headers", problems),
        enabled=entry.get("disabled") is not True and entry.get("enabled") is not False,
        pointer=pointer,
        line=_find_line(text, name),
        raw=entry,
    )


def _transport(
    entry: dict[str, Any],
    command: str | None,
    url: str | None,
    pointer: str,
    problems: list[ConfigProblem],
) -> Transport:
    declared = entry.get("type", entry.get("transport"))
    if isinstance(declared, str):
        transport = _TRANSPORT_ALIASES.get(declared.lower())
        if transport is not None:
            return transport
        problems.append(
            ConfigProblem(pointer=f"{pointer}/type", message=f"unknown transport {declared!r}")
        )
        return Transport.UNKNOWN
    if command is not None:
        return Transport.STDIO
    if url is not None:
        return Transport.HTTP
    problems.append(
        ConfigProblem(pointer=pointer, message="server has neither a command nor a URL")
    )
    return Transport.UNKNOWN


def _optional_str(
    entry: dict[str, Any], key: str, pointer: str, problems: list[ConfigProblem]
) -> str | None:
    value = entry.get(key)
    if value is None or isinstance(value, str):
        return value
    problems.append(ConfigProblem(pointer=f"{pointer}/{key}", message="expected a string"))
    return None


def _scalar_to_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return None


def _str_list(value: object, pointer: str, problems: list[ConfigProblem]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        problems.append(ConfigProblem(pointer=pointer, message="expected an array"))
        return ()
    items: list[str] = []
    for index, item in enumerate(value):
        text = _scalar_to_str(item)
        if text is None:
            problems.append(
                ConfigProblem(pointer=f"{pointer}/{index}", message="expected a string")
            )
        else:
            items.append(text)
    return tuple(items)


def _str_map(value: object, pointer: str, problems: list[ConfigProblem]) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        problems.append(ConfigProblem(pointer=pointer, message="expected an object"))
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        text = _scalar_to_str(item)
        if text is None:
            problems.append(
                ConfigProblem(
                    pointer=f"{pointer}/{_escape_pointer(key)}", message="expected a string"
                )
            )
        else:
            result[key] = text
    return result


def _escape_pointer(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _find_line(text: str, key: str) -> int | None:
    """Best-effort line of the first occurrence of ``key`` used as an object key."""
    match = re.search(re.escape(json.dumps(key, ensure_ascii=False)) + r"\s*:", text)
    if match is None:
        return None
    return text.count("\n", 0, match.start()) + 1
