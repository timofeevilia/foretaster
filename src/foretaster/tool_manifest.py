"""Load tool manifests: saved copies of what an MCP server advertises.

A manifest lets tool descriptions be scanned without starting the server.
Accepted shapes:

* a ``tools/list`` result: ``{"tools": [...]}``, optionally with
  ``instructions`` and ``serverInfo``;
* the same wrapped in a JSON-RPC response: ``{"result": {"tools": [...]}}``;
* several servers at once: ``{"servers": {"name": {"tools": [...]}}}``.
"""

import json
from pathlib import Path
from typing import Any

from foretaster.config_loader import ConfigLoadError, read_text
from foretaster.models import Location, ServerInventory, ToolDefinition


def load_tool_manifest(path: Path) -> list[ServerInventory]:
    """Read a manifest file. Raises :class:`ConfigLoadError` when it is unusable."""
    try:
        data = json.loads(read_text(path))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ConfigLoadError(path, f"invalid JSON: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]
    if not isinstance(data, dict):
        raise ConfigLoadError(path, "top-level value is not a JSON object")

    servers = data.get("servers")
    if isinstance(servers, dict) and "tools" not in data:
        return [
            _inventory(path, str(name), entry, f"/servers/{_escape(str(name))}")
            for name, entry in servers.items()
        ]
    info = data.get("serverInfo")
    name = info.get("name") if isinstance(info, dict) else None
    return [_inventory(path, name if isinstance(name, str) and name else path.stem, data, "")]


def inventory_from_tools(
    server: str,
    origin: Location,
    tools: list[dict[str, Any]],
    instructions: str | None,
    *,
    open_remote: bool = False,
) -> ServerInventory:
    """Build an inventory from already-parsed ``tools/list`` entries."""
    return ServerInventory(
        server=server,
        origin=origin,
        instructions=instructions,
        open_remote=open_remote,
        tools=tuple(_tool(origin.path, tool, index) for index, tool in enumerate(tools)),
    )


def _inventory(path: Path, server: str, entry: object, pointer: str) -> ServerInventory:
    if not isinstance(entry, dict):
        raise ConfigLoadError(path, f"server {server!r} is not an object")
    tools = entry.get("tools", [])
    if not isinstance(tools, list):
        raise ConfigLoadError(path, f"'tools' of server {server!r} is not an array")
    instructions = entry.get("instructions")
    return inventory_from_tools(
        server,
        Location(path=path, pointer=pointer),
        tools,
        instructions if isinstance(instructions, str) else None,
    )


def _tool(path: Path, entry: object, index: int) -> ToolDefinition:
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        raise ConfigLoadError(path, f"tool #{index} is not an object with a string 'name'")
    description = entry.get("description")
    schema = entry.get("inputSchema", entry.get("input_schema"))
    return ToolDefinition(
        name=entry["name"],
        description=description if isinstance(description, str) else "",
        input_schema=schema if isinstance(schema, dict) else {},
    )


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")
