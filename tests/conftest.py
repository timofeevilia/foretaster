import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from foretaster.config_loader import parse_config
from foretaster.models import Finding, Location, ServerInventory
from foretaster.rules import Rule, ScanTarget
from foretaster.tool_manifest import inventory_from_tools

Check = Callable[[type[Rule], dict[str, Any]], list[Finding]]


def make_target(servers: dict[str, Any]) -> ScanTarget:
    text = json.dumps({"mcpServers": servers}, indent=2)
    return ScanTarget((parse_config(text, path=Path("mcp.json")),))


@pytest.fixture
def check() -> Check:
    """Run one rule over a config made of the given server entries."""

    def run(rule: type[Rule], servers: dict[str, Any]) -> list[Finding]:
        return list(rule().check(make_target(servers)))

    return run


def make_inventory(
    tools: list[dict[str, Any]], server: str = "srv", instructions: str | None = None
) -> ServerInventory:
    origin = Location(path=Path("tools.json"))
    return inventory_from_tools(server, origin, tools, instructions)


def tool(description: str = "", name: str = "do_thing", **properties: Any) -> dict[str, Any]:
    """A tool entry as it appears in a tools/list result."""
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties},
    }


def scan_text(rule: type[Rule], description: str, **properties: Any) -> list[Finding]:
    """Run one rule over a server that has a single tool with this description."""
    inventory = make_inventory([tool(description, **properties)])
    return list(rule().check(ScanTarget((), (inventory,))))
