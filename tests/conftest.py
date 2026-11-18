import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from foretaster.config_loader import parse_config
from foretaster.models import Finding
from foretaster.rules import Rule, ScanTarget

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
