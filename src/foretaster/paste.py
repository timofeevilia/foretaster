"""Scan text that somebody pasted, without knowing what kind of file it is.

This is the entry point for places with no filesystem to speak of, such as the
in-browser demo. The text is either an agent configuration or a saved tool list;
which one is decided from its shape.
"""

import json
from pathlib import Path

from foretaster.config_loader import ConfigLoadError, parse_config
from foretaster.discovery import Candidate, LoadFailure
from foretaster.engine import run_rules
from foretaster.jsonc import strip_jsonc
from foretaster.models import AgentConfig, Client, Scope, ServerInventory
from foretaster.report import Report, build_report
from foretaster.rules import ScanTarget
from foretaster.tool_manifest import parse_tool_manifest

MAX_PASTE_CHARACTERS = 2_000_000
PASTED = Path("pasted.json")


def looks_like_tool_list(text: str) -> bool:
    """True when the text is a ``tools/list`` result rather than an agent configuration."""
    try:
        data = json.loads(strip_jsonc(text))
    except (json.JSONDecodeError, RecursionError):
        return False
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("tools"), list):
        return True
    servers = data.get("servers")
    return isinstance(servers, dict) and any(
        isinstance(entry, dict) and isinstance(entry.get("tools"), list)
        for entry in servers.values()
    )


def scan_pasted(text: str) -> Report:
    """Scan pasted text and return a report; problems with the text become report errors."""
    configs: list[AgentConfig] = []
    inventories: list[ServerInventory] = []
    failures: list[LoadFailure] = []
    try:
        if len(text) > MAX_PASTE_CHARACTERS:
            raise ConfigLoadError(PASTED, f"text is longer than {MAX_PASTE_CHARACTERS} characters")
        if looks_like_tool_list(text):
            inventories = parse_tool_manifest(text, path=PASTED)
        else:
            configs = [parse_config(text, path=PASTED)]
    except ConfigLoadError as exc:
        failures.append(LoadFailure(Candidate(Client.GENERIC, Scope.USER, PASTED), exc.reason))
    target = ScanTarget(tuple(configs), tuple(inventories))
    return build_report(configs, failures, run_rules(target), inventories)
