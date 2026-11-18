"""Rules about what a set of servers can do together."""

import re
from collections.abc import Iterator, Sequence
from pathlib import Path

from foretaster.models import Finding, ServerDefinition, Severity, ToolDefinition
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget, TextItem


class OpenRemoteServer(Rule):
    meta = RuleMeta(
        id="FT-X001",
        title="Remote server answers without authentication",
        severity=Severity.MEDIUM,
        description=(
            "The scanner received the server's tool list over the network without "
            "sending any credential. Anyone who can reach the address can use the same "
            "tools. That is acceptable for a public read-only service and a serious "
            "problem for anything that touches private data or performs actions."
        ),
        remediation=(
            "Confirm the server is meant to be public. Otherwise put it behind "
            "authentication before connecting an agent to it."
        ),
        references=(OWASP_MCP["MCP07"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for inventory in target.inventories:
            if inventory.open_remote:
                yield self.text_finding(
                    TextItem(inventory, None, inventory.origin.pointer, "server", ""),
                    f"Server listed {len(inventory.tools)} tool(s) to an unauthenticated client.",
                )


_OBJECT_GAP = r"\s+(?:\w+\s+){0,3}"
_CAPABILITIES: dict[str, re.Pattern[str]] = {
    "private data": re.compile(
        rf"\b(?:read|get|list|search|query|open|download|export)\w*{_OBJECT_GAP}"
        r"(?:files?|director(?:y|ies)|folders?|documents?|emails?|inbox|mail|notes?|databases?"
        r"|tables?|rows?|records?|calendars?|contacts?|secrets?|credentials?|drive"
        r"|private\s+repositor(?:y|ies)|chat\s+history|channel\s+history)\b"
        r"|\bsql\b|\bfile\s*system\b"
    ),
    "untrusted content": re.compile(
        rf"\b(?:fetch|browse|scrape|crawl|navigate|visit|open|load)\w*{_OBJECT_GAP}"
        r"(?:urls?|web\s*pages?|websites?|pages?|links?|sites?)\b"
        r"|\bweb\s*search\b|\bsearch\w*\s+the\s+(?:web|internet)\b"
        rf"|\b(?:read|get|list|search)\w*{_OBJECT_GAP}"
        r"(?:issues?|pull\s+requests?|comments?|reviews?|emails?|inbox|tickets?|feeds?)\b"
    ),
    "a way to send data out": re.compile(
        rf"\b(?:send|post|publish|upload|create|add|write|push|forward|reply)\w*{_OBJECT_GAP}"
        r"(?:emails?|mail|messages?|comments?|issues?|pull\s+requests?|webhooks?|requests?"
        r"|tweets?|posts?|gists?)\b"
        r"|\bhttp\s*(?:request|post|get)\b"
        rf"|\b(?:fetch|request|browse|navigate|visit)\w*{_OBJECT_GAP}(?:urls?|web\s*pages?)\b"
    ),
}
_BY_PACKAGE: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (
        re.compile(r"filesystem|postgres|sqlite|mysql|mongo|gdrive|google-drive|obsidian|memory"),
        ("private data",),
    ),
    (
        re.compile(r"fetch|puppeteer|playwright|browser|firecrawl"),
        ("untrusted content", "a way to send data out"),
    ),
    (re.compile(r"brave-search|tavily|exa-mcp|web-search"), ("untrusted content",)),
    (
        re.compile(r"github|gitlab|gmail|outlook|slack|notion"),
        ("private data", "untrusted content", "a way to send data out"),
    ),
)


class LethalTrifecta(Rule):
    meta = RuleMeta(
        id="FT-X002",
        title="One agent combines private data, untrusted content and a way out",
        severity=Severity.MEDIUM,
        description=(
            "The servers connected to this agent together let it read private data, "
            "take in content written by strangers, and send data to the outside. With "
            "all three, one injected instruction in a web page or an issue is enough to "
            "make the agent read your data and ship it away. No single server is at "
            "fault; the combination is."
        ),
        remediation=(
            "Remove one of the three abilities from this agent, or split the work across "
            "agents so that none holds all three."
        ),
        references=(OWASP_MCP["MCP10"], OWASP_MCP["MCP02"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        config_paths = {config.path for config in target.configs}
        described = {
            (inventory.origin.path, inventory.server): inventory for inventory in target.inventories
        }
        groups: dict[Path | None, dict[str, str]] = {}

        for config, server in target.servers():
            if not server.enabled:
                continue
            inventory = described.get((config.path, server.name))
            found = groups.setdefault(config.path, {})
            if inventory is None:
                for capability in _from_package(server):
                    found.setdefault(capability, f"server {server.name!r}")
            else:
                _from_tools(inventory.server, inventory.tools, found)
        for inventory in target.inventories:
            if inventory.origin.path not in config_paths:
                _from_tools(inventory.server, inventory.tools, groups.setdefault(None, {}))

        manifest_path = next(
            (i.origin.path for i in target.inventories if i.origin.path not in config_paths), None
        )
        for path, found in groups.items():
            if len(found) < len(_CAPABILITIES):
                continue
            location = path or manifest_path
            if location is None:  # pragma: no cover - a group without a path cannot exist
                continue
            yield self.make(
                location,
                "The connected servers together provide all three abilities.",
                evidence="; ".join(f"{name}: {found[name]}" for name in _CAPABILITIES),
            )


def _from_tools(server: str, tools: Sequence[ToolDefinition], found: dict[str, str]) -> None:
    for tool in tools:
        text = _words(f"{tool.name} {tool.description}")
        for capability, pattern in _CAPABILITIES.items():
            if capability not in found and pattern.search(text):
                found[capability] = f"tool {tool.name!r} of server {server!r}"


def _from_package(server: ServerDefinition) -> set[str]:
    line = " ".join((server.command or "", *server.args, server.url or "")).lower()
    return {
        capability
        for pattern, capabilities in _BY_PACKAGE
        if pattern.search(line)
        for capability in capabilities
    }


def _words(text: str) -> str:
    """Split identifiers such as ``read_file`` or ``sendEmail`` into words."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.sub(r"[_\-./]+", " ", text).lower()
