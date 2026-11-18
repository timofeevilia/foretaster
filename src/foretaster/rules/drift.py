"""Rules about tools changing over time or clashing across servers."""

import re
from collections.abc import Iterator

from foretaster.baseline import digest_text, digest_tool
from foretaster.models import Finding, ServerInventory, Severity, ToolDefinition
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget, TextItem


class ChangedSinceBaseline(Rule):
    meta = RuleMeta(
        id="FT-D001",
        title="Tool definition changed since the baseline",
        severity=Severity.HIGH,
        description=(
            "What the server advertises differs from what was recorded when it was "
            "reviewed. A server can pass review with harmless descriptions and replace "
            "them afterwards; clients rarely ask for approval again. This is known as a "
            "rug pull."
        ),
        remediation=(
            "Review the current definition. If the change is expected, record a new "
            "baseline with `foretaster baseline`; otherwise disconnect the server."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP04"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        if target.baseline is None:
            return
        for inventory in target.inventories:
            base = inventory.origin.pointer
            known = target.baseline.servers.get(inventory.server)
            if known is None:
                yield self.text_finding(
                    TextItem(inventory, None, base, "server", ""),
                    "Server is not in the baseline, so its tools were never reviewed.",
                    severity=Severity.LOW,
                )
                continue

            current = digest_text(inventory.instructions) if inventory.instructions else None
            if current != known.instructions:
                yield self.text_finding(
                    TextItem(inventory, None, f"{base}/instructions", "server instructions", ""),
                    "Server instructions changed since the baseline.",
                    evidence=_change(known.instructions, current),
                )
            for index, tool in enumerate(inventory.tools):
                item = TextItem(inventory, tool, f"{base}/tools/{index}", "tool", "")
                recorded = known.tools.get(tool.name)
                digest = digest_tool(tool)
                if recorded is None:
                    yield self.text_finding(
                        item,
                        "Tool was added after the baseline was recorded.",
                        severity=Severity.MEDIUM,
                    )
                elif recorded != digest:
                    yield self.text_finding(
                        item,
                        "Tool description or parameters changed since the baseline.",
                        evidence=_change(recorded, digest),
                    )
            present = {tool.name for tool in inventory.tools}
            for name in sorted(set(known.tools) - present):
                yield self.text_finding(
                    TextItem(inventory, None, f"{base}/tools", "tool list", ""),
                    f"Tool {name!r} from the baseline is no longer advertised.",
                    severity=Severity.LOW,
                )


def _change(before: str | None, after: str | None) -> str:
    def short(digest: str | None) -> str:
        return f"sha256 {digest[:12]}" if digest else "absent"

    return f"{short(before)} -> {short(after)}"


class ToolNameCollision(Rule):
    meta = RuleMeta(
        id="FT-D002",
        title="Two servers advertise a tool with the same name",
        severity=Severity.MEDIUM,
        description=(
            "Several connected servers offer a tool under the same name, or names that "
            "differ only in case and separators. The model can call the wrong one, and a "
            "malicious server can take over calls meant for a trusted tool by copying "
            "its name."
        ),
        remediation=(
            "Check that both servers are intended. Remove the one you do not need, or "
            "use a client that prefixes tool names with the server name."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP09"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        seen: dict[str, list[tuple[ServerInventory, int, ToolDefinition]]] = {}
        for inventory in target.inventories:
            for index, tool in enumerate(inventory.tools):
                key = re.sub(r"[^a-z0-9]", "", tool.name.lower())
                if key:
                    seen.setdefault(key, []).append((inventory, index, tool))
        for entries in seen.values():
            servers = {inventory.server for inventory, _, _ in entries}
            if len(servers) < 2:
                continue
            for inventory, index, tool in entries:
                others = ", ".join(sorted(servers - {inventory.server}))
                pointer = f"{inventory.origin.pointer}/tools/{index}/name"
                yield self.text_finding(
                    TextItem(inventory, tool, pointer, "tool name", tool.name),
                    f"Tool name is also used by another server ({others}).",
                    evidence=tool.name,
                )
