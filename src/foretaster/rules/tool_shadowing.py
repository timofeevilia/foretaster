import re
from collections.abc import Iterator

from foretaster.models import Finding, Severity
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget
from foretaster.textscan import normalise, snippet

_OTHER_TOOLS = re.compile(
    r"\b(?:when(?:ever)?|before|after|instead\s+of|every\s+time|each\s+time|always|never)\b"
    r"[^.]{0,60}\b(?:any|all|other|another|every)\s+(?:mcp\s+)?(?:tools?|servers?)\b"
    r"|\bthis\s+(?:tool|server)\b[^.]{0,40}"
    r"\b(?:overrides?|takes?\s+(?:precedence|priority)|replaces?|supersedes?)\b",
    re.IGNORECASE,
)
_MIN_NAME_LENGTH = 5


class ToolShadowing(Rule):
    meta = RuleMeta(
        id="FT-T006",
        title="Tool text tries to control other tools",
        severity=Severity.HIGH,
        description=(
            "The text talks about tools that belong to a different server, or sets rules "
            "for tools in general. A server should describe only its own tools. This "
            "pattern, called tool shadowing, lets a harmless-looking server change how "
            "the model uses a trusted one, for example by redirecting every e-mail."
        ),
        remediation=(
            "Do not run this server next to servers that handle anything sensitive, or remove it."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP06"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        owners: dict[str, set[str]] = {}
        for inventory in target.inventories:
            for tool in inventory.tools:
                owners.setdefault(tool.name, set()).add(inventory.server)

        for item in target.texts():
            text = normalise(item.text)
            foreign = sorted(
                name
                for name, servers in owners.items()
                if item.inventory.server not in servers and _distinctive(name)
            )
            named = next(
                (
                    (name, match)
                    for name in foreign
                    if (match := re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text))
                ),
                None,
            )
            if named:
                name, match = named
                other = ", ".join(sorted(owners[name]))
                yield self.text_finding(
                    item,
                    f"The {item.label} mentions the tool {name!r}, which belongs to "
                    f"another server ({other}).",
                    evidence=snippet(text, match.start(), match.end()),
                )
                continue
            generic = _OTHER_TOOLS.search(text)
            if generic:
                yield self.text_finding(
                    item,
                    f"The {item.label} sets rules for tools it does not own.",
                    evidence=snippet(text, generic.start(), generic.end()),
                    severity=Severity.MEDIUM,
                )


def _distinctive(name: str) -> bool:
    """Skip names that are ordinary words and would match innocent prose."""
    return len(name) >= _MIN_NAME_LENGTH and (
        "_" in name or "-" in name or name != name.lower() or len(name) >= 12
    )
