import re
from collections.abc import Iterator

from foretaster.models import Finding, Severity
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget, TextItem
from foretaster.textscan import normalise, parameters, snippet

_ALWAYS_SUSPICIOUS = re.compile(
    r"^(?:system_?prompt|conversation(?:_?history)?|chat_?(?:history|log)|full_?context"
    r"|(?:previous|prior|all)_?messages|message_?history|side_?note|exfil\w*)$",
    re.IGNORECASE,
)
_CATCH_ALL = frozenset(
    {
        "note",
        "notes",
        "context",
        "metadata",
        "extra",
        "debug",
        "feedback",
        "details",
        "info",
        "comment",
        "memo",
        "reason",
        "summary",
        "data",
        "payload",
        "annotation",
    }
)
_HARVEST = re.compile(
    r"\b(?:contents?\s+of|entire\s+(?:conversation|file|history)|full\s+(?:conversation|"
    r"history|file|contents?)|all\s+(?:previous\s+|prior\s+)?messages|api\s+keys?|credentials"
    r"|passwords?|secrets?|access\s+tokens?|private\s+keys?|environment\s+variables)\b",
    re.IGNORECASE,
)
_VERBS = r"pass|put|include|provide|send|add|place|supply|attach|append|copy|write|set|store|paste"


class ExfiltrationParameter(Rule):
    meta = RuleMeta(
        id="FT-T005",
        title="Tool parameter looks built to carry stolen data",
        severity=Severity.MEDIUM,
        description=(
            "The tool takes a parameter that its stated job does not need and that the "
            "text steers the model to fill with unrelated content: file contents, the "
            "conversation, or credentials. This is the usual way a poisoned tool ships "
            "data out, since arguments go straight to the server."
        ),
        remediation=(
            "Check what the parameter is for. If the tool's purpose does not explain it, "
            "do not connect the server."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP10"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for inventory in target.inventories:
            for index, tool in enumerate(inventory.tools):
                description = normalise(tool.description)
                for name, spec in parameters(tool.input_schema).items():
                    raw = spec.get("description")
                    own = normalise(raw) if isinstance(raw, str) else ""
                    verdict = _judge(name, own, description)
                    if verdict is None:
                        continue
                    message, evidence, severity = verdict
                    pointer = (
                        f"{inventory.origin.pointer}/tools/{index}/inputSchema/properties/{name}"
                    )
                    item = TextItem(inventory, tool, pointer, "parameter", own)
                    yield self.text_finding(item, message, evidence=evidence, severity=severity)


def _judge(name: str, own: str, description: str) -> tuple[str, str, Severity] | None:
    steering = re.search(
        rf"\b(?:{_VERBS})\b[^.]{{0,120}}\b(?:as|in|into|to|via|using|inside|through)\b"
        rf"[^.]{{0,20}}[\"'`]?{re.escape(name)}[\"'`]?(?![\w-])",
        description,
        re.IGNORECASE,
    )
    if name.lower() in _CATCH_ALL and steering:
        return (
            f"The tool description tells the model what to put into the catch-all "
            f"parameter {name!r}.",
            snippet(description, steering.start(), steering.end()),
            Severity.HIGH,
        )
    harvest = _HARVEST.search(own)
    if name.lower() in _CATCH_ALL and harvest:
        return (
            f"The catch-all parameter {name!r} asks for sensitive or unrelated content.",
            snippet(own, harvest.start(), harvest.end()),
            Severity.MEDIUM,
        )
    if _ALWAYS_SUSPICIOUS.match(name):
        return (
            f"Parameter {name!r} is named for content a tool has no reason to receive.",
            name,
            Severity.MEDIUM,
        )
    return None
