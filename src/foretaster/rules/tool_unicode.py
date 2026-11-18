from collections import Counter
from collections.abc import Iterator

from foretaster.models import Finding, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget
from foretaster.textscan import classify_invisible, decode_tags

_KINDS: dict[str, tuple[Severity, str]] = {
    "tags": (
        Severity.CRITICAL,
        "Unicode tag characters, which encode text that people cannot see but models can read",
    ),
    "variation": (
        Severity.HIGH,
        "supplementary variation selectors, which can carry hidden data",
    ),
    "bidi": (
        Severity.HIGH,
        "bidirectional control characters, which make text display in a different "
        "order than it is read",
    ),
    "control": (
        Severity.HIGH,
        "control characters, which can rewrite or hide text in a terminal",
    ),
    "zero-width": (
        Severity.MEDIUM,
        "zero-width characters, which split words to dodge filters or hide content",
    ),
}


class InvisibleCharacters(Rule):
    meta = RuleMeta(
        id="FT-T002",
        title="Tool text contains invisible characters",
        severity=Severity.HIGH,
        description=(
            "The text holds characters that a person reviewing it does not see. What "
            "the reviewer approves and what the model reads are then different texts."
        ),
        remediation=(
            "Do not connect this server. Ask the author for a description in plain "
            "visible characters."
        ),
        references=(OWASP_MCP["MCP03"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for item in target.texts():
            for kind, codes in classify_invisible(item.text).items():
                severity, explanation = _KINDS[kind]
                counts = Counter(codes)
                listed = ", ".join(
                    f"U+{code:04X} x{count}" for code, count in sorted(counts.items())[:6]
                )
                if len(counts) > 6:
                    listed += f", and {len(counts) - 6} more"
                evidence = listed
                hidden = decode_tags(item.text) if kind == "tags" else ""
                if hidden:
                    evidence += f"; hidden text: {truncate(hidden, 100)!r}"
                yield self.text_finding(
                    item,
                    f"The {item.label} contains {explanation}.",
                    evidence=evidence,
                    severity=severity,
                )
