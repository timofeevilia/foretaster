"""Rules that match phrases in the text a server shows to the model."""

import re
from collections.abc import Iterator
from typing import ClassVar

from foretaster.models import Finding, Severity
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget
from foretaster.textscan import normalise, snippet

Pattern = tuple[str, Severity, re.Pattern[str]]


def _compile(*patterns: tuple[str, Severity, str]) -> tuple[Pattern, ...]:
    return tuple(
        (label, severity, re.compile(regex, re.IGNORECASE)) for label, severity, regex in patterns
    )


class _PhraseRule(Rule):
    """Report each piece of text once, listing every pattern it matches."""

    patterns: ClassVar[tuple[Pattern, ...]]

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for item in target.texts():
            text = normalise(item.text)
            hits = [
                (severity, label, match)
                for label, severity, pattern in self.patterns
                if (match := pattern.search(text))
            ]
            if not hits:
                continue
            hits.sort(key=lambda hit: hit[0].rank)
            worst, _, first = hits[0]
            labels = "; ".join(label for _, label, _ in hits)
            yield self.text_finding(
                item,
                f"The {item.label} contains {labels}.",
                evidence=snippet(text, first.start(), first.end()),
                severity=worst,
            )


class HiddenInstructions(_PhraseRule):
    meta = RuleMeta(
        id="FT-T001",
        title="Tool text gives instructions to the model",
        severity=Severity.HIGH,
        description=(
            "A tool description should say what the tool does. This one addresses the "
            "model directly: it overrides earlier instructions, imitates a system "
            "message, or orders steps to take before other tools are used. The model "
            "reads the description as trusted context and tends to obey."
        ),
        remediation=(
            "Do not connect this server until its author explains the text. A legitimate "
            "description never needs to command the model."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP06"]),
    )
    patterns = _compile(
        (
            "an instruction-override phrase",
            Severity.HIGH,
            r"\b(?:ignore|disregard|forget|override)\b[^.]{0,40}"
            r"\b(?:previous|prior|above|earlier|all|other|system)\b[^.]{0,30}"
            r"\b(?:instructions?|prompts?|rules|guidelines)\b",
        ),
        (
            "a fake system marker",
            Severity.HIGH,
            r"<\s*/?\s*(?:important|system|instructions?|admin|secret|critical|hidden)\s*>"
            r"|\[(?:system|important|admin)\]"
            r"|(?-i:\bSYSTEM(?:\s+(?:PROMPT|MESSAGE|NOTE|OVERRIDE))?\s*:)",
        ),
        (
            "a mandatory step imposed on the model",
            Severity.HIGH,
            r"\bbefore\s+(?:using|calling|invoking|running|you\s+(?:use|call)|any|each|every)\b"
            r"[^.]{0,60}\b(?:must|always|first|required|need\s+to)\b",
        ),
        (
            "a reference to the model's own instructions",
            Severity.HIGH,
            r"\b(?:system\s+prompt|developer\s+message|your\s+(?:instructions|guidelines|rules))\b",
        ),
        (
            "an attempt to reassign the model's role",
            Severity.HIGH,
            r"\byou\s+are\s+now\b|\bnew\s+instructions?\s*:|\bdeveloper\s+mode\b",
        ),
        (
            "a directive addressed to the model",
            Severity.MEDIUM,
            r"\b(?:you|the\s+(?:assistant|model|ai|llm|agent))\s+"
            r"(?:must|shall|have\s+to|are\s+required\s+to)\s+(?:always|never|first|now)\b",
        ),
    )


class SensitiveFileReference(_PhraseRule):
    meta = RuleMeta(
        id="FT-T003",
        title="Tool text refers to credential files",
        severity=Severity.HIGH,
        description=(
            "The text names files that hold keys, tokens or agent configuration, such as "
            "~/.ssh/id_rsa or mcp.json. Tool-poisoning attacks name these files to make "
            "the model read them and hand over the contents."
        ),
        remediation=(
            "Treat the server as hostile unless reading these files is its stated purpose "
            "and you accept that."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP01"]),
    )
    patterns = _compile(
        (
            "a reference to SSH keys",
            Severity.HIGH,
            r"(?<![\w-])\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b",
        ),
        (
            "a reference to stored cloud or registry credentials",
            Severity.HIGH,
            r"\.aws/credentials|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b"
            r"|\.kube/config|\.docker/config\.json|/etc/(?:passwd|shadow|sudoers)\b",
        ),
        (
            "a reference to agent configuration files",
            Severity.HIGH,
            r"\bclaude_desktop_config\.json\b|\.cursor/mcp\.json|(?<![\w-])\.?mcp\.json\b"
            r"|\.claude\.json\b|\bmcp_config\.json\b",
        ),
        (
            "a reference to wallets or browser secrets",
            Severity.HIGH,
            r"\bwallet\.dat\b|\bseed\s+phrase\b|\bcookies\.sqlite\b|\blogin\s+data\b",
        ),
        (
            "a reference to secret material",
            Severity.MEDIUM,
            r"(?<![\w.-])\.env\b(?!\.example)|\bprivate\s+keys?\b",
        ),
    )


class Concealment(_PhraseRule):
    meta = RuleMeta(
        id="FT-T004",
        title="Tool text tells the model to hide something from the user",
        severity=Severity.HIGH,
        description=(
            "The text asks the model to act without telling the user. There is no "
            "honest reason for a tool to demand secrecy from the person it serves."
        ),
        remediation="Do not connect this server.",
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP06"]),
    )
    patterns = _compile(
        (
            "an order to keep the user uninformed",
            Severity.HIGH,
            r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not)\s+"
            r"(?:tell|mention|inform|reveal|show|notify|alert|disclose|let)\b[^.]{0,40}\buser\b",
        ),
        (
            "an order to act behind the user's back",
            Severity.HIGH,
            r"\bwithout\s+(?:telling|informing|notifying|asking|alerting|the\s+user)\b"
            r"[^.]{0,30}(?:\buser\b|\bknow(?:ing|ledge)\b|\bconsent\b|\bnotic)"
            r"|\buser\s+(?:should|must|will|does)\s+not\s+(?:know|see|notice|be\s+aware)\b"
            r"|\bhide\s+(?:this|it|that)\s+from\b",
        ),
        (
            "an order to act covertly",
            Severity.HIGH,
            r"\b(?:silently|secretly|covertly|quietly)\s+"
            r"(?:send|forward|upload|include|add|append|read|pass|copy|attach|bcc|post)\b"
            r"|\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\b",
        ),
    )
