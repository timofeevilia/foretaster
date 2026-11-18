"""Rules about the form of tool text rather than its wording."""

import base64
import binascii
import re
from collections.abc import Iterator

from foretaster.models import Finding, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){20,}(?![0-9A-Fa-f])")
_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}|(?:\\u[0-9A-Fa-f]{4}){6,}")
_PADDING = re.compile(r"[ \t]{40,}|(?:[ \t]*\n){10,}")
LONG_TEXT = 3000
VERY_LONG_TEXT = 8000


class EncodedPayload(Rule):
    meta = RuleMeta(
        id="FT-T007",
        title="Tool text contains encoded content",
        severity=Severity.HIGH,
        description=(
            "The text carries a block that decodes to readable text. Encoding keeps "
            "instructions away from human reviewers and keyword filters, while a model "
            "can decode them without effort."
        ),
        remediation="Decode the block and review it; do not connect the server before that.",
        references=(OWASP_MCP["MCP03"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for item in target.texts():
            decoded = _first_decodable(item.text)
            if decoded:
                kind, plain = decoded
                yield self.text_finding(
                    item,
                    f"The {item.label} contains {kind} that decodes to readable text.",
                    evidence=f"decoded: {truncate(plain, 100)!r}",
                )
            elif match := _ESCAPES.search(item.text):
                yield self.text_finding(
                    item,
                    f"The {item.label} contains a run of escaped character codes.",
                    evidence=truncate(match.group(0), 60),
                    severity=Severity.MEDIUM,
                )


def _first_decodable(text: str) -> tuple[str, str] | None:
    for match in _HEX.finditer(text):
        plain = _readable(bytes.fromhex(match.group(0)))
        if plain:
            return "a hexadecimal block", plain
    for match in _BASE64.finditer(text):
        blob = match.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        plain = _readable(raw)
        if plain:
            return "a Base64 block", plain
    return None


def _readable(raw: bytes) -> str | None:
    """Return ``raw`` as text when it reads like prose or code, not random bytes."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 16:
        return None
    ordinary = sum(char.isalnum() or char in " .,:;/_-'\"()\n" for char in text)
    return text if ordinary / len(text) >= 0.9 and " " in text.strip() else None


class AbnormalLength(Rule):
    meta = RuleMeta(
        id="FT-T008",
        title="Tool text is unusually long or padded",
        severity=Severity.LOW,
        description=(
            "The text is far longer than a tool description needs to be, or contains a "
            "large run of blank space. Both are used to push injected instructions "
            "below what an approval dialog shows, so the reviewer sees only the "
            "innocent beginning."
        ),
        remediation="Read the whole text, including what follows the blank area.",
        references=(OWASP_MCP["MCP03"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for item in target.texts():
            padding = _PADDING.search(item.text)
            if padding:
                yield self.text_finding(
                    item,
                    f"The {item.label} contains a large blank area, which can push text "
                    "out of view.",
                    evidence=f"{len(padding.group(0))} whitespace characters at offset "
                    f"{padding.start()}",
                    severity=Severity.MEDIUM,
                )
            length = len(item.text)
            if length > LONG_TEXT:
                yield self.text_finding(
                    item,
                    f"The {item.label} is {length} characters long.",
                    evidence=f"{length} characters",
                    severity=Severity.MEDIUM if length > VERY_LONG_TEXT else Severity.LOW,
                )
