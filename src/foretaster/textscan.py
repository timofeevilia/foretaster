"""Utilities for inspecting untrusted text advertised by MCP servers."""

import re
import unicodedata
from collections.abc import Iterator
from typing import Any

_TAG_BLOCK = range(0xE0000, 0xE0080)
_VARIATION_SUPPLEMENT = range(0xE0100, 0xE01F0)
_BIDI = frozenset({*range(0x202A, 0x202F), *range(0x2066, 0x206A)})
_ZERO_WIDTH = frozenset(
    {0x00AD, 0x034F, 0x180E, 0x200B, 0x200E, 0x200F, 0xFEFF, *range(0x2060, 0x2065)}
)
_JOINERS = frozenset({0x200C, 0x200D})
_MAX_SCHEMA_DEPTH = 6


def classify_invisible(text: str) -> dict[str, list[int]]:
    """Group the invisible or display-altering code points found in ``text``.

    Keys are ``tags``, ``variation``, ``bidi``, ``control`` and ``zero-width``.
    Zero-width joiners are ignored inside non-Latin scripts and emoji, where
    they are part of normal spelling.
    """
    found: dict[str, list[int]] = {}
    for index, char in enumerate(text):
        code = ord(char)
        if code in _TAG_BLOCK:
            kind = "tags"
        elif code in _VARIATION_SUPPLEMENT:
            kind = "variation"
        elif code in _BIDI:
            kind = "bidi"
        elif code in _ZERO_WIDTH or (code in _JOINERS and _between_ascii(text, index)):
            kind = "zero-width"
        elif unicodedata.category(char) == "Cc" and char not in "\t\n\r":
            kind = "control"
        else:
            continue
        found.setdefault(kind, []).append(code)
    return found


def _between_ascii(text: str, index: int) -> bool:
    before = text[index - 1] if index else " "
    after = text[index + 1] if index + 1 < len(text) else " "
    return before.isascii() and after.isascii()


def decode_tags(text: str) -> str:
    """Return the ASCII message hidden in Unicode tag characters, if any."""
    return "".join(chr(ord(char) - 0xE0000) for char in text if 0xE0020 <= ord(char) <= 0xE007E)


def normalise(text: str) -> str:
    """Rewrite text the way a model effectively reads it.

    Hidden tag characters become the ASCII they encode, other invisible
    characters vanish, compatibility forms are folded and whitespace collapses,
    so that patterns cannot be dodged by splitting a phrase with tricks.
    """
    chars: list[str] = []
    for char in text:
        code = ord(char)
        if 0xE0020 <= code <= 0xE007E:
            chars.append(chr(code - 0xE0000))
        elif (
            code in _TAG_BLOCK
            or code in _VARIATION_SUPPLEMENT
            or code in _BIDI
            or code in _ZERO_WIDTH
            or code in _JOINERS
        ):
            continue
        elif unicodedata.category(char) == "Cc":
            chars.append(" ")
        else:
            chars.append(char)
    folded = unicodedata.normalize("NFKC", "".join(chars))
    return re.sub(r"\s+", " ", folded).strip()


def printable(text: str) -> str:
    """Escape everything that is not a visible character or a plain space."""
    out: list[str] = []
    for char in text:
        if char in "\n\r\t":
            out.append(" ")
        elif char == " " or (char.isprintable() and not _is_invisible(char)):
            out.append(char)
        else:
            code = ord(char)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
    return "".join(out)


def _is_invisible(char: str) -> bool:
    code = ord(char)
    return (
        code in _TAG_BLOCK
        or code in _VARIATION_SUPPLEMENT
        or code in _BIDI
        or code in _ZERO_WIDTH
        or code in _JOINERS
    )


def snippet(text: str, start: int, end: int, margin: int = 40, limit: int = 160) -> str:
    """Quote ``text[start:end]`` with some context on both sides."""
    left = max(0, start - margin)
    right = min(len(text), end + margin)
    quoted = text[left:right]
    if len(quoted) > limit:
        quoted = quoted[: limit - 1] + "…"
        right = len(text) + 1
    return ("…" if left else "") + quoted + ("…" if right < len(text) else "")


def schema_texts(schema: object, pointer: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield ``(pointer, text)`` for every string a model reads in a JSON Schema."""
    if depth > _MAX_SCHEMA_DEPTH:
        return
    if isinstance(schema, list):
        for index, item in enumerate(schema):
            yield from schema_texts(item, f"{pointer}/{index}", depth + 1)
        return
    if not isinstance(schema, dict):
        return
    for key, value in schema.items():
        here = f"{pointer}/{_escape(str(key))}"
        if isinstance(value, str):
            if key in {"description", "title", "default", "const", "pattern", "examples"}:
                yield here, value
        elif key in {"enum", "examples"} and isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    yield f"{here}/{index}", item
        else:
            yield from schema_texts(value, here, depth + 1)


def parameters(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the top-level parameters declared by a tool's input schema."""
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    return {str(name): spec for name, spec in properties.items() if isinstance(spec, dict)}


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")
