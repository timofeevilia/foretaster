"""Convert JSON-with-comments into plain JSON.

VS Code and several other clients accept ``//`` and ``/* */`` comments and
trailing commas in their configuration files. Removed characters are replaced
with spaces, so offsets and line numbers in the result match the original.
"""


def strip_jsonc(text: str) -> str:
    """Blank out comments and trailing commas, leaving string contents intact."""
    out = _blank_comments(text)
    _blank_trailing_commas(out)
    return "".join(out)


def _blank_comments(text: str) -> list[str]:
    out = list(text)
    length = len(text)
    i = 0
    while i < length:
        char = text[i]
        if char == '"':
            i = _skip_string(text, i)
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = length if end == -1 else end
            _blank(out, i, end)
            i = end
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = length if close == -1 else close + 2
            _blank(out, i, end)
            i = end
        else:
            i += 1
    return out


def _blank_trailing_commas(out: list[str]) -> None:
    text = "".join(out)
    length = len(text)
    i = 0
    while i < length:
        char = text[i]
        if char == '"':
            i = _skip_string(text, i)
            continue
        if char == ",":
            j = i + 1
            while j < length and text[j].isspace():
                j += 1
            if j < length and text[j] in "}]":
                out[i] = " "
        i += 1


def _skip_string(text: str, start: int) -> int:
    """Return the index just past the string literal opening at ``start``."""
    i = start + 1
    length = len(text)
    while i < length:
        if text[i] == "\\":
            i += 2
        elif text[i] == '"':
            return i + 1
        else:
            i += 1
    return length


def _blank(out: list[str], start: int, end: int) -> None:
    for i in range(start, end):
        if out[i] not in "\r\n":
            out[i] = " "
