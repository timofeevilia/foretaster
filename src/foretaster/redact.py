"""Helpers that keep credentials out of reports."""

import re
from urllib.parse import urlsplit

TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ),
)
_URL_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+@")
_URL_QUERY = re.compile(r"(?<=\?)[^\s#]+")


def redact(value: str) -> str:
    """Describe a secret without revealing it."""
    prefix = value[:4] if len(value) >= 16 else ""
    return f"{prefix}*** ({len(value)} chars)"


def scrub(text: str) -> str:
    """Remove recognisable credentials from free text bound for a report."""
    for _, pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda match: redact(match.group(0)), text)
    text = _URL_CREDENTIALS.sub("***@", text)
    return _URL_QUERY.sub("***", text)


def safe_url(url: str) -> str:
    """Reduce a URL to scheme and host, dropping credentials, path and query."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "<unparseable URL>"
    return f"{parts.scheme}://{host}{port}"


def truncate(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
