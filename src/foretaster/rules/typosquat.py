import re
from collections.abc import Iterator

from foretaster.commandline import package_ref
from foretaster.models import Finding, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

# Widely used MCP server packages. The list is a seed, not an authority: it only
# decides which names are worth imitating.
KNOWN_PACKAGES: dict[str, frozenset[str]] = {
    "npm": frozenset(
        {
            "@modelcontextprotocol/server-filesystem",
            "@modelcontextprotocol/server-github",
            "@modelcontextprotocol/server-memory",
            "@modelcontextprotocol/server-postgres",
            "@modelcontextprotocol/server-puppeteer",
            "@modelcontextprotocol/server-slack",
            "@modelcontextprotocol/server-brave-search",
            "@modelcontextprotocol/server-sequential-thinking",
            "@modelcontextprotocol/server-everything",
            "@modelcontextprotocol/server-google-maps",
            "@modelcontextprotocol/inspector",
            "@playwright/mcp",
            "@upstash/context7-mcp",
            "@notionhq/notion-mcp-server",
            "@supabase/mcp-server-supabase",
            "@sentry/mcp-server",
            "@stripe/mcp",
            "@cloudflare/mcp-server-cloudflare",
            "@wonderwhy-er/desktop-commander",
            "mcp-remote",
            "firecrawl-mcp",
            "tavily-mcp",
            "exa-mcp-server",
            "chrome-devtools-mcp",
        }
    ),
    "pypi": frozenset(
        {
            "mcp",
            "fastmcp",
            "mcp-server-fetch",
            "mcp-server-git",
            "mcp-server-time",
            "mcp-server-sqlite",
            "mcp-server-qdrant",
            "awslabs.core-mcp-server",
            "serena-agent",
        }
    ),
    "docker": frozenset(
        {
            "ghcr.io/github/github-mcp-server",
            "mcp/filesystem",
            "mcp/fetch",
            "mcp/git",
            "mcp/github",
            "mcp/memory",
            "mcp/postgres",
            "mcp/puppeteer",
            "mcp/sqlite",
            "mcp/time",
        }
    ),
}


class TyposquattedPackage(Rule):
    meta = RuleMeta(
        id="FT-C005",
        title="Package name imitates a well-known MCP server",
        severity=Severity.MEDIUM,
        description=(
            "The package name differs from a popular MCP server by one character, by "
            "separators only, or contains non-ASCII look-alike letters. Attackers "
            "register such names to catch typos and copy-pasted configs."
        ),
        remediation=(
            "Check the name against the project's official documentation and replace it "
            "with the genuine package."
        ),
        references=(OWASP_MCP["MCP04"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            ref = package_ref(server)
            if ref is None or ref.remote:
                continue
            name = _normalise(ref.name, ref.ecosystem)
            known = {_normalise(k, ref.ecosystem): k for k in KNOWN_PACKAGES[ref.ecosystem]}
            if name in known:
                continue
            if not name.isascii():
                yield self.finding(
                    config,
                    "Package name contains non-ASCII characters that can pass for "
                    "ordinary letters.",
                    server=server,
                    evidence=ascii(ref.name),
                    severity=Severity.HIGH,
                )
                continue
            lookalike = next(
                (
                    original
                    for candidate, original in sorted(known.items())
                    if _similar(name, candidate)
                ),
                None,
            )
            if lookalike:
                yield self.finding(
                    config,
                    f"Package name is almost identical to `{lookalike}`.",
                    server=server,
                    evidence=truncate(ref.name),
                )


def _normalise(name: str, ecosystem: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _similar(name: str, known: str) -> bool:
    if _squash(name) == _squash(known):
        return True
    return _edit_distance_at_most_one(name, known)


def _squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name)


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    """True when ``a`` becomes ``b`` by one insert, delete, substitution or swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = next((k for k in range(len(a)) if a[k] != b[k]), len(a))
    if len(a) == len(b):
        if a[i + 1 :] == b[i + 1 :]:
            return True
        return a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2 :] == b[i + 2 :]
    return a[i:] == b[i + 1 :]
