import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlsplit

from foretaster.models import AgentConfig, Finding, ServerDefinition, Severity
from foretaster.redact import TOKEN_PATTERNS, redact
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_SENSITIVE_NAME = re.compile(
    r"token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential"
    r"|(?:^|[_.-])(?:key|auth|authorization|pwd)(?:$|[_.-])",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"\$\{|\{\{|^\$[A-Za-z_]|^%[A-Za-z_]+%$|^<.*>$"
    r"|^(?:bearer\s+|basic\s+)?(?:your|my|xxx|changeme|replace|todo|example|placeholder|\*{3}|\.{3})",
    re.IGNORECASE,
)
_NOT_A_SECRET = re.compile(r"^(?:\d+|true|false|[~./\\].*|[A-Za-z]:[\\/].*|https?://\S*)$", re.I)
_MIN_LENGTH = 8


class PlaintextSecret(Rule):
    meta = RuleMeta(
        id="FT-C001",
        title="Credential stored in plain text",
        severity=Severity.HIGH,
        description=(
            "A credential is written directly into the configuration file. Such files "
            "are synced, backed up, committed and read by every process running as the "
            "user, including other MCP servers."
        ),
        remediation=(
            "Move the value to the client's secret input or an environment variable "
            "reference and rotate the exposed credential."
        ),
        references=(OWASP_MCP["MCP01"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            for name, value in server.env.items():
                yield from self._named(config, server, f"env/{name}", name, value)
            for name, value in server.headers.items():
                yield from self._named(config, server, f"headers/{name}", name, value)
            yield from self._args(config, server)
            if server.url:
                yield from self._url(config, server, server.url)

    def _args(self, config: AgentConfig, server: ServerDefinition) -> Iterator[Finding]:
        previous_flag: str | None = None
        for index, arg in enumerate(server.args):
            where = f"args/{index}"
            flag, separator, inline = arg.partition("=")
            if arg.startswith("-") and separator:
                yield from self._named(config, server, where, flag, inline)
            elif previous_flag is not None:
                yield from self._named(config, server, where, previous_flag, arg)
            else:
                yield from self._pattern_only(config, server, where, arg)
            previous_flag = arg if arg.startswith("-") and not separator else None

    def _url(self, config: AgentConfig, server: ServerDefinition, url: str) -> Iterator[Finding]:
        try:
            parts = urlsplit(url)
            password = parts.password
        except ValueError:
            return
        if password:
            yield from self._named(config, server, "url", "password", password)
        for name, value in parse_qsl(parts.query):
            yield from self._named(config, server, "url", name, value)

    def _named(
        self, config: AgentConfig, server: ServerDefinition, where: str, name: str, value: str
    ) -> Iterator[Finding]:
        """Check a value whose name is known, such as an env variable or a flag."""
        found = False
        for finding in self._pattern_only(config, server, where, value):
            found = True
            yield finding
        if found or not _SENSITIVE_NAME.search(name) or not _looks_literal(value):
            return
        yield self.finding(
            config,
            f"{name!r} holds a literal value in {_describe(where)}.",
            server=server,
            pointer=f"{server.pointer}/{where}",
            evidence=redact(value),
            severity=Severity.MEDIUM,
        )

    def _pattern_only(
        self, config: AgentConfig, server: ServerDefinition, where: str, value: str
    ) -> Iterator[Finding]:
        for label, pattern in TOKEN_PATTERNS:
            match = pattern.search(value)
            if match:
                yield self.finding(
                    config,
                    f"{label} found in {_describe(where)}.",
                    server=server,
                    pointer=f"{server.pointer}/{where}",
                    evidence=redact(match.group(0)),
                )
                return


def _looks_literal(value: str) -> bool:
    value = value.strip()
    return (
        len(value) >= _MIN_LENGTH
        and not _PLACEHOLDER.search(value)
        and not _NOT_A_SECRET.match(value)
    )


def _describe(where: str) -> str:
    kind = where.split("/", 1)[0]
    return {
        "env": "an environment variable",
        "headers": "an HTTP header",
        "args": "a command-line argument",
        "url": "the server URL",
    }[kind]
