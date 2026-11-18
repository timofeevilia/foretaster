import ipaddress
from collections.abc import Iterator
from urllib.parse import urlsplit

from foretaster.models import Finding, Severity
from foretaster.redact import safe_url
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_CLEARTEXT_SCHEMES = {"http", "ws"}


class CleartextTransport(Rule):
    meta = RuleMeta(
        id="FT-C003",
        title="Remote server is reached without TLS",
        severity=Severity.HIGH,
        description=(
            "Traffic to the server is unencrypted and the server is not authenticated. "
            "Anyone on the network path can read credentials and tool results, or "
            "rewrite tool descriptions in transit."
        ),
        remediation="Use an https:// URL, or bind the server to localhost.",
        references=(OWASP_MCP["MCP07"], OWASP_MCP["MCP01"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            if not server.url:
                continue
            try:
                parts = urlsplit(server.url)
                host = parts.hostname or ""
            except ValueError:
                continue
            if parts.scheme.lower() not in _CLEARTEXT_SCHEMES or _is_loopback(host):
                continue
            private = _is_private(host)
            yield self.finding(
                config,
                "Server URL uses an unencrypted scheme"
                + (" on a private network address." if private else "."),
                server=server,
                pointer=f"{server.pointer}/url",
                evidence=safe_url(server.url),
                severity=Severity.MEDIUM if private else Severity.HIGH,
            )


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False
