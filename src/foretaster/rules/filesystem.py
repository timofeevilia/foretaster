import re
from collections.abc import Iterator

from foretaster.commandline import invocation
from foretaster.models import Finding, ServerDefinition, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_ROOT = re.compile(r"^(?:/|[A-Za-z]:[\\/]?)$")
_HOME = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE"
    r"|/home|/Users|/root|/home/[^/]+|/Users/[^/]+"
    r"|[A-Za-z]:[\\/]Users(?:[\\/][^\\/]+)?)$",
    re.IGNORECASE,
)
_VOLUME_HOST = re.compile(r"^([A-Za-z]:[\\/][^:]*|[^:]+):")
_MOUNT_SOURCE = re.compile(r"(?:^|,)(?:src|source)=([^,]+)")
_CONTAINER_RUNTIMES = {"docker", "podman", "nerdctl"}


class BroadFilesystemAccess(Rule):
    meta = RuleMeta(
        id="FT-C006",
        title="Server is granted access to the whole filesystem",
        severity=Severity.HIGH,
        description=(
            "The server receives the filesystem root or an entire home directory. A "
            "single injected instruction is then enough to read SSH keys, browser "
            "profiles and every other project on the machine."
        ),
        remediation="Pass only the specific project directories the server needs.",
        references=(OWASP_MCP["MCP02"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            for path in dict.fromkeys(_granted_paths(server)):
                severity = _classify(path)
                if severity is None:
                    continue
                scope = "filesystem root" if severity is Severity.HIGH else "home directory"
                yield self.finding(
                    config,
                    f"Server is given the {scope}.",
                    server=server,
                    evidence=truncate(path),
                    severity=severity,
                )


def _classify(path: str) -> Severity | None:
    trimmed = path if len(path) <= 1 else path.rstrip("/\\") or path[0]
    if _ROOT.match(path) or _ROOT.match(trimmed):
        return Severity.HIGH
    if _HOME.match(trimmed):
        return Severity.MEDIUM
    return None


def _granted_paths(server: ServerDefinition) -> Iterator[str]:
    inv = invocation(server)
    if inv is None:
        return
    if inv.program not in _CONTAINER_RUNTIMES:
        yield from inv.args
        return
    args = inv.args
    for index, arg in enumerate(args):
        flag, _, inline = arg.partition("=")
        value = inline or (args[index + 1] if index + 1 < len(args) else "")
        if flag in {"-v", "--volume"}:
            match = _VOLUME_HOST.match(value)
            if match:
                yield match.group(1)
        elif flag == "--mount":
            match = _MOUNT_SOURCE.search(arg if inline else value)
            if match:
                yield match.group(1)
