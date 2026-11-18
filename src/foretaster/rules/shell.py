import re
from collections.abc import Iterator

from foretaster.commandline import program_name
from foretaster.models import Finding, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_INTERPRETER = r"(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby)\b"
_DOWNLOAD_AND_RUN = re.compile(
    rf"(?:curl|wget)\b[^|;&]*\|\s*{_INTERPRETER}"
    rf"|base64\s+(?:-d|-D|--decode)\b[^|;&]*\|\s*{_INTERPRETER}"
    r"|(?:\$\(|`)\s*(?:curl|wget)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*(?:iex|invoke-expression)\b"
    r"|\b(?:iex|invoke-expression)\s*\(",
    re.IGNORECASE,
)
_POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
_POWERSHELLS = {"powershell", "pwsh"}
_ENCODED_FLAG = re.compile(r"^-e(?:nc(?:odedcommand)?|c)?$", re.IGNORECASE)
_POWERSHELL_COMMAND_FLAG = re.compile(r"^-c(?:ommand)?$", re.IGNORECASE)


class ShellCommand(Rule):
    meta = RuleMeta(
        id="FT-C004",
        title="Server is started through a shell command",
        severity=Severity.MEDIUM,
        description=(
            "The server entry runs a shell script instead of a program. A shell line can "
            "hide anything, and one that downloads code and pipes it into an interpreter "
            "runs unreviewed remote code on every start."
        ),
        remediation=(
            "Run the server binary directly with explicit arguments. Never pipe a "
            "download into an interpreter."
        ),
        references=(OWASP_MCP["MCP05"], OWASP_MCP["MCP04"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            if not server.command:
                continue
            line = " ".join((server.command, *server.args))
            match = _DOWNLOAD_AND_RUN.search(line)
            if match:
                yield self.finding(
                    config,
                    "Command downloads code and executes it immediately.",
                    server=server,
                    evidence=truncate(match.group(0)),
                    severity=Severity.CRITICAL,
                )
                continue
            program = program_name(server.command)
            if program in _POWERSHELLS and any(_ENCODED_FLAG.match(a) for a in server.args):
                yield self.finding(
                    config,
                    "PowerShell runs an encoded command, which hides what is executed.",
                    server=server,
                    evidence=program,
                    severity=Severity.HIGH,
                )
            elif (
                program in _POSIX_SHELLS
                and any(re.fullmatch(r"-[a-z]*c", arg) for arg in server.args)
            ) or (
                program in _POWERSHELLS
                and any(_POWERSHELL_COMMAND_FLAG.match(arg) for arg in server.args)
            ):
                yield self.finding(
                    config,
                    "Server is launched by an inline shell script.",
                    server=server,
                    evidence=program,
                )
