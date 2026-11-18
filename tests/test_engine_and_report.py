import io
import json
from collections.abc import Iterator
from pathlib import Path

from rich.console import Console

from foretaster.commandline import invocation, program_name
from foretaster.discovery import Candidate, LoadFailure
from foretaster.engine import ScanResult, run_rules
from foretaster.models import Client, Finding, Scope, ServerDefinition, Severity, Transport
from foretaster.redact import redact, safe_url, scrub, truncate
from foretaster.report import Report, build_report
from foretaster.report.console import render_console
from foretaster.rules import Rule, RuleMeta, ScanTarget
from tests.conftest import make_target

SERVERS = {
    "files": {"command": "npx", "args": ["-y", "some-server", "/"]},
    "remote": {"url": "http://mcp.example.com"},
}


class Crashing(Rule):
    meta = RuleMeta("X-1", "Crashes", Severity.LOW, "d", "r")

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        yield self.finding(target.configs[0], "before the crash")
        raise RuntimeError("boom")


class Repeating(Rule):
    meta = RuleMeta("X-2", "Repeats", Severity.INFO, "d", "r")

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for _ in range(3):
            yield self.finding(target.configs[0], "same thing")


def test_default_rules_sorted_by_severity() -> None:
    result = run_rules(make_target(SERVERS))
    assert result.rule_errors == ()
    ranks = [finding.severity.rank for finding in result.findings]
    assert ranks == sorted(ranks)
    assert {finding.rule_id for finding in result.findings} == {"FT-C002", "FT-C003", "FT-C006"}


def test_crashing_rule_is_isolated() -> None:
    result = run_rules(make_target(SERVERS), [Crashing(), Repeating()])
    assert [finding.message for finding in result.findings] == ["before the crash", "same thing"]
    (error,) = result.rule_errors
    assert error.rule_id == "X-1"
    assert error.message == "RuntimeError: boom"


def test_report_summary_and_json_roundtrip() -> None:
    target = make_target(SERVERS)
    failure = LoadFailure(Candidate(Client.CURSOR, Scope.USER, Path("bad.json")), "invalid JSON")
    result = run_rules(target, [Crashing()])
    report = build_report(target.configs, [failure], result)

    assert report.summary.configs == 1
    assert report.summary.servers == 2
    assert report.summary.findings[Severity.LOW] == 1
    assert report.worst() is Severity.LOW
    assert [(error.kind, error.subject) for error in report.errors] == [
        ("config", "bad.json"),
        ("rule", "X-1"),
    ]

    payload = json.loads(report.model_dump_json())
    assert payload["schema_version"] == "1"
    assert payload["tool"]["name"] == "foretaster"
    assert payload["scanned"] == ["mcp.json"]
    assert Report.model_validate(payload) == report


def test_empty_report() -> None:
    report = build_report([], [], ScanResult((), ()))
    assert report.worst() is None
    assert (
        render(report) == "Scanned 0 configuration file(s), 0 server(s), 0 tool(s). No findings.\n"
    )


def render(report: Report) -> str:
    stream = io.StringIO()
    render_console(report, Console(file=stream, no_color=True, width=200))
    return stream.getvalue()


def test_console_report() -> None:
    target = make_target(SERVERS)
    failure = LoadFailure(Candidate(Client.CURSOR, Scope.USER, Path("bad.json")), "invalid JSON")
    result = run_rules(target)
    text = render(build_report(target.configs, [failure], result))

    assert "HIGH FT-C006 Server is granted access to the whole filesystem" in text
    assert "mcp.json:3 (server 'files')" in text
    assert "Evidence: http://mcp.example.com" in text
    assert "Fix: Use an https:// URL" in text
    assert "OWASP MCP02:2025" in text
    assert "Could not parse bad.json: invalid JSON" in text
    assert "Findings: 2 high, 1 medium." in text
    assert "1 error(s): the scan is incomplete." in text


def test_console_report_rule_error_and_markup_is_escaped() -> None:
    target = make_target({"[bold]x[/bold]": {"url": "http://example.com"}})
    text = render(build_report(target.configs, [], run_rules(target, [Crashing()])))
    assert "Rule failed X-1: RuntimeError: boom" in text

    text = render(build_report(target.configs, [], run_rules(target)))
    assert "(server '[bold]x[/bold]')" in text


def test_program_name() -> None:
    assert program_name("/usr/local/bin/NPX") == "npx"
    assert program_name("C:\\Program Files\\nodejs\\npx.cmd") == "npx"
    assert program_name(" powershell.exe ") == "powershell"


def server(command: str | None, *args: str) -> ServerDefinition:
    return ServerDefinition(
        name="s", transport=Transport.STDIO, command=command, args=args, pointer="/s"
    )


def test_invocation_unwraps_wrappers() -> None:
    assert invocation(server(None)) is None
    assert invocation(server("env", "A=1")) is None
    assert invocation(server("cmd", "/C", "npx.cmd", "-y", "pkg")) == ("npx", ("-y", "pkg"))
    assert invocation(server("cmd", "/c")) == ("cmd", ("/c",))
    assert invocation(server("env", "A=1", "B=2", "node", "x.js")) == ("node", ("x.js",))
    assert invocation(server("env", "-i", "node")) == ("-i", ("node",))


def test_redaction_helpers() -> None:
    assert redact("short-secret") == "*** (12 chars)"
    assert redact("ghp_0123456789abcdef") == "ghp_*** (20 chars)"
    assert safe_url("https://user:pw@host.example:8443/path?token=1") == "https://host.example:8443"
    assert safe_url("http://[::1") == "<unparseable URL>"
    assert truncate("abc", 5) == "abc"
    assert truncate("abcdefgh", 5) == "abcd…"


def test_scrub_removes_credentials_from_free_text() -> None:
    token = "ghp_" + "a1B2" * 9
    assert token not in scrub(f"spec {token} end")
    assert scrub("git+https://user:pw@github.com/o/r") == "git+https://***@github.com/o/r"
    assert scrub("https://h/p?token=abc&x=1 tail") == "https://h/p?*** tail"
    assert scrub("@scope/server@1.2.3") == "@scope/server@1.2.3"


def test_findings_are_scrubbed_at_construction() -> None:
    token = "ghp_" + "a1B2" * 9
    target = make_target(
        {"s": {"command": "uvx", "args": ["--from", f"git+https://{token}@github.com/o/r", "x"]}}
    )
    result = run_rules(target)
    assert result.findings
    assert token not in "".join(finding.model_dump_json() for finding in result.findings)
