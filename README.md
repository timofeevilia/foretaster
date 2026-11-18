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

> **Status: pre-alpha.** Configuration scanning and tool-description scanning
> work. Rug-pull detection, SARIF and HTML reports are not built yet. See the
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

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

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

### Scanning tool descriptions

Configuration files say how a server is started. The poison itself usually sits
in the tool descriptions the server sends to the model. There are two ways to
scan those.

From a saved tool list, without running anything. The file is a `tools/list`
result, which most MCP inspectors can export:

```bash
uv run foretaster scan --tools examples/poisoned-tools.json
```

```text
HIGH FT-T001 Tool text gives instructions to the model
  examples/poisoned-tools.json (server 'handy-math', tool 'add')
  The tool description contains a fake system marker; a mandatory step imposed on the model; a directive addressed to the model.
  ...
Scanned 0 configuration file(s), 1 server(s), 3 tool(s). Findings: 3 high, 2 medium.
```

From the servers themselves:

```bash
uv sync --extra connect
```

```bash
uv run foretaster scan --connect
```

`--connect` starts or contacts every enabled server in the scanned
configurations and asks for its tool list. **This runs the commands written in
your configuration files**, exactly as your agent would, so use it only on
configurations you were going to run anyway, or inside a sandbox. Foretaster
sends `initialize` and `tools/list` and nothing else: no tool is ever called.
A server that does not answer within `--timeout` seconds (default 30) is
reported and makes the scan incomplete.

### Options

| Option | Meaning |
|---|---|
| `--tools FILE` | Scan a saved tool list. Repeatable. |
| `--connect` | Ask the configured servers for their tools. Runs their commands. |
| `--timeout SECONDS` | How long to wait for each server with `--connect`. |
| `--format console\|json` | Report format. The JSON report has no timestamps, so equal inputs give byte-equal reports. |
| `--output FILE` | Write the report to a file instead of the terminal. |
| `--fail-on SEVERITY` | Lowest severity that makes the command fail: `critical`, `high` (default), `medium`, `low`, `info` or `never`. |
| `--project-dir DIR` | Where to look for project-level configuration. |

Exit status: `0` clean, `1` findings at or above `--fail-on`, `2` the scan was
incomplete (a file could not be parsed, a server did not answer or a rule
crashed). An incomplete scan is never reported as clean.

Other commands: `foretaster discover` lists configuration files and servers
without scanning them, `foretaster rules` lists the rules.

Without `--connect`, scanning only reads files. Credentials never reach a
report: rules redact what they quote, and every finding is scrubbed again when
it is created. Text that comes from a server is escaped to visible characters
before it is printed, so a hostile description cannot rewrite your terminal.

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

Rules for text a server shows to the model (tool descriptions, parameter
schemas, server instructions):

| ID | Severity | Finds | OWASP MCP Top 10 |
|---|---|---|---|
| FT-T001 | medium–high | Instructions aimed at the model: overriding earlier instructions, fake system markers, steps imposed before other tools | MCP03, MCP06 |
| FT-T002 | medium–critical | Invisible characters: Unicode tags (decoded and shown), bidirectional controls, control characters, zero-width characters | MCP03 |
| FT-T003 | medium–high | References to credential files such as `~/.ssh/id_rsa`, `.aws/credentials` or `mcp.json` | MCP03, MCP01 |
| FT-T004 | high | Orders to hide an action from the user | MCP03, MCP06 |
| FT-T005 | medium–high | Parameters built to carry stolen data: catch-all parameters the description tells the model to fill, or names such as `sidenote` and `system_prompt` | MCP03, MCP10 |
| FT-T006 | medium–high | Tool shadowing: text that names another server's tool or sets rules for tools in general | MCP03, MCP06 |
| FT-T007 | medium–high | Base64 or hex blocks that decode to readable text (decoded and shown), and runs of escaped character codes | MCP03 |
| FT-T008 | low–medium | Text that is unusually long or padded with blank space to push content out of view | MCP03 |

Before matching, text is rewritten the way a model reads it: hidden tag
characters are decoded, zero-width characters removed and look-alike forms
folded. Splitting `ignore` with an invisible character does not get a phrase
past a rule.

Planned for v0.1:

| Group | Checks |
|---|---|
| Change and conflict | tool description changed since baseline (rug pull), tool name collisions across servers |
| Dangerous combinations | remote server without authentication; one agent holding private data access, untrusted input and an outbound channel at once |

Known limits:

- The rules are pattern-based heuristics. An instruction phrased in a way no
  pattern anticipates, or written in a language other than English, passes. The
  optional LLM layer planned for stage 4 targets this gap.
- FT-C001 can miss a secret that matches no known format and sits under an
  innocent name. FT-C005 compares against a short built-in list of popular
  packages.
- The thresholds of FT-T008 are provisional until the benchmark exists.
- `--connect` over HTTP and SSE is tested against unreachable endpoints only;
  the stdio path is tested end to end.

## Development

```bash
uv sync --all-extras
```

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
