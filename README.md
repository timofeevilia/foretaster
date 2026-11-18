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

> **Status: pre-alpha.** The repository currently holds the project skeleton.
> Nothing below marked *planned* works yet. See the [roadmap](#roadmap).

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
4. **Mapped to standards.** Every finding references the OWASP MCP Top 10 and
   the OWASP Top 10 for Agentic Applications, and reports export to SARIF for
   GitHub code scanning.

## Planned rule set (v0.1)

| Group | Checks |
|---|---|
| Poisoned tool descriptions | hidden instructions, invisible Unicode, references to sensitive files, "do not tell the user" directives, suspicious exfiltration parameters, cross-server tool references, encoded payloads, abnormal length |
| Configuration | plaintext secrets, unpinned packages, remote servers without TLS, shell pipelines in commands, typosquatted package names, whole-filesystem access |
| Change and conflict | tool description changed since baseline, tool name collisions across servers |
| Dangerous combinations | remote server without authentication; one agent holding private data access, untrusted input and an outbound channel at once |

## Installation

Not published to PyPI yet. From a checkout:

```bash
uv sync
```

```bash
uv run foretaster --version
```

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
