# Security Policy

Foretaster is a security tool, so flaws in it matter twice: a false sense of
safety is itself a vulnerability.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/timofeevilia/foretaster/security/advisories/new)
instead. Include the affected version, a minimal reproduction, and the impact
you expect.

You will get an acknowledgement within 7 days. Fixes are released as soon as
they are ready, and reporters are credited unless they ask otherwise.

## Scope

In scope:

- Code execution, file access or network access triggered by scanning a
  malicious configuration or MCP server in the default (static) mode.
- Any way to make the scanner call a tool on a scanned MCP server.
- Detection bypasses for documented rules (report these as regular issues if
  disclosure carries no risk).

## Supported versions

The project is pre-alpha. Only the latest release receives fixes.
