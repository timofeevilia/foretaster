"""SARIF 2.1.0 output, the format GitHub code scanning ingests."""

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from foretaster.models import Finding, Severity
from foretaster.report import Report
from foretaster.rules import ALL_RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/timofeevilia/foretaster"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub maps this CVSS-like score to its own critical/high/medium/low labels.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(report: Report, base_dir: Path | None = None) -> str:
    """Serialise a report as SARIF. Paths are made relative to ``base_dir``."""
    base = (base_dir or Path.cwd()).resolve()
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Foretaster",
                "version": report.tool.version,
                "informationUri": INFORMATION_URI,
                "rules": [_rule(rule.meta) for rule in ALL_RULES],
            }
        },
        "invocations": [
            {
                "executionSuccessful": not report.errors,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": f"{error.kind} {error.subject}: {error.message}"},
                    }
                    for error in report.errors
                ],
            }
        ],
        "results": [_result(finding, base) for finding in report.findings],
    }
    document = {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _rule(meta: Any) -> dict[str, Any]:
    return {
        "id": meta.id,
        "name": "".join(word.capitalize() for word in meta.title.split()),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "help": {"text": f"{meta.description}\n\nFix: {meta.remediation}"},
        "defaultConfiguration": {"level": _LEVEL[meta.severity]},
        "properties": {
            "tags": ["security", *meta.references],
            "security-severity": _SECURITY_SEVERITY[meta.severity],
        },
    }


def _result(finding: Finding, base: Path) -> dict[str, Any]:
    text = finding.message
    if finding.server and finding.tool:
        text = f"Server {finding.server!r}, tool {finding.tool!r}: {text}"
    elif finding.server:
        text = f"Server {finding.server!r}: {text}"
    if finding.evidence:
        text += f" Evidence: {finding.evidence}"
    uri = _uri(finding.location.path, base)
    fingerprint = hashlib.sha256(
        "\x00".join((finding.rule_id, uri, finding.location.pointer, finding.message)).encode()
    ).hexdigest()
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": finding.location.line or 1},
                },
                "logicalLocations": [{"fullyQualifiedName": finding.location.pointer or "/"}],
            }
        ],
        "partialFingerprints": {"foretaster/v1": fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def _uri(path: Path, base: Path) -> str:
    """Repository-relative POSIX path when possible, since GitHub requires it."""
    try:
        return PurePosixPath(path.resolve().relative_to(base)).as_posix()
    except ValueError:
        return path.resolve().as_uri()
