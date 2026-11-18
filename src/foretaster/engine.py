"""Run rules over a scan target."""

from collections.abc import Sequence
from typing import NamedTuple

from foretaster.models import Finding
from foretaster.rules import ALL_RULES, Rule, ScanTarget


class RuleError(NamedTuple):
    """A rule that crashed. Its findings, if any, are incomplete."""

    rule_id: str
    message: str


class ScanResult(NamedTuple):
    findings: tuple[Finding, ...]
    rule_errors: tuple[RuleError, ...]


def run_rules(target: ScanTarget, rules: Sequence[Rule] | None = None) -> ScanResult:
    """Apply every rule and return de-duplicated findings, most severe first.

    A rule that raises is recorded rather than propagated: one broken rule must
    not hide the others' results, and must not pass for a clean scan either.
    """
    if rules is None:
        rules = [rule() for rule in ALL_RULES]
    findings: dict[tuple[str, str, str, str], Finding] = {}
    errors: list[RuleError] = []
    for rule in rules:
        try:
            for finding in rule.check(target):
                key = (
                    finding.rule_id,
                    str(finding.location.path),
                    finding.location.pointer,
                    finding.message,
                )
                findings.setdefault(key, finding)
        except Exception as exc:
            errors.append(RuleError(rule.meta.id, f"{type(exc).__name__}: {exc}"))
    ordered = sorted(
        findings.values(),
        key=lambda f: (
            f.severity.rank,
            str(f.location.path),
            f.location.line or 0,
            f.rule_id,
            f.location.pointer,
        ),
    )
    return ScanResult(tuple(ordered), tuple(errors))
