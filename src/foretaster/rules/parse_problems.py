from collections.abc import Iterator

from foretaster.models import Finding, ProblemKind, Severity
from foretaster.rules.base import Rule, RuleMeta, ScanTarget


class ParseProblems(Rule):
    meta = RuleMeta(
        id="FT-C000",
        title="Configuration entry could not be interpreted",
        severity=Severity.LOW,
        description=(
            "Part of the file is malformed or ambiguous, so the scanner and the agent "
            "may read it differently. Duplicate keys are the sharpest case: JSON parsers "
            "disagree on which value wins."
        ),
        remediation="Fix the entry so that it has exactly one valid interpretation.",
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config in target.configs:
            for problem in config.problems:
                duplicate = problem.kind is ProblemKind.DUPLICATE_KEY
                yield self.finding(
                    config,
                    problem.message,
                    pointer=problem.pointer,
                    severity=Severity.MEDIUM if duplicate else Severity.LOW,
                )
