"""Foretaster itself, driven through its library API."""

from pathlib import Path

from benchmark.scanners.base import Flag, Servers, Verdicts
from foretaster import __version__
from foretaster.engine import run_rules
from foretaster.llm import Reviewer
from foretaster.models import Location
from foretaster.rules import ALL_RULES, LlmReview, Rule, ScanTarget
from foretaster.tool_manifest import inventory_from_tools


class ForetasterScanner:
    """The pattern rules, the LLM review, or both.

    ``reviewer`` adds the LLM review; ``patterns=False`` leaves the pattern
    rules out, which shows what the model contributes on its own.
    """

    version = __version__

    def __init__(self, reviewer: Reviewer | None = None, *, patterns: bool = True) -> None:
        if reviewer is None and not patterns:
            raise ValueError("a scanner needs the pattern rules, a reviewer, or both")
        self.reviewer = reviewer
        self.patterns = patterns
        if reviewer is None:
            self.name = "foretaster"
            self.notes: tuple[str, ...] = ("Pattern rules only; the LLM review is off.",)
        else:
            self.name = "foretaster+llm" if patterns else "foretaster-llm-only"
            what = "Pattern rules and the LLM review" if patterns else "The LLM review alone"
            self.notes = (f"{what}; reviewer {reviewer.model.identity}.",)

    def _rules(self) -> list[Rule]:
        rules: list[Rule] = [rule() for rule in ALL_RULES] if self.patterns else []
        if self.reviewer is not None:
            rules.append(LlmReview(self.reviewer))
        return rules

    def scan_many(self, batches: list[Servers]) -> list[Verdicts]:
        return [self._scan(batch) for batch in batches]

    def _scan(self, servers: Servers) -> Verdicts:
        origin = Location(path=Path("benchmark.json"))
        inventories = tuple(
            inventory_from_tools(name, origin, tools, None) for name, tools in servers.items()
        )
        result = run_rules(ScanTarget((), inventories), self._rules())
        if result.rule_errors:
            # A tool the reviewer could not judge would be counted as passed.
            raise RuntimeError(f"rule crashed during benchmark: {result.rule_errors}")
        verdicts: Verdicts = {}
        for finding in result.findings:
            if finding.server is None or finding.tool is None:
                continue
            key = (finding.server, finding.tool)
            previous = verdicts.get(key)
            if previous is None:
                # Findings arrive most severe first, so the first one sets the severity.
                verdicts[key] = Flag(
                    finding.severity,
                    (finding.rule_id,),
                    f"{finding.message} {finding.evidence or ''}".strip(),
                )
            elif finding.rule_id not in previous.labels:
                verdicts[key] = previous._replace(labels=(*previous.labels, finding.rule_id))
        return verdicts
