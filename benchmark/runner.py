"""Run Foretaster over a suite and count what it caught and what it got wrong.

Protocol
--------
*Detection* is measured in two scenarios, because the answer depends heavily on
what the scanner can see:

``alone``
    Only the poisoned tool is scanned. This is the hard case: a reviewer is
    handed one server and nothing else.
``beside_target``
    The poisoned tool is advertised by a second server next to the real server
    it targets, the way an agent would meet it. The scanner can then notice
    that the text talks about tools belonging to someone else.

A case counts as detected only if a finding names the poisoned tool itself. A
finding on one of the real tools never counts.

*False positives* are measured on the real servers, whose definitions are
published and widely used, so any finding on one of their tools is counted as
false. Again there are two scenarios: each server scanned ``alone``, and all of
them scanned ``together`` as if one agent had connected every one. The second
is the fair counterpart of ``beside_target``: it exposes the rules that compare
servers with each other to real text.

*Thresholds.* Everything is reported at ``medium`` (what a reviewer is shown as
a warning) and ``high`` (what fails a CI run by default).

*Splits.* Servers are divided into ``dev`` and ``test`` by a hash of their name.
Rules may be tuned by studying ``dev``. For ``test`` only counts are written out,
never the text of a missed case or of a false positive, so that it stays unseen.
"""

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from benchmark.cases import SPLITS, PoisonedTool, Suite, split_of
from benchmark.metrics import Rate
from foretaster import __version__
from foretaster.engine import run_rules
from foretaster.models import Finding, Location, Severity
from foretaster.rules import ScanTarget
from foretaster.tool_manifest import inventory_from_tools

THRESHOLDS = (Severity.MEDIUM, Severity.HIGH)
SCENARIOS = ("alone", "beside_target")
FP_SCENARIOS = ("alone", "together")
ATTACKER = "benchmark-attacker"


def _scan(servers: dict[str, list[dict[str, Any]]]) -> tuple[Finding, ...]:
    origin = Location(path=Path("benchmark.json"))
    inventories = tuple(
        inventory_from_tools(name, origin, tools, None) for name, tools in servers.items()
    )
    result = run_rules(ScanTarget((), inventories))
    if result.rule_errors:
        raise RuntimeError(f"rule crashed during benchmark: {result.rule_errors}")
    return result.findings


def _reaches(finding: Finding, threshold: Severity) -> bool:
    return finding.severity.rank <= threshold.rank


def _rates(counts: dict[str, int], totals: Counter[str]) -> dict[str, Any]:
    result = {split: Rate(counts[split], totals[split]).as_dict() for split in SPLITS}
    result["all"] = Rate(sum(counts.values()), sum(totals.values())).as_dict()
    return result


def _grouped(groups: dict[str, list[bool]]) -> dict[str, Any]:
    return {name: Rate(sum(flags), len(flags)).as_dict() for name, flags in sorted(groups.items())}


def _false_positives(clean: dict[str, list[dict[str, Any]]], scenario: str) -> dict[str, Any]:
    flagged: dict[str, dict[str, set[tuple[str, str]]]] = {
        t.value: {split: set() for split in SPLITS} for t in THRESHOLDS
    }
    rules: Counter[str] = Counter()
    examples: list[dict[str, str]] = []
    totals: Counter[str] = Counter()
    for name, tools in clean.items():
        totals[split_of(name)] += len(tools)
    batches = [clean] if scenario == "together" else [{n: t} for n, t in clean.items()]
    for batch in batches:
        for finding in _scan(batch):
            if finding.tool is None or finding.server is None:
                continue
            name = finding.server
            split = split_of(name)
            for threshold in THRESHOLDS:
                if _reaches(finding, threshold):
                    flagged[threshold.value][split].add((name, finding.tool))
            if not _reaches(finding, Severity.MEDIUM):
                continue
            rules[finding.rule_id] += 1
            if split == "dev":
                examples.append(
                    {
                        "server": name,
                        "tool": finding.tool,
                        "rule": finding.rule_id,
                        "severity": finding.severity.value,
                        "message": finding.message,
                        "evidence": finding.evidence or "",
                    }
                )
    return {
        "rates": {
            threshold.value: _rates(
                {split: len(flagged[threshold.value][split]) for split in SPLITS}, totals
            )
            for threshold in THRESHOLDS
        },
        "rules": dict(sorted(rules.items())),
        "dev_findings": sorted(examples, key=lambda e: (e["server"], e["tool"], e["rule"])),
    }


def _detection(
    poisoned: tuple[PoisonedTool, ...], clean: dict[str, list[dict[str, Any]]], scenario: str
) -> dict[str, Any]:
    detected: dict[str, dict[str, int]] = {t.value: dict.fromkeys(SPLITS, 0) for t in THRESHOLDS}
    totals: Counter[str] = Counter()
    by_category: dict[str, list[bool]] = defaultdict(list)
    by_technique: dict[str, list[bool]] = defaultdict(list)
    rules: Counter[str] = Counter()
    missed: list[dict[str, str]] = []
    for case in poisoned:
        split = split_of(case.server)
        totals[split] += 1
        servers = {ATTACKER: [case.tool]}
        if scenario == "beside_target":
            servers[case.server] = clean.get(case.server, [])
        findings = [
            finding
            for finding in _scan(servers)
            if finding.server == ATTACKER and finding.tool == case.tool["name"]
        ]
        for threshold in THRESHOLDS:
            if any(_reaches(finding, threshold) for finding in findings):
                detected[threshold.value][split] += 1
        caught = any(_reaches(finding, Severity.MEDIUM) for finding in findings)
        by_category[case.category].append(caught)
        by_technique[case.technique].append(caught)
        for rule_id in {f.rule_id for f in findings if _reaches(f, Severity.MEDIUM)}:
            rules[rule_id] += 1
        if not caught:
            missed.append(
                {
                    "case": case.case_id,
                    "split": split,
                    "category": case.category,
                    "technique": case.technique,
                    "description": (
                        str(case.tool.get("description", ""))[:400] if split == "dev" else ""
                    ),
                }
            )
    return {
        "rates": {
            threshold.value: _rates(detected[threshold.value], totals) for threshold in THRESHOLDS
        },
        "by_category": _grouped(by_category),
        "by_technique": _grouped(by_technique),
        "rules": dict(sorted(rules.items())),
        "missed": sorted(missed, key=lambda e: e["case"]),
    }


def evaluate(suite: Suite) -> dict[str, Any]:
    """Return every number the report needs, as plain JSON-ready data."""
    clean = {server.name: list(server.tools) for server in suite.servers}
    return {
        "schema_version": "1",
        "scanner": {"name": "foretaster", "version": __version__},
        "suite": {
            "name": suite.name,
            "description": suite.description,
            "source": suite.source,
            "revision": suite.revision,
            "licence": suite.licence,
            "notes": list(suite.notes),
            "servers": len(suite.servers),
            "clean_tools": sum(len(tools) for tools in clean.values()),
            "poisoned_tools": len(suite.poisoned),
        },
        "detection": {
            scenario: _detection(suite.poisoned, clean, scenario) for scenario in SCENARIOS
        },
        "false_positives": {
            scenario: _false_positives(clean, scenario) for scenario in FP_SCENARIOS
        },
    }
