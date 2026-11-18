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

*Thresholds.* Everything is reported at ``low`` (any finding at all), ``medium``
(what a reviewer is shown as a warning) and ``high`` (what fails a CI run by
default). Scanners grade severity differently, so no single threshold is the
fair one; comparisons should look at all three.

*Splits.* Servers are divided into ``dev`` and ``test`` by a hash of their name.
Rules may be tuned by studying ``dev``. For ``test`` only counts are written out,
never the text of a missed case or of a false positive, so that it stays unseen.
"""

from collections import Counter, defaultdict
from typing import Any

from benchmark.cases import SPLITS, PoisonedTool, Suite, split_of
from benchmark.metrics import Rate
from benchmark.scanners import Flag, Scanner, Servers
from benchmark.suites.wild import SUBJECT, CaseSuite
from foretaster.models import Severity

THRESHOLDS = (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
BREAKDOWN = Severity.MEDIUM
SCENARIOS = ("alone", "beside_target")
FP_SCENARIOS = ("alone", "together")
ATTACKER = "benchmark-attacker"


def _reaches(flag: Flag | None, threshold: Severity) -> bool:
    return flag is not None and flag.severity.rank <= threshold.rank


def _rates(counts: dict[str, int], totals: Counter[str]) -> dict[str, Any]:
    result = {split: Rate(counts[split], totals[split]).as_dict() for split in SPLITS}
    result["all"] = Rate(sum(counts.values()), sum(totals.values())).as_dict()
    return result


def _grouped(groups: dict[str, list[bool]]) -> dict[str, Any]:
    return {name: Rate(sum(flags), len(flags)).as_dict() for name, flags in sorted(groups.items())}


def _false_positives(scanner: Scanner, clean: Servers, scenario: str) -> dict[str, Any]:
    flagged = {t.value: dict.fromkeys(SPLITS, 0) for t in THRESHOLDS}
    labels: Counter[str] = Counter()
    examples: list[dict[str, str]] = []
    totals: Counter[str] = Counter()
    for name, tools in clean.items():
        totals[split_of(name)] += len(tools)
    batches = [clean] if scenario == "together" else [{n: t} for n, t in clean.items()]
    for verdicts in scanner.scan_many(batches):
        for (server, tool), flag in sorted(verdicts.items()):
            split = split_of(server)
            for threshold in THRESHOLDS:
                if _reaches(flag, threshold):
                    flagged[threshold.value][split] += 1
            if not _reaches(flag, BREAKDOWN):
                continue
            labels.update(flag.labels)
            if split == "dev":
                examples.append(
                    {
                        "server": server,
                        "tool": tool,
                        "labels": ", ".join(flag.labels),
                        "severity": flag.severity.value,
                        "detail": flag.detail,
                    }
                )
    return {
        "rates": {t.value: _rates(flagged[t.value], totals) for t in THRESHOLDS},
        "labels": dict(sorted(labels.items())),
        "dev_findings": examples,
    }


def _detection(
    scanner: Scanner, poisoned: tuple[PoisonedTool, ...], clean: Servers, scenario: str
) -> dict[str, Any]:
    batches: list[Servers] = []
    for case in poisoned:
        servers: Servers = {ATTACKER: [case.tool]}
        if scenario == "beside_target":
            servers[case.server] = clean.get(case.server, [])
        batches.append(servers)

    detected = {t.value: dict.fromkeys(SPLITS, 0) for t in THRESHOLDS}
    totals: Counter[str] = Counter()
    by_category: dict[str, list[bool]] = defaultdict(list)
    by_technique: dict[str, list[bool]] = defaultdict(list)
    labels: Counter[str] = Counter()
    missed: list[dict[str, str]] = []
    for case, verdicts in zip(poisoned, scanner.scan_many(batches), strict=True):
        split = split_of(case.server)
        totals[split] += 1
        flag = verdicts.get((ATTACKER, case.tool["name"]))
        for threshold in THRESHOLDS:
            if _reaches(flag, threshold):
                detected[threshold.value][split] += 1
        caught = _reaches(flag, BREAKDOWN)
        by_category[case.category].append(caught)
        by_technique[case.technique].append(caught)
        if caught and flag is not None:
            labels.update(flag.labels)
        else:
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
        "rates": {t.value: _rates(detected[t.value], totals) for t in THRESHOLDS},
        "by_category": _grouped(by_category),
        "by_technique": _grouped(by_technique),
        "labels": dict(sorted(labels.items())),
        "missed": sorted(missed, key=lambda e: e["case"]),
    }


def evaluate(suite: Suite, scanner: Scanner) -> dict[str, Any]:
    """Return every number the report needs, as plain JSON-ready data."""
    clean: Servers = {server.name: list(server.tools) for server in suite.servers}
    return {
        "schema_version": "2",
        "scanner": {"name": scanner.name, "version": scanner.version, "notes": list(scanner.notes)},
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
            scenario: _detection(scanner, suite.poisoned, clean, scenario) for scenario in SCENARIOS
        },
        "false_positives": {
            scenario: _false_positives(scanner, clean, scenario) for scenario in FP_SCENARIOS
        },
    }


def evaluate_cases(suite: CaseSuite, scanner: Scanner) -> dict[str, Any]:
    """Judge whole tool lists: is each malicious one flagged, is each benign one left alone?

    The whole suite is held out, so no text from it is written to the result.
    """
    verdicts = scanner.scan_many([case.servers for case in suite.cases])
    worst: list[Flag | None] = []
    for case_verdicts in verdicts:
        flags = [flag for (server, _), flag in case_verdicts.items() if server == SUBJECT]
        worst.append(min(flags, key=lambda flag: flag.severity.rank) if flags else None)

    def rates(malicious: bool, **only: str) -> dict[str, Any]:
        chosen = [
            flag
            for case, flag in zip(suite.cases, worst, strict=True)
            if case.malicious is malicious
            and all(getattr(case, field) == value for field, value in only.items())
        ]
        return {
            t.value: Rate(sum(_reaches(flag, t) for flag in chosen), len(chosen)).as_dict()
            for t in THRESHOLDS
        }

    malicious = [case for case in suite.cases if case.malicious]
    benign = [case for case in suite.cases if not case.malicious]
    labels: Counter[str] = Counter()
    for case, case_verdicts in zip(suite.cases, verdicts, strict=True):
        if case.malicious:
            seen = {
                label
                for (server, _), flag in case_verdicts.items()
                if server == SUBJECT and _reaches(flag, BREAKDOWN)
                for label in flag.labels
            }
            labels.update(seen)
    return {
        "schema_version": "2",
        "kind": "cases",
        "scanner": {"name": scanner.name, "version": scanner.version, "notes": list(scanner.notes)},
        "suite": {
            "name": suite.name,
            "description": suite.description,
            "notes": list(suite.notes),
            "malicious_cases": len(malicious),
            "benign_cases": len(benign),
            "sources": [
                {
                    "name": source.name,
                    "url": source.url,
                    "revision": source.revision,
                    "licence": source.licence,
                    "malicious_cases": sum(c.source == source.name for c in malicious),
                    "benign_cases": sum(c.source == source.name for c in benign),
                }
                for source in suite.sources
            ],
        },
        "detection": {
            "rates": rates(True),
            "by_source": {s.name: rates(True, source=s.name) for s in suite.sources},
            "by_category": {
                category: rates(True, category=category)
                for category in sorted({case.category for case in malicious})
            },
            "labels": dict(sorted(labels.items())),
            "missed": sorted(
                case.case_id
                for case, flag in zip(suite.cases, worst, strict=True)
                if case.malicious and not _reaches(flag, BREAKDOWN)
            ),
        },
        "false_positives": {
            "rates": rates(False),
            "flagged": sorted(
                case.case_id
                for case, flag in zip(suite.cases, worst, strict=True)
                if not case.malicious and _reaches(flag, BREAKDOWN)
            ),
        },
    }
