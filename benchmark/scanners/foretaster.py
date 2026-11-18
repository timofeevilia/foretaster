"""Foretaster itself, driven through its library API."""

from pathlib import Path

from benchmark.scanners.base import Flag, Servers, Verdicts
from foretaster import __version__
from foretaster.engine import run_rules
from foretaster.models import Location
from foretaster.rules import ScanTarget
from foretaster.tool_manifest import inventory_from_tools


class ForetasterScanner:
    name = "foretaster"
    version = __version__
    notes: tuple[str, ...] = ("Deterministic rules only; no LLM layer exists yet.",)

    def scan_many(self, batches: list[Servers]) -> list[Verdicts]:
        return [self._scan(batch) for batch in batches]

    def _scan(self, servers: Servers) -> Verdicts:
        origin = Location(path=Path("benchmark.json"))
        inventories = tuple(
            inventory_from_tools(name, origin, tools, None) for name, tools in servers.items()
        )
        result = run_rules(ScanTarget((), inventories))
        if result.rule_errors:
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
