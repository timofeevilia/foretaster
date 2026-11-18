"""Cisco MCP Scanner (https://github.com/cisco-ai-defense/mcp-scanner), YARA analyzer only.

The scanner is driven through its published command line in offline mode::

    mcp-scanner --analyzers yara --format raw static --tools FILE

This is its free, key-less configuration. Its LLM and cloud analyzers are not
exercised, so the numbers describe that configuration and not the product at
its best.

The offline mode takes one flat tool list and judges every tool on its own, so
it cannot see which server a tool belongs to. All batches are therefore sent in
a single invocation and the verdicts are matched back by position. A check on
25 randomly chosen tools found no difference between a tool scanned alone and
the same tool scanned inside the full list.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from benchmark.scanners.base import Flag, Servers, Verdicts
from foretaster.models import Severity

_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
DISTRIBUTION = "cisco-ai-mcp-scanner"


class CiscoYaraScanner:
    name = "cisco-mcp-scanner (YARA only)"
    notes: tuple[str, ...] = (
        "Offline YARA analyzer only; the LLM and Cisco AI Defense analyzers were not used.",
        "Judges each tool on its own, so both detection scenarios give the same verdicts.",
    )

    def __init__(self, executable: Path) -> None:
        self.executable = executable
        self.version = self._installed_version()

    def _installed_version(self) -> str:
        python = self.executable.parent / "python"
        code = f"import importlib.metadata as m; print(m.version({DISTRIBUTION!r}))"
        result = subprocess.run(  # noqa: S603 - fixed arguments, path chosen by the operator
            [str(python), "-c", code], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()

    def scan_many(self, batches: list[Servers]) -> list[Verdicts]:
        owners: list[tuple[int, str, str]] = []
        tools: list[dict[str, Any]] = []
        for index, batch in enumerate(batches):
            for server, server_tools in batch.items():
                for tool in server_tools:
                    owners.append((index, server, str(tool["name"])))
                    tools.append(tool)
        results = self._run(tools)
        if len(results) != len(tools):
            raise RuntimeError(f"expected {len(tools)} verdicts, got {len(results)}")

        verdicts: list[Verdicts] = [{} for _ in batches]
        for (index, server, name), result in zip(owners, results, strict=True):
            if result.get("tool_name") != name:
                raise RuntimeError(f"verdict order mismatch at {name!r}")
            if result.get("status") != "completed":
                raise RuntimeError(f"scan of {name!r} ended as {result.get('status')!r}")
            finding = result["findings"]["yara_analyzer"]
            severity = _SEVERITY.get(finding["severity"])
            if severity is not None:
                verdicts[index][server, name] = Flag(
                    severity, tuple(finding["threat_names"]), finding["threat_summary"]
                )
        return verdicts

    def _run(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not tools:
            return []
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "tools.json"
            manifest.write_text(json.dumps({"tools": tools}), encoding="utf-8")
            completed = subprocess.run(  # noqa: S603 - fixed arguments, path chosen by the operator
                [
                    str(self.executable),
                    "--analyzers",
                    "yara",
                    "--format",
                    "raw",
                    "static",
                    "--tools",
                    str(manifest),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        output = completed.stdout
        document = json.loads(output[output.index("{") :])
        results: list[dict[str, Any]] = document["scan_results"]
        return results
