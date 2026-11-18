"""Command line: ``python -m benchmark run mcptox`` and ``python -m benchmark compare``."""

import argparse
import json
import os
from pathlib import Path

from benchmark.report import render_comparison, render_markdown
from benchmark.runner import evaluate
from benchmark.scanners import CiscoYaraScanner, ForetasterScanner, Scanner
from benchmark.suites import LOADERS

ROOT = Path(__file__).parent
SCANNERS = ("foretaster", "cisco-yara")


def _scanner(name: str, cisco_bin: Path | None) -> Scanner:
    if name == "foretaster":
        return ForetasterScanner()
    if cisco_bin is None:
        raise SystemExit(
            "cisco-yara needs the path to the mcp-scanner executable: "
            "pass --cisco-bin or set MCP_SCANNER_BIN"
        )
    return CiscoYaraScanner(cisco_bin)


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m benchmark")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run a suite with one scanner and write its results.")
    run.add_argument("suite", choices=sorted(LOADERS))
    run.add_argument("--scanner", choices=SCANNERS, default="foretaster")
    run.add_argument(
        "--cisco-bin",
        type=Path,
        default=Path(os.environ["MCP_SCANNER_BIN"]) if "MCP_SCANNER_BIN" in os.environ else None,
        help="Path to the mcp-scanner executable, for --scanner cisco-yara.",
    )
    run.add_argument("--cache-dir", type=Path, default=ROOT / ".cache")
    run.add_argument("--output-dir", type=Path, default=ROOT / "results")
    run.add_argument("--label", default="", help="Result file name; defaults to the scanner.")

    compare = commands.add_parser("compare", help="Combine result files into one table.")
    compare.add_argument("results", nargs="+", type=Path, help="Result JSON files to compare.")
    compare.add_argument("--output", type=Path, required=True)

    arguments = parser.parse_args()
    if arguments.command == "compare":
        results = [json.loads(path.read_text(encoding="utf-8")) for path in arguments.results]
        arguments.output.write_text(render_comparison(results), encoding="utf-8")
        print(f"wrote {arguments.output}")
        return

    suite = LOADERS[arguments.suite](arguments.cache_dir)
    result = evaluate(suite, _scanner(arguments.scanner, arguments.cisco_bin))
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{arguments.suite}-{arguments.label or arguments.scanner}"
    (arguments.output_dir / f"{stem}.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (arguments.output_dir / f"{stem}.md").write_text(render_markdown(result), encoding="utf-8")

    for scenario, detection in result["detection"].items():
        for threshold, rates in detection["rates"].items():
            print(f"detection ({scenario}) >= {threshold}: {rates['all']['rate']:.1%}")
    for scenario, entry in result["false_positives"].items():
        for threshold, rates in entry["rates"].items():
            print(f"false positives ({scenario}) >= {threshold}: {rates['all']['rate']:.1%}")


if __name__ == "__main__":
    main()
