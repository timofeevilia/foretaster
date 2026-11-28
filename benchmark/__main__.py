"""Command line: ``python -m benchmark run mcptox`` and ``python -m benchmark compare``."""

import argparse
import json
import os
from pathlib import Path

from benchmark.llm import PRICES, counting_reviewer, live_reviewer, usage_report
from benchmark.report import render_case_comparison, render_comparison, render_markdown
from benchmark.runner import evaluate, evaluate_cases
from benchmark.scanners import CiscoYaraScanner, ForetasterScanner, Scanner
from benchmark.suites import CASE_LOADERS, LOADERS
from foretaster.llm import Reviewer

ROOT = Path(__file__).parent
EFFORTS = ("low", "medium", "high", "xhigh", "max")
SCANNERS = ("foretaster", "foretaster+llm", "foretaster-llm-only", "cisco-yara")


def _scanner(name: str, cisco_bin: Path | None, reviewer: Reviewer | None) -> Scanner:
    if name == "foretaster":
        return ForetasterScanner()
    if name in {"foretaster+llm", "foretaster-llm-only"}:
        return ForetasterScanner(reviewer, patterns=name == "foretaster+llm")
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
    run.add_argument("suite", choices=sorted({*LOADERS, *CASE_LOADERS}))
    run.add_argument("--scanner", choices=SCANNERS, default="foretaster")
    run.add_argument(
        "--cisco-bin",
        type=Path,
        default=Path(os.environ["MCP_SCANNER_BIN"]) if "MCP_SCANNER_BIN" in os.environ else None,
        help="Path to the mcp-scanner executable, for --scanner cisco-yara.",
    )
    run.add_argument(
        "--llm-model", default="claude-opus-5-5", help="Reviewer model for the LLM scanners."
    )
    run.add_argument("--llm-effort", choices=EFFORTS, default="medium")
    run.add_argument("--llm-workers", type=int, default=4, help="Requests in flight at once.")
    run.add_argument(
        "--estimate",
        action="store_true",
        help="For an LLM scanner: count what would be sent and price it, without calling "
        "the API or writing results.",
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
        render = render_case_comparison if results[0].get("kind") == "cases" else render_comparison
        arguments.output.write_text(render(results), encoding="utf-8")
        print(f"wrote {arguments.output}")
        return

    reviewer: Reviewer | None = None
    if "llm" in arguments.scanner:
        if arguments.estimate:
            reviewer, counter = counting_reviewer(arguments.llm_model, arguments.llm_effort)
        else:
            reviewer = live_reviewer(
                arguments.llm_model,
                arguments.llm_effort,
                arguments.cache_dir,
                arguments.llm_workers,
            )
    elif arguments.estimate:
        raise SystemExit("--estimate applies to the LLM scanners only")
    scanner = _scanner(arguments.scanner, arguments.cisco_bin, reviewer)
    if arguments.estimate:
        if arguments.suite in CASE_LOADERS:
            evaluate_cases(CASE_LOADERS[arguments.suite](arguments.cache_dir), scanner)
        else:
            evaluate(LOADERS[arguments.suite](arguments.cache_dir), scanner)
        estimate = counter.estimate(arguments.llm_model)
        price = "unknown price" if estimate["usd"] is None else f"about ${estimate['usd']:.2f}"
        print(
            f"{arguments.suite} with {arguments.llm_model}: {estimate['items']} items in "
            f"{estimate['requests']} requests, roughly {estimate['input_tokens']:,} input and "
            f"{estimate['output_tokens']:,} output tokens, {price} "
            f"(list prices known for: {', '.join(PRICES)})"
        )
        return

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{arguments.suite}-{arguments.label or arguments.scanner}"
    if arguments.suite in CASE_LOADERS:
        result = evaluate_cases(CASE_LOADERS[arguments.suite](arguments.cache_dir), scanner)
        if reviewer is not None:
            result["llm"] = usage_report(reviewer)
        (arguments.output_dir / f"{stem}.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        for threshold, rate in result["detection"]["rates"].items():
            print(f"detection >= {threshold}: {rate['rate']:.1%} ({rate['hits']}/{rate['total']})")
        for threshold, rate in result["false_positives"]["rates"].items():
            print(
                f"false positives >= {threshold}: {rate['rate']:.1%} "
                f"({rate['hits']}/{rate['total']})"
            )
        return

    suite = LOADERS[arguments.suite](arguments.cache_dir)
    result = evaluate(suite, scanner)
    if reviewer is not None:
        result["llm"] = usage_report(reviewer)
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
