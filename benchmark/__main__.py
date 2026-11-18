"""Command line: ``python -m benchmark run mcptox``."""

import argparse
import json
from pathlib import Path

from benchmark.report import render_markdown
from benchmark.runner import evaluate
from benchmark.suites import LOADERS

ROOT = Path(__file__).parent


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run a suite and write its results.")
    run.add_argument("suite", choices=sorted(LOADERS))
    run.add_argument("--cache-dir", type=Path, default=ROOT / ".cache")
    run.add_argument("--output-dir", type=Path, default=ROOT / "results")
    run.add_argument(
        "--label", default="", help="Suffix for the result files, e.g. 'blind' for a first run."
    )
    arguments = parser.parse_args()

    suite = LOADERS[arguments.suite](arguments.cache_dir)
    result = evaluate(suite)
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    stem = arguments.suite + (f"-{arguments.label}" if arguments.label else "")
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
