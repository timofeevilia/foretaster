"""Build the static site into ``site/dist``.

The site has no server-side code. The demo runs the real scanner in the visitor's
browser with Pyodide, which is fetched here at a pinned version, verified, and
served from the site itself so that pages never contact a third party.

    uv run python site/build.py
"""

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from importlib.metadata import version
from pathlib import Path
from typing import Any

from content import COMMAND, CONTENT, REPOSITORY

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
RESULTS = PROJECT / "benchmark" / "results"

PYODIDE_VERSION = "314.0.8"
PYODIDE_TARBALL_SHA256 = "9a52704e0ae5b07aaacb8e4fed9f1658e8024694a078695ea45ac79dee4cefcb"
PYODIDE_CORE = (
    "pyodide.mjs",
    "pyodide.asm.mjs",
    "pyodide.asm.wasm",
    "python_stdlib.zip",
    "pyodide-lock.json",
)
# pydantic and what it needs, by their keys in pyodide-lock.json.
PYODIDE_PACKAGES = (
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "annotated-types",
    "typing-inspection",
)
PLAIN = re.compile(r"\{\{(\w+)\}\}")
RAW = re.compile(r"\{\{\{(\w+)\}\}\}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_runtime(cache: Path) -> Path:
    """Return a directory holding the pinned Pyodide files, downloading what is missing."""
    runtime = cache / f"pyodide-{PYODIDE_VERSION}"
    runtime.mkdir(parents=True, exist_ok=True)
    if not all((runtime / name).exists() for name in PYODIDE_CORE):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(  # noqa: S603 - fixed arguments
                ["npm", "pack", f"pyodide@{PYODIDE_VERSION}", "--silent"],  # noqa: S607
                cwd=directory,
                check=True,
                capture_output=True,
            )
            tarball = Path(directory) / f"pyodide-{PYODIDE_VERSION}.tgz"
            actual = sha256(tarball)
            if actual != PYODIDE_TARBALL_SHA256:
                raise RuntimeError(f"pyodide tarball SHA-256 is {actual}, expected a pinned value")
            with tarfile.open(tarball) as archive:
                for name in PYODIDE_CORE:
                    member = archive.extractfile(f"package/{name}")
                    if member is None:
                        raise RuntimeError(f"{name} is missing from the pyodide tarball")
                    (runtime / name).write_bytes(member.read())

    lock = json.loads((runtime / "pyodide-lock.json").read_text(encoding="utf-8"))
    for key in PYODIDE_PACKAGES:
        entry = lock["packages"][key]
        target = runtime / entry["file_name"]
        if not target.exists() or sha256(target) != entry["sha256"]:
            url = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/{entry['file_name']}"
            with urllib.request.urlopen(url, timeout=120) as response:
                target.write_bytes(response.read())
        if sha256(target) != entry["sha256"]:
            raise RuntimeError(f"{entry['file_name']} does not match the Pyodide lock file")
    return runtime


def build_wheel(destination: Path) -> str:
    """Build the scanner's wheel into ``destination`` and return its file name."""
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(  # noqa: S603 - fixed arguments
            ["uv", "build", "--wheel", "--out-dir", directory],  # noqa: S607
            cwd=PROJECT,
            check=True,
            capture_output=True,
        )
        (wheel,) = Path(directory).glob("foretaster-*.whl")
        shutil.copy(wheel, destination / wheel.name)
        return wheel.name


def load_numbers() -> dict[str, Any]:
    """Collect the figures shown on the page from the committed benchmark results."""

    def read(name: str) -> dict[str, Any]:
        data: dict[str, Any] = json.loads((RESULTS / name).read_text(encoding="utf-8"))
        return data

    blind = read("mcptox-foretaster-blind.json")
    current = read("mcptox-foretaster.json")
    wild = read("wild-foretaster.json")
    by_source = wild["detection"]["by_source"]
    devices = [
        by_source["mcp-guardbench"]["medium"],
        by_source["mcp-injection-experiments"]["medium"],
    ]
    return {
        "before": blind["detection"]["alone"]["rates"]["medium"]["test"],
        "after": current["detection"]["alone"]["rates"]["medium"]["test"],
        "false_positives": current["false_positives"]["alone"]["rates"]["medium"]["test"],
        "wild": wild["detection"]["rates"]["medium"],
        "wild_devices": {
            "hits": sum(entry["hits"] for entry in devices),
            "total": sum(entry["total"] for entry in devices),
        },
        "wild_plain": by_source["MCP-Poison-Bench"]["medium"],
        "traps": wild["false_positives"]["rates"]["medium"],
    }


def percent(entry: dict[str, Any], lang: str) -> str:
    text = f"{entry['hits'] / entry['total']:.1%}"
    return text.replace(".", ",") if lang == "ru" else text


def chart(bars: list[tuple[str, dict[str, Any], str]], lang: str, of: str) -> str:
    """Horizontal bars as inline SVG. Geometry sits in attributes, so no inline CSS is needed."""
    row, label_width, track, height = 62, 0, 520, 0
    parts = []
    for index, (label, entry, colour) in enumerate(bars):
        y = index * row
        width = max(4.0, track * entry["hits"] / entry["total"])
        parts.append(
            f'<text x="{label_width}" y="{y + 16}" font-size="15">{html.escape(label)}</text>'
            f'<rect x="0" y="{y + 24}" width="{track}" height="22" rx="4" fill="#f1e9f3"/>'
            f'<rect x="0" y="{y + 24}" width="{width:.1f}" height="22" rx="4" fill="{colour}"/>'
            f'<text class="num" x="{track + 14}" y="{y + 43}" font-size="24">'
            f"{percent(entry, lang)}</text>"
            f'<text class="sub" x="{track + 14}" y="{y + 16}" font-size="13">'
            f"{entry['hits']} {html.escape(of)} {entry['total']}</text>"
        )
        height = y + row
    return (
        f'<svg viewBox="0 0 640 {height}" role="img" aria-label="'
        + html.escape("; ".join(f"{label}: {percent(e, lang)}" for label, e, _ in bars))
        + '">'
        + "".join(parts)
        + "</svg>"
    )


def render(lang: str, numbers: dict[str, Any], wheel: str, examples: dict[str, str]) -> str:
    text = dict(CONTENT[lang])
    base = "" if lang == "en" else "../"
    plum, teal = "#7e4b82", "#4c858c"
    values = {
        **text,
        "base": base,
        "base_lang": "./",
        "other_href": "ru/" if lang == "en" else "../",
        "repository": REPOSITORY,
        "command": COMMAND,
        "version": version("foretaster"),
        "caveat_2": text["caveat_2"].format(
            fp_hits=numbers["false_positives"]["hits"],
            fp_total=numbers["false_positives"]["total"],
            trap_hits=numbers["traps"]["hits"],
            trap_total=numbers["traps"]["total"],
        ),
    }
    ui = {key[3:]: value for key, value in text.items() if key.startswith("ui_")}
    ui.update({"base": base, "wheel": wheel})
    raw = {
        "chart_1": chart(
            [
                (text["bar_before"], numbers["before"], "#b99dbc"),
                (text["bar_after"], numbers["after"], plum),
            ],
            lang,
            text["of"],
        ),
        "chart_2": chart(
            [
                (text["bar_all"], numbers["wild"], teal),
                (text["bar_devices"], numbers["wild_devices"], "#8fb8bd"),
                (text["bar_plain"], numbers["wild_plain"], "#8fb8bd"),
            ],
            lang,
            text["of"],
        ),
        # "<" is escaped so that no text can close the script element it sits in.
        "ui_json": json.dumps(ui, ensure_ascii=False).replace("<", "\\u003c"),
        "example_config": json.dumps(examples["config"]).replace("<", "\\u003c"),
        "example_tools": json.dumps(examples["tools"]).replace("<", "\\u003c"),
    }
    template = (ROOT / "src" / "template.html").read_text(encoding="utf-8")
    template = RAW.sub(lambda match: raw[match.group(1)], template)
    return PLAIN.sub(lambda match: html.escape(str(values[match.group(1)])), template)


FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<path d="M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13z" fill="#7e4b82"/>'
    '<path d="m20 32 9 9 16-18" fill="none" stroke="#fff" stroke-width="7" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def build(dist: Path, cache: Path) -> None:
    if dist.exists():
        shutil.rmtree(dist)
    (dist / "ru").mkdir(parents=True)
    for name in ("styles.css", "app.js"):
        shutil.copy(ROOT / "src" / name, dist / name)
    (dist / "favicon.svg").write_text(FAVICON, encoding="utf-8")
    shutil.copy(ROOT / "htaccess", dist / ".htaccess")

    runtime = fetch_runtime(cache)
    (dist / "pyodide").mkdir()
    for path in runtime.iterdir():
        shutil.copy(path, dist / "pyodide" / path.name)
    wheel = build_wheel(dist / "pkg")

    examples = {
        "config": (PROJECT / "examples" / "risky-mcp.json").read_text(encoding="utf-8"),
        "tools": (PROJECT / "examples" / "poisoned-tools.json").read_text(encoding="utf-8"),
    }
    numbers = load_numbers()
    (dist / "index.html").write_text(render("en", numbers, wheel, examples), encoding="utf-8")
    (dist / "ru" / "index.html").write_text(
        render("ru", numbers, wheel, examples), encoding="utf-8"
    )
    size = sum(path.stat().st_size for path in dist.rglob("*") if path.is_file())
    print(f"built {dist} ({size / 1_000_000:.1f} MB, wheel {wheel})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache")
    arguments = parser.parse_args()
    build(arguments.dist, arguments.cache)
