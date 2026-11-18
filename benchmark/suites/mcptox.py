"""MCPTox: tool-poisoning attacks built on 45 real-world MCP servers.

Wang et al., "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP
Servers" (arXiv:2508.14925). Data: https://github.com/zhiqiangwang4/MCPTox-Benchmark,
licensed CC BY 4.0. The data is downloaded at a pinned revision and verified by
SHA-256; it is not redistributed in this repository.

MCPTox was built to test whether *language models* obey poisoned tools. Here it
is reused to test whether a *scanner* notices them. Two things follow from the
original purpose:

* poisoned tools come with a name and a description but no parameter schema;
* the real servers' tools are stored as rendered prompt text, which is parsed
  back into name, description and parameter descriptions.
"""

import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from benchmark.cases import CleanServer, PoisonedTool, Suite

REVISION = "630121b3275f74cc72d000a7a056e4d3c68648ef"
BASE_URL = f"https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/{REVISION}"
FILES = {
    "pure_tool.json": "54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617",
    "response_all.json": "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03",
}

_TRAILER = "\n\nChoose the appropriate tool"
_BLOCK = re.compile(
    r"^Tool: (?P<name>[^\n]+)\nDescription: (?P<description>.*?)"
    r"(?:\nArguments:\n(?P<arguments>.*))?$",
    re.DOTALL,
)
_ARGUMENT = re.compile(r"^- (?P<name>[^:\n]+): (?P<description>.*)$", re.MULTILINE)


def fetch(cache_dir: Path) -> dict[str, Path]:
    """Download the pinned files into ``cache_dir`` unless already there and intact."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, expected in FILES.items():
        path = cache_dir / f"mcptox-{REVISION[:12]}-{name}"
        if not path.exists() or _sha256(path) != expected:
            with urllib.request.urlopen(f"{BASE_URL}/{name}", timeout=120) as response:  # noqa: S310
                path.write_bytes(response.read())
        actual = _sha256(path)
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 is {actual}, expected {expected}")
        paths[name] = path
    return paths


def load(cache_dir: Path) -> Suite:
    paths = fetch(cache_dir)
    return parse(
        json.loads(paths["pure_tool.json"].read_text(encoding="utf-8")),
        json.loads(paths["response_all.json"].read_text(encoding="utf-8")),
    )


def parse(pure_tool: list[dict[str, Any]], response_all: dict[str, Any]) -> Suite:
    """Build the suite from the two MCPTox files, already decoded."""
    servers = tuple(
        CleanServer(name, tuple(parse_clean_tools(entry["clean_system_promot"])))
        for name, entry in sorted(response_all["servers"].items())
    )
    poisoned = tuple(
        PoisonedTool(
            case_id=case_id,
            server=entry["server_name"],
            tool={
                "name": entry["tool_name"],
                "description": entry["tool_content"].strip(),
                "inputSchema": {"type": "object", "properties": {}},
            },
            category=entry["security risk"],
            technique=entry["paradigm"],
        )
        for group in pure_tool
        for case_id, entry in sorted(group.items())
    )
    return Suite(
        name="mcptox",
        description="Tool-poisoning attacks built on 45 real-world MCP servers",
        source="https://github.com/zhiqiangwang4/MCPTox-Benchmark",
        revision=REVISION,
        licence="CC BY 4.0 (MCPTox contributors)",
        servers=servers,
        poisoned=poisoned,
        notes=(
            "Poisoned tools carry no parameter schema, so parameter rules cannot fire on them.",
            "Clean tools are parsed back from rendered prompt text.",
        ),
    )


def parse_clean_tools(prompt: str) -> list[dict[str, Any]]:
    """Recover tool definitions from MCPTox's rendered system prompt."""
    tools: list[dict[str, Any]] = []
    body = prompt.split(_TRAILER, 1)[0]
    for chunk in re.split(r"\n+(?=Tool: )", body):
        block = _BLOCK.match(chunk.strip())
        if block is None:
            continue
        properties = {
            argument["name"].strip(): {
                "type": "string",
                "description": re.sub(r"\s*\(required\)\s*$", "", argument["description"]),
            }
            for argument in _ARGUMENT.finditer(block["arguments"] or "")
        }
        for spec in properties.values():
            if spec["description"] == "No description":
                del spec["description"]
        tools.append(
            {
                "name": block["name"].strip(),
                "description": block["description"].strip(),
                "inputSchema": {"type": "object", "properties": properties},
            }
        )
    return tools


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
