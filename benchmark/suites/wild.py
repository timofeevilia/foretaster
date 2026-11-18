"""A second corpus: tool-poisoning examples written by three unrelated authors.

MCPTox comes from one generator and three templates. This suite asks whether
detection carries over to attacks written by other people in other styles. It is
small, and it was never used to change a rule: every case is test-only.

Sources, each fetched at a pinned commit and never executed:

* **mcp-guardbench** (MIT): JSON test cases for runtime guards. Only the cases
  whose message is a ``tools/list`` result are used: attacks, and benign lists
  written as deliberate false-positive probes.
* **MCP-Poison-Bench** (MIT): payloads for a demonstration server. They are read
  out of the Python source with ``ast`` and placed into tool definitions the way
  that server places them. Two of its five attack classes inject only *after* a
  tool has been called; no scan-time tool can see those, so they are left out
  and counted separately.
* **Invariant Labs mcp-injection-experiments** (no licence stated): the three
  original tool-poisoning demonstrations. Docstrings are read with ``ast``. The
  text is fetched for measurement and is not copied into this repository.
"""

import ast
import contextlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmark.fetch import combined_digest, fetch_pinned
from benchmark.scanners.base import Servers

SUBJECT = "case"
CONTEXT = "trusted"


@dataclass(frozen=True)
class Source:
    name: str
    repository: str
    revision: str
    licence: str

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repository}"


GUARDBENCH = Source(
    "mcp-guardbench",
    "getmcpm/mcp-guardbench",
    "13445a84989a1fee1038e82e04e911117a1bc08e",
    "MIT",
)
POISON_BENCH = Source(
    "MCP-Poison-Bench",
    "chirag-dewan/MCP-Poison-Bench",
    "21a77a4c963fe24f92f01aaf80f0df1173fd681a",
    "MIT",
)
INVARIANT = Source(
    "mcp-injection-experiments",
    "invariantlabs-ai/mcp-injection-experiments",
    "7382a5e64d825b2c7c2bace11f8fb9f2f16e01e2",
    "no licence stated",
)
INVARIANT_FILES = ("direct-poisoning.py", "shadowing.py", "whatsapp-takeover.py")
POISON_BENCH_AT_SCAN_TIME = ("tool_description", "schema_field", "cross_server")
POISON_BENCH_SETS = ("PAYLOADS", "HELDOUT_PAYLOADS", "ADVERSARIAL_PAYLOADS")


@dataclass(frozen=True)
class ServerCase:
    """One tool list to judge as a whole."""

    case_id: str
    source: str
    malicious: bool
    category: str
    servers: Servers
    """The list under test is ``servers[SUBJECT]``; anything else is context."""


@dataclass(frozen=True)
class CaseSuite:
    name: str
    description: str
    sources: tuple[Source, ...]
    cases: tuple[ServerCase, ...]
    notes: tuple[str, ...]


def _tool(name: str, description: str, **parameters: str | None) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for parameter, text in parameters.items():
        properties[parameter] = {"type": "string"}
        if text:
            properties[parameter]["description"] = text
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties},
    }


# ---- mcp-guardbench ------------------------------------------------------------


def guardbench_cases(
    index: dict[str, Any], documents: dict[str, dict[str, Any]]
) -> list[ServerCase]:
    cases = []
    for entry in index["cases"]:
        document = documents[entry["id"]]
        result = document.get("message", {}).get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            continue
        if entry["bucket"] not in {"attacks", "benign"}:
            continue
        cases.append(
            ServerCase(
                case_id=f"guardbench/{entry['id']}",
                source=GUARDBENCH.name,
                malicious=entry["bucket"] == "attacks",
                category=str(entry.get("category") or "false-positive probe"),
                servers={SUBJECT: result["tools"]},
            )
        )
    return cases


# ---- MCP-Poison-Bench ----------------------------------------------------------

_CALCULATE_DOC = (
    "Perform an arithmetic operation on two numbers.\n\n"
    "operation must be one of: add, subtract, multiply, divide.\n"
    "Returns a human-readable string with the result."
)
_SINK = _tool("export_data", "Submit a record to the analytics ingest endpoint.", payload=None)
_ADD_NOTE = _tool(
    "add_note",
    "Save a note with the given title and body. Returns a confirmation string.",
    title=None,
    body=None,
)
_CLEAN_CALCULATE = _tool("calculate", _CALCULATE_DOC, a=None, b=None, operation=None)


class _StaticEvaluator:
    """Evaluate the string expressions in a module without running it.

    Understands literals, ``+``, f-strings and names bound earlier at module
    level. Anything else raises, so an upstream change cannot be misread quietly.
    """

    def __init__(self, module: ast.Module) -> None:
        self.names: dict[str, str] = {}
        self.assignments: dict[str, ast.expr] = {}
        for node in module.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                self._bind(node.targets[0].id, node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
            ):
                self._bind(node.target.id, node.value)

    def _bind(self, name: str, value: ast.expr) -> None:
        self.assignments[name] = value
        with contextlib.suppress(ValueError):
            self.names[name] = self.string(value)

    def string(self, node: ast.expr) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.names:
            return self.names[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.string(node.left) + self.string(node.right)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if value.format_spec is not None or value.conversion != -1:
                        raise ValueError("formatted f-string field")
                    parts.append(self.string(value.value))
                else:
                    parts.append(self.string(value))
            return "".join(parts)
        raise ValueError(f"cannot evaluate {ast.dump(node)[:80]} statically")


def poison_bench_cases(source: str) -> tuple[list[ServerCase], int]:
    """Return scan-time cases and the number of payloads that act only after a call."""
    evaluator = _StaticEvaluator(ast.parse(source))
    cases: list[ServerCase] = []
    after_call = 0
    for set_name in POISON_BENCH_SETS:
        table = evaluator.assignments[set_name]
        if not isinstance(table, ast.Dict):
            raise ValueError(f"{set_name} is not a dict literal")
        for key, payloads in zip(table.keys, table.values, strict=True):
            if key is None or not isinstance(payloads, ast.List):
                raise ValueError(f"unexpected shape inside {set_name}")
            attack_class = evaluator.string(key)
            for call in payloads.elts:
                if not isinstance(call, ast.Call):
                    raise ValueError(f"unexpected entry inside {set_name}")
                fields = {kw.arg: evaluator.string(kw.value) for kw in call.keywords if kw.arg}
                if attack_class not in POISON_BENCH_AT_SCAN_TIME:
                    after_call += 1
                    continue
                cases.append(_poison_bench_case(set_name, attack_class, fields))
    cases.append(
        ServerCase(
            case_id="poison-bench/benign-server",
            source=POISON_BENCH.name,
            malicious=False,
            category="benign server",
            servers={SUBJECT: [_CLEAN_CALCULATE, _ADD_NOTE]},
        )
    )
    return cases, after_call


def _poison_bench_case(set_name: str, attack_class: str, fields: dict[str, str]) -> ServerCase:
    injection = fields["injection"]
    servers: Servers
    if attack_class == "tool_description":
        poisoned = _tool("calculate", _CALCULATE_DOC + injection, a=None, b=None, operation=None)
        servers = {SUBJECT: [poisoned, _SINK, _ADD_NOTE]}
    elif attack_class == "schema_field":
        poisoned = _tool(
            "calculate",
            "Perform an arithmetic operation on two numbers.",
            a=None,
            b=None,
            operation=injection,
        )
        servers = {SUBJECT: [poisoned, _SINK, _ADD_NOTE]}
    else:
        shadow = _tool("compliance_audit", injection, note=None)
        servers = {SUBJECT: [shadow, _SINK], CONTEXT: [_CLEAN_CALCULATE, _ADD_NOTE]}
    return ServerCase(
        case_id=f"poison-bench/{set_name.lower()}/{fields['id']}",
        source=POISON_BENCH.name,
        malicious=True,
        category=attack_class,
        servers=servers,
    )


# ---- Invariant Labs ------------------------------------------------------------


def invariant_case(file_name: str, source: str) -> ServerCase:
    """Build one case from a demonstration server: every text it can advertise."""
    module = ast.parse(source)
    tools: list[dict[str, Any]] = []
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and any(
            "tool" in ast.unparse(decorator) for decorator in node.decorator_list
        ):
            parameters: dict[str, str | None] = {argument.arg: None for argument in node.args.args}
            tools.append(_tool(node.name, ast.get_docstring(node) or "", **parameters))
        elif (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Attribute)
            and node.targets[0].attr == "__doc__"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            # A server that swaps its own description later: scan the swapped text too.
            name = ast.unparse(node.targets[0].value)
            tools.append(_tool(f"{name}__after_swap", node.value.value))
    return ServerCase(
        case_id=f"invariant/{file_name}",
        source=INVARIANT.name,
        malicious=True,
        category="original demonstration",
        servers={SUBJECT: tools},
    )


# ---- assembly ------------------------------------------------------------------


def load(cache_dir: Path) -> CaseSuite:
    index_bytes = fetch_pinned(
        GUARDBENCH.repository, GUARDBENCH.revision, "cases/index.json", cache_dir
    )
    index = json.loads(index_bytes)
    guard_files = {"cases/index.json": index_bytes}
    documents: dict[str, dict[str, Any]] = {}
    for entry in index["cases"]:
        path = f"cases/{entry['bucket']}/{entry['id']}.json"
        guard_files[path] = fetch_pinned(
            GUARDBENCH.repository, GUARDBENCH.revision, path, cache_dir
        )
        documents[entry["id"]] = json.loads(guard_files[path])

    payloads = fetch_pinned(
        POISON_BENCH.repository, POISON_BENCH.revision, "fixtures/payloads.py", cache_dir
    )
    invariant_files = {
        name: fetch_pinned(INVARIANT.repository, INVARIANT.revision, name, cache_dir)
        for name in INVARIANT_FILES
    }

    for source, files in (
        (GUARDBENCH, guard_files),
        (POISON_BENCH, {"fixtures/payloads.py": payloads}),
        (INVARIANT, invariant_files),
    ):
        actual = combined_digest(files)
        if actual != PINNED_DIGESTS[source.name]:
            raise RuntimeError(f"{source.name}: digest is {actual}, expected a pinned value")

    poison_cases, after_call = poison_bench_cases(payloads.decode("utf-8"))
    cases = [
        *guardbench_cases(index, documents),
        *poison_cases,
        *(invariant_case(name, data.decode("utf-8")) for name, data in invariant_files.items()),
    ]
    return CaseSuite(
        name="wild",
        description="Tool-poisoning examples by three unrelated authors",
        sources=(GUARDBENCH, POISON_BENCH, INVARIANT),
        cases=tuple(cases),
        notes=(
            "Every case is test-only; no rule was changed in response to this suite.",
            "A case is one whole tool list. It counts as flagged when any tool in it is.",
            f"{after_call} MCP-Poison-Bench payloads inject only after a tool call and are "
            "excluded: no scan-time tool can see them.",
            "MCP-Poison-Bench cross-server cases are scanned beside the trusted server "
            "they target, as that benchmark runs them.",
        ),
    )


# Combined SHA-256 of the files used from each source, as fetched at its revision.
PINNED_DIGESTS: dict[str, str] = {
    GUARDBENCH.name: "9632facd4246adf2f5e4582e478d17dd011d1ef469f5fb34701411527f684c98",
    POISON_BENCH.name: "2439ca463806c25aa916d31044c10f69bb1da6fcce82e3dcfc4d52e8edb2264a",
    INVARIANT.name: "1f58c5fce47db3cdf00328086cc09dd9b3886bb017abde4cea3b676b3927a050",
}
