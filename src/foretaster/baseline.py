"""Remember what servers advertised, to notice when it changes.

A server can show a harmless tool description while it is being approved and
swap in a malicious one later (a "rug pull"). A baseline stores a digest of
every tool definition; a later scan compares against it.

Only digests are stored, never the text, so a baseline is safe to commit.
"""

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from foretaster.config_loader import ConfigLoadError, read_text
from foretaster.models import ServerInventory, ToolDefinition


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ServerFingerprint(_Model):
    instructions: str | None = None
    tools: dict[str, str] = {}


class Baseline(_Model):
    schema_version: Literal["1"] = "1"
    servers: dict[str, ServerFingerprint] = {}


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_tool(tool: ToolDefinition) -> str:
    """Digest everything about a tool that the model reads."""
    canonical = json.dumps(
        [tool.description, tool.input_schema],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return digest_text(canonical)


def build_baseline(inventories: Sequence[ServerInventory]) -> Baseline:
    """Fingerprint the given inventories. Servers are identified by name."""
    servers: dict[str, ServerFingerprint] = {}
    for inventory in inventories:
        servers[inventory.server] = ServerFingerprint(
            instructions=digest_text(inventory.instructions) if inventory.instructions else None,
            tools={tool.name: digest_tool(tool) for tool in inventory.tools},
        )
    return Baseline(servers=dict(sorted(servers.items())))


def load_baseline(path: Path) -> Baseline:
    try:
        return Baseline.model_validate_json(read_text(path))
    except ValidationError as exc:
        raise ConfigLoadError(path, f"not a valid baseline: {exc.error_count()} error(s)") from exc


def dump_baseline(baseline: Baseline) -> str:
    return baseline.model_dump_json(indent=2) + "\n"
