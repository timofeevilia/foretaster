"""Remember verdicts, so that unchanged tools are not sent to the model again."""

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

FORMAT = 1


def default_cache_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "foretaster" / "llm-verdicts.json"


class VerdictCache:
    """A JSON file of verdicts keyed by a digest of everything that produced them.

    The file holds no tool text apart from the short excerpt quoted in a
    verdict. A file that cannot be read is treated as empty: the cache is an
    optimisation and must never decide the outcome of a scan.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entries: dict[str, dict[str, Any]] = {}
        self._dirty = False
        if path is not None:
            self._entries = _read(path)

    def get(self, key: str) -> dict[str, Any] | None:
        return self._entries.get(key)

    def put(self, key: str, verdict: dict[str, Any]) -> None:
        if self._entries.get(key) != verdict:
            self._entries[key] = verdict
            self._dirty = True

    def save(self) -> None:
        """Write the file if anything changed. Failure to write is not an error."""
        if self.path is None or not self._dirty:
            return
        payload = json.dumps({"format": FORMAT, "entries": self._entries}, sort_keys=True)
        temporary = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(payload, encoding="utf-8")
            temporary.replace(self.path)
        except OSError:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            return
        self._dirty = False


def _read(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        return {}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        return {}
    return {str(key): value for key, value in entries.items() if isinstance(value, dict)}
