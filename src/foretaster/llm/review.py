"""Ask a language model whether tool definitions try to steer the agent.

The texts under review are written by a possible attacker and are designed to
manipulate language models, so the reviewer is treated as something that can be
fooled:

* its verdicts only ever add findings; they never remove what the pattern
  rules found;
* an answer that is missing, malformed or incomplete counts as a failure of
  the scan, never as a clean result;
* an excerpt it quotes is kept only if it really occurs in the reviewed text;
* texts are sent with credentials scrubbed and invisible characters escaped,
  and configuration files are never sent at all.
"""

import hashlib
import json
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from pydantic import BaseModel, ConfigDict, ValidationError

from foretaster.llm.cache import VerdictCache
from foretaster.llm.prompt import ANSWER_SCHEMA, PROMPT_VERSION, SYSTEM_PROMPT
from foretaster.models import ServerInventory
from foretaster.redact import scrub, truncate
from foretaster.textscan import decode_tags, parameters, printable, schema_texts

MAX_ITEM_CHARACTERS = 30_000
MAX_CHUNK_CHARACTERS = 30_000
MAX_CHUNK_ITEMS = 12
MAX_SIBLING_NAMES = 300
MAX_REASON_CHARACTERS = 300
MAX_QUOTE_CHARACTERS = 200
DEFAULT_WORKERS = 4


class VerdictKind(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Category(StrEnum):
    NONE = "none"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    CROSS_TOOL_MANIPULATION = "cross_tool_manipulation"
    CONCEALMENT = "concealment"
    DESTRUCTIVE_ACTION = "destructive_action"
    OTHER = "other"


class Verdict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: VerdictKind
    category: Category
    reason: str
    quote: str = ""


class _Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class Entry(Verdict):
        id: int

    verdicts: list[Entry]


class ModelError(Exception):
    """The model could not be reached or did not give a usable answer."""


class AnswerError(ModelError):
    """The model answered, but not with a verdict for exactly the items it was given."""


class Model(Protocol):
    """A provider of completions. Everything provider-specific sits behind this."""

    identity: str
    """Provider, model and settings; part of every cache key."""

    def complete(self, system: str, document: str, schema: dict[str, Any]) -> str:
        """Return the model's answer as JSON text conforming to ``schema``.

        Raises ``ModelError`` when there is no usable answer.
        """
        ...


@dataclass(frozen=True)
class Item:
    """One thing a model would read: a tool definition or a server's instructions."""

    inventory: int
    """Index of the inventory the item came from."""
    pointer: str
    tool: str | None
    payload: dict[str, Any]
    """What is sent to the model, already scrubbed and escaped."""
    text: str
    """Every string in ``payload``, for checking quoted excerpts."""
    key: str = field(compare=False, default="")


class Failure(NamedTuple):
    item: Item
    reason: str


@dataclass
class Stats:
    items: int = 0
    cached: int = 0
    requests: int = 0
    failed: int = 0


class Outcome(NamedTuple):
    verdicts: tuple[tuple[Item, Verdict], ...]
    failures: tuple[Failure, ...]


def _clean(text: str) -> str:
    return scrub(printable(text))


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def _add_hidden(payload: dict[str, Any], originals: Sequence[str]) -> None:
    """Spell out a message hidden in Unicode tag characters, which escapes alone obscure."""
    hidden = " ".join(filter(None, (decode_tags(text) for text in originals)))
    if hidden:
        payload["hidden_text"] = _clean(hidden)


def collect_items(inventories: Sequence[ServerInventory], identity: str) -> list[Item]:
    """Turn inventories into reviewable items with their cache keys."""
    items: list[Item] = []
    for index, inventory in enumerate(inventories):
        base = inventory.origin.pointer
        server = _clean(inventory.server)
        siblings = sorted(_clean(tool.name) for tool in inventory.tools)
        entries: list[tuple[str, str | None, dict[str, Any]]] = []
        if inventory.instructions:
            payload: dict[str, Any] = {
                "kind": "server instructions",
                "text": _clean(inventory.instructions),
            }
            _add_hidden(payload, [inventory.instructions])
            entries.append((f"{base}/instructions", None, payload))
        for position, tool in enumerate(inventory.tools):
            texts = list(schema_texts(tool.input_schema))
            payload = {
                "kind": "tool",
                "name": _clean(tool.name),
                "description": _clean(tool.description),
                "parameters": sorted(_clean(name) for name in parameters(tool.input_schema)),
                "parameter_texts": [
                    {"where": _clean(where), "text": _clean(text)} for where, text in texts
                ],
            }
            _add_hidden(payload, [tool.name, tool.description, *(text for _, text in texts)])
            entries.append((f"{base}/tools/{position}", tool.name, payload))
        for pointer, name, payload in entries:
            digest = hashlib.sha256(
                json.dumps(
                    {
                        "model": identity,
                        "prompt": PROMPT_VERSION,
                        "server": server,
                        "tools": siblings,
                        "item": payload,
                    },
                    sort_keys=True,
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            items.append(Item(index, pointer, name, payload, "\n".join(_strings(payload)), digest))
    return items


def build_document(inventory: ServerInventory, chunk: Sequence[Item]) -> str:
    """The user message for one request: one server, some of its items."""
    names = sorted(_clean(tool.name) for tool in inventory.tools)
    document = {
        "server": _clean(inventory.server),
        "all_tools_on_this_server": names[:MAX_SIBLING_NAMES],
        "items": [{"id": number, **item.payload} for number, item in enumerate(chunk, start=1)],
    }
    return json.dumps(document, ensure_ascii=False, indent=1)


def parse_answer(text: str, chunk: Sequence[Item]) -> list[Verdict]:
    """Validate the model's answer against the chunk it was asked about.

    The answer must hold exactly one verdict per item. Anything else is
    rejected whole: a reviewer that skipped an item, or was talked into
    answering about something else, has not reviewed the chunk.
    """
    try:
        answer = _Answer.model_validate_json(text)
    except ValidationError as exc:
        raise AnswerError(
            f"the answer does not have the expected shape ({exc.error_count()} problem(s))"
        ) from exc
    by_id: dict[int, Verdict] = {}
    for entry in answer.verdicts:
        if entry.id in by_id:
            raise AnswerError(f"the answer gives two verdicts for item {entry.id}")
        by_id[entry.id] = entry
    expected = set(range(1, len(chunk) + 1))
    if set(by_id) != expected:
        missing = sorted(expected - set(by_id))
        extra = sorted(set(by_id) - expected)
        raise AnswerError(
            f"the answer does not cover the items it was given (missing {missing}, "
            f"unexpected {extra})"
        )
    verdicts: list[Verdict] = []
    for number, item in enumerate(chunk, start=1):
        given = by_id[number]
        quote = " ".join(given.quote.split())
        if quote and quote not in " ".join(item.text.split()):
            quote = ""
        verdicts.append(
            Verdict(
                verdict=given.verdict,
                category=given.category,
                reason=truncate(" ".join(given.reason.split()), MAX_REASON_CHARACTERS),
                quote=truncate(quote, MAX_QUOTE_CHARACTERS),
            )
        )
    return verdicts


def _chunks(items: Sequence[Item]) -> list[list[Item]]:
    """Group items of one server into requests of bounded size."""
    chunks: list[list[Item]] = []
    current: list[Item] = []
    size = 0
    for item in items:
        length = len(item.text)
        if current and (len(current) >= MAX_CHUNK_ITEMS or size + length > MAX_CHUNK_CHARACTERS):
            chunks.append(current)
            current, size = [], 0
        current.append(item)
        size += length
    if current:
        chunks.append(current)
    return chunks


class Reviewer:
    """Review inventories with a model, using and filling a verdict cache."""

    def __init__(
        self,
        model: Model,
        cache: VerdictCache | None = None,
        *,
        workers: int = DEFAULT_WORKERS,
    ) -> None:
        self.model = model
        self.cache = cache or VerdictCache()
        self.workers = max(1, workers)
        self.stats = Stats()

    def review(self, inventories: Sequence[ServerInventory]) -> Outcome:
        items = collect_items(inventories, self.model.identity)
        self.stats.items += len(items)
        verdicts: dict[int, Verdict] = {}
        failures: list[Failure] = []
        pending: dict[int, list[tuple[int, Item]]] = {}
        for position, item in enumerate(items):
            cached = self._cached(item)
            if cached is not None:
                verdicts[position] = cached
                self.stats.cached += 1
            elif len(item.text) > MAX_ITEM_CHARACTERS:
                failures.append(
                    Failure(item, f"the text is too long to review ({len(item.text)} characters)")
                )
            else:
                pending.setdefault(item.inventory, []).append((position, item))

        jobs: list[tuple[ServerInventory, list[tuple[int, Item]]]] = []
        for index, entries in pending.items():
            by_item = {id(item): position for position, item in entries}
            for chunk in _chunks([item for _, item in entries]):
                jobs.append((inventories[index], [(by_item[id(item)], item) for item in chunk]))

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = list(pool.map(lambda job: self._ask(job[0], [i for _, i in job[1]]), jobs))
        for (_, entries), result in zip(jobs, results, strict=True):
            if isinstance(result, ModelError):
                failures.extend(Failure(item, str(result)) for _, item in entries)
                continue
            for (position, item), verdict in zip(entries, result, strict=True):
                verdicts[position] = verdict
                self.cache.put(item.key, verdict.model_dump(mode="json"))
        self.stats.failed += len(failures)
        self.cache.save()
        return Outcome(
            tuple((items[position], verdicts[position]) for position in sorted(verdicts)),
            tuple(failures),
        )

    def _cached(self, item: Item) -> Verdict | None:
        stored = self.cache.get(item.key)
        if stored is None:
            return None
        try:
            return Verdict.model_validate(stored)
        except ValidationError:
            return None

    def _ask(self, inventory: ServerInventory, chunk: list[Item]) -> list[Verdict] | ModelError:
        document = build_document(inventory, chunk)
        error: ModelError = ModelError("no attempt was made")
        # A malformed answer is retried once; a transport failure is the provider's to retry.
        for _ in range(2):
            self.stats.requests += 1
            try:
                return parse_answer(
                    self.model.complete(SYSTEM_PROMPT, document, ANSWER_SCHEMA), chunk
                )
            except AnswerError as exc:
                error = exc
            except ModelError as exc:
                return exc
        return error
