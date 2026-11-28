"""Reviewer models for the benchmark, and a way to price a run before paying for it."""

import json
from pathlib import Path
from typing import Any

from foretaster.llm import Reviewer, VerdictCache
from foretaster.llm.anthropic_model import AnthropicModel, Effort
from foretaster.llm.prompt import SYSTEM_PROMPT

# US dollars per million tokens (input, output), from the provider's price list as read on
# 2026-11-03. Prices change; the figures only turn token counts into an order of magnitude.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}
# Rough allowances for an estimate made without calling the API.
CHARACTERS_PER_TOKEN = 3.0
OUTPUT_TOKENS_PER_ITEM = 90
THINKING_TOKENS_PER_REQUEST = 500


class CountingModel:
    """Stands in for a model: answers "benign" to everything and counts what was sent."""

    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.requests = 0
        self.items = 0
        self.characters = 0

    def complete(self, system: str, document: str, schema: dict[str, Any]) -> str:
        items = json.loads(document)["items"]
        self.requests += 1
        self.items += len(items)
        self.characters += len(system) + len(document)
        return json.dumps(
            {
                "verdicts": [
                    {
                        "id": item["id"],
                        "reason": "",
                        "quote": "",
                        "category": "none",
                        "verdict": "benign",
                    }
                    for item in items
                ]
            }
        )

    def estimate(self, model: str) -> dict[str, Any]:
        input_tokens = round(self.characters / CHARACTERS_PER_TOKEN)
        output_tokens = (
            self.items * OUTPUT_TOKENS_PER_ITEM + self.requests * THINKING_TOKENS_PER_REQUEST
        )
        return {
            "requests": self.requests,
            "items": self.items,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "usd": _cost(model, input_tokens, output_tokens),
        }


def _cost(model: str, input_tokens: int, output_tokens: int) -> float | None:
    if model not in PRICES:
        return None
    per_input, per_output = PRICES[model]
    return round((input_tokens * per_input + output_tokens * per_output) / 1_000_000, 2)


def counting_reviewer(model: str, effort: str) -> tuple[Reviewer, CountingModel]:
    counter = CountingModel(f"anthropic/{model}/{effort}")
    return Reviewer(counter, VerdictCache(), workers=1), counter


def live_reviewer(model: str, effort: Effort, cache_dir: Path, workers: int) -> Reviewer:
    """A reviewer that calls the API and keeps its verdicts, so a run can be resumed."""
    cache = VerdictCache(cache_dir / f"llm-verdicts-{model}-{effort}.json")
    return Reviewer(AnthropicModel(model, effort=effort), cache, workers=workers)


def usage_report(reviewer: Reviewer) -> dict[str, Any]:
    """What a finished run consumed, for the result file."""
    report: dict[str, Any] = {
        "reviewer": reviewer.model.identity,
        "prompt_characters": len(SYSTEM_PROMPT),
        "items": reviewer.stats.items,
        "answered_from_cache": reviewer.stats.cached,
        "requests": reviewer.stats.requests,
    }
    model = reviewer.model
    if isinstance(model, AnthropicModel):
        usage = model.usage
        billed_input = (
            usage.input_tokens + usage.cache_read_input_tokens + usage.cache_creation_input_tokens
        )
        report.update(
            input_tokens=billed_input,
            output_tokens=usage.output_tokens,
            usd_at_list_price=_cost(model.model, billed_input, usage.output_tokens),
        )
    return report
