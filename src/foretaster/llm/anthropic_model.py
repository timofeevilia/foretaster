"""The Claude API as a reviewer model."""

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from foretaster.llm.review import ModelError

if TYPE_CHECKING:
    import anthropic
    from anthropic.types import Message, TextBlockParam
    from anthropic.types.beta import BetaMessage

DEFAULT_MODEL = "claude-opus-5-5"
Effort = Literal["low", "medium", "high", "xhigh", "max"]
DEFAULT_EFFORT: Effort = "medium"
MAX_OUTPUT_TOKENS = 16_000
TIMEOUT_SECONDS = 180.0
MAX_RETRIES = 4
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models on which a request declined by a safety classifier can be re-run by the
# API on another model. Tool poisoning is attack text, so declines are plausible.
SUPPORTS_FALLBACK = frozenset(
    {
        "claude-fable-5-2",
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
    }
)


class LlmUnavailableError(Exception):
    """The optional Anthropic client library is not installed."""


@dataclass
class Usage:
    requests: int = 0
    input_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    output_tokens: int = 0


class AnthropicModel:
    """Completions from the Claude API with a JSON schema enforced on the answer.

    Credentials are resolved by the client library, normally from the
    ``ANTHROPIC_API_KEY`` environment variable.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        effort: Effort = DEFAULT_EFFORT,
        client: "anthropic.Anthropic | None" = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise LlmUnavailableError(
                "the LLM review needs the Anthropic client library: "
                "install it with `pip install 'foretaster[llm]'`"
            ) from exc
        self._anthropic = anthropic
        self._client: anthropic.Anthropic = client or anthropic.Anthropic(
            timeout=TIMEOUT_SECONDS, max_retries=MAX_RETRIES
        )
        self.model = model
        self.effort: Effort = effort
        self.identity = f"anthropic/{model}/{effort}"
        self.usage = Usage()
        self._lock = threading.Lock()

    def complete(self, system: str, document: str, schema: dict[str, Any]) -> str:
        anthropic = self._anthropic
        # The instructions are identical in every request, so they are cached.
        instructions: list[TextBlockParam] = [
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
        ]
        response: Message | BetaMessage
        try:
            if self.model in SUPPORTS_FALLBACK:
                response = self._client.beta.messages.create(
                    model=self.model,
                    max_tokens=MAX_OUTPUT_TOKENS,
                    system=instructions,
                    messages=[{"role": "user", "content": document}],
                    output_config={
                        "effort": self.effort,
                        "format": {"type": "json_schema", "schema": schema},
                    },
                    betas=[FALLBACK_BETA],
                    fallbacks="default",
                )
            else:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=MAX_OUTPUT_TOKENS,
                    system=instructions,
                    messages=[{"role": "user", "content": document}],
                    output_config={
                        "effort": self.effort,
                        "format": {"type": "json_schema", "schema": schema},
                    },
                )
        except anthropic.AuthenticationError as exc:
            raise ModelError("the API key was rejected") from exc
        except anthropic.PermissionDeniedError as exc:
            raise ModelError(f"the API key may not use this model: {exc.message}") from exc
        except anthropic.NotFoundError as exc:
            raise ModelError(f"the model {self.model!r} was not found") from exc
        except anthropic.RateLimitError as exc:
            raise ModelError("the API rate limit was reached") from exc
        except anthropic.APIStatusError as exc:
            raise ModelError(f"the API returned status {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise ModelError("the API could not be reached") from exc
        except Exception as exc:
            # Without credentials the client fails here, with an error of no specific type.
            if "authentication method" in str(exc):
                raise ModelError(
                    "no API credentials were found: set ANTHROPIC_API_KEY to a Claude API key"
                ) from exc
            raise ModelError(f"the request could not be made: {type(exc).__name__}: {exc}") from exc

        self._count(response.usage)
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            raise ModelError(f"the model declined to review the text (category: {category})")
        if response.stop_reason == "max_tokens":
            raise ModelError("the answer was cut off at the output limit")
        for block in response.content:
            if block.type == "text":
                return str(block.text)
        raise ModelError("the answer holds no text")

    def _count(self, usage: Any) -> None:
        with self._lock:
            self.usage.requests += 1
            self.usage.input_tokens += usage.input_tokens or 0
            self.usage.output_tokens += usage.output_tokens or 0
            self.usage.cache_read_input_tokens += usage.cache_read_input_tokens or 0
            self.usage.cache_creation_input_tokens += usage.cache_creation_input_tokens or 0
