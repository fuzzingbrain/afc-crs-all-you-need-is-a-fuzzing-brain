# SPDX-License-Identifier: Apache-2.0
"""
Models and their prices, from litellm's price table.

A model id is passed to its provider as given; nothing here keeps a list of
models. What a model costs, and which provider serves it, come from
``litellm.model_cost`` -- by default the table litellm fetches when it is
imported, so a model released after this code still prices correctly. A
model the table does not price is an error (UnknownModelError): estimating it
would put a made-up number in the paper's cost data.

    get_model_info(id)   ModelInfo, or UnknownModelError
    get_model_by_id(id)  ModelInfo, or None
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class Provider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    XAI = "xai"
    DEEPSEEK = "deepseek"


class UnknownModelError(ValueError):
    """The price table has no price for this model."""


# litellm_provider -> ours. Gemini's API models are listed as "gemini/<id>";
# the bare ids belong to Vertex AI, which this code does not call.
_PROVIDERS = {
    "anthropic": Provider.ANTHROPIC,
    "openai": Provider.OPENAI,
    "gemini": Provider.GOOGLE,
    "xai": Provider.XAI,
    "deepseek": Provider.DEEPSEEK,
}
_PREFIXED = ("gemini/", "xai/", "deepseek/")


@dataclass(frozen=True)
class ModelInfo:
    """A model as the price table describes it. Prices are $ per 1M tokens."""

    id: str  # what the task named, and what is sent
    provider: Provider
    price_input: float
    price_output: float
    price_cache_read: Optional[float] = None
    price_cache_write: Optional[float] = None
    context_window: int = 0
    max_output: int = 0
    supports_reasoning: bool = False
    table_key: str = ""  # the price table's key for it

    @property
    def name(self) -> str:
        return self.id

    def __str__(self) -> str:
        return self.id


def _table():
    import litellm

    return litellm.model_cost


def _lookup(model_id: str) -> Tuple[Optional[str], Optional[dict]]:
    table = _table()
    bare = model_id
    for p in _PREFIXED:
        if model_id.startswith(p):
            bare = model_id[len(p):]
    candidates = [model_id] + [p + bare for p in _PREFIXED]
    for key in candidates:
        entry = table.get(key)
        if entry and entry.get("litellm_provider") in _PROVIDERS:
            return key, entry
    return None, None


def _per_m(v) -> Optional[float]:
    return None if v is None else float(v) * 1_000_000


def get_model_info(model_id: str) -> ModelInfo:
    """The model's provider and prices; UnknownModelError when it has none."""
    if isinstance(model_id, ModelInfo):
        return model_id
    key, e = _lookup(str(model_id or ""))
    if e is None:
        raise UnknownModelError(
            f"model {model_id!r} is not in litellm's price table "
            f"(openai, anthropic, gemini/, xai/, deepseek/ models)"
        )
    if e.get("input_cost_per_token") is None or e.get("output_cost_per_token") is None:
        raise UnknownModelError(f"model {model_id!r} has no price in litellm's table")
    bare = model_id
    for p in _PREFIXED:
        if bare.startswith(p):
            bare = bare[len(p):]
    return ModelInfo(
        id=bare,
        provider=_PROVIDERS[e["litellm_provider"]],
        price_input=_per_m(e["input_cost_per_token"]),
        price_output=_per_m(e["output_cost_per_token"]),
        price_cache_read=_per_m(e.get("cache_read_input_token_cost")),
        price_cache_write=_per_m(e.get("cache_creation_input_token_cost")),
        context_window=int(e.get("max_input_tokens") or 0),
        max_output=int(e.get("max_output_tokens") or e.get("max_tokens") or 0),
        supports_reasoning=bool(e.get("supports_reasoning")),
        table_key=key,
    )


def get_model_by_id(model_id: str) -> Optional[ModelInfo]:
    try:
        return get_model_info(model_id)
    except UnknownModelError:
        return None


def litellm_model_name(info: ModelInfo) -> str:
    """The name litellm routes on: Gemini and DeepSeek ids carry their prefix."""
    if info.provider == Provider.GOOGLE:
        return f"gemini/{info.id}"
    if info.provider == Provider.DEEPSEEK:
        return f"deepseek/{info.id}"
    return info.id


def call_cost(
    info: ModelInfo,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_creation_tokens: int = 0,
) -> Tuple[float, float, float, dict]:
    """(input $, output $, total $, the unit prices used).

    input_tokens includes the cached parts (litellm folds cache reads and
    writes into prompt_tokens); they are billed at the table's cache prices,
    or the input price where the table has none.
    """
    cache_read = max(0, min(cache_read_tokens or 0, input_tokens))
    cache_write = max(0, min(cache_creation_tokens or 0, input_tokens - cache_read))
    regular = max(0, input_tokens - cache_read - cache_write)
    p_read = info.price_cache_read if info.price_cache_read is not None else info.price_input
    p_write = info.price_cache_write if info.price_cache_write is not None else info.price_input
    cost_in = (regular * info.price_input + cache_read * p_read + cache_write * p_write) / 1e6
    cost_out = output_tokens * info.price_output / 1e6
    prices = {
        "input": info.price_input,
        "output": info.price_output,
        "cache_read": p_read,
        "cache_write": p_write,
        "per": "1M tokens",
        "table_key": info.table_key,
    }
    return cost_in, cost_out, cost_in + cost_out, prices
