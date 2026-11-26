"""Paquete multi-proveedor de LLMs."""

from src.llm.catalog import AUTO_ENV_ORDER, PROVIDER_ALIASES, PROVIDER_CATALOG, LLMConfig
from src.llm.clients import (
    _chat_anthropic,
    _chat_gemini,
    _chat_openai_compatible,
    chat_completion,
)
from src.llm.resolver import (
    detect_configured_providers,
    infer_provider,
    normalize_provider,
    resolve_llm_config,
)

__all__ = [
    "AUTO_ENV_ORDER",
    "LLMConfig",
    "PROVIDER_ALIASES",
    "PROVIDER_CATALOG",
    "_chat_anthropic",
    "_chat_gemini",
    "_chat_openai_compatible",
    "chat_completion",
    "detect_configured_providers",
    "infer_provider",
    "normalize_provider",
    "resolve_llm_config",
]
