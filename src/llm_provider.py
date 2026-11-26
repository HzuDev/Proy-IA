"""Fachada compatible del adaptador universal multi-proveedor de LLMs."""

from __future__ import annotations

from dotenv import load_dotenv
from openai import OpenAI
import requests

from src.llm import (
    AUTO_ENV_ORDER,
    LLMConfig,
    PROVIDER_ALIASES,
    PROVIDER_CATALOG,
    _chat_anthropic,
    _chat_gemini,
    _chat_openai_compatible,
    chat_completion,
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


def main() -> int:
    config = resolve_llm_config()
    text = chat_completion(
        config,
        messages=[
            {"role": "system", "content": "Eres un asistente de ciberseguridad defensiva. Responde en una frase corta."},
            {"role": "user", "content": "Confirma conexión operativa para diagnóstico preventivo."},
        ],
        temperature=0.0,
        max_tokens=80,
    )
    print(f"OK | Proveedor: {config.provider} | Modelo: {config.model} | Respuesta: {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
