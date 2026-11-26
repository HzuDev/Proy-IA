"""Catálogo de proveedores LLM soportados y estructura de configuración."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PROVIDER_ALIASES: dict[str, str] = {
    "auto": "auto",
    "deepseek": "deepseek",
    "openai": "openai",
    "gpt": "openai",
    "chatgpt": "openai",
    "gemini": "gemini",
    "google": "gemini",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "opencode": "opencode",
    "opencode-zen": "opencode",
    "opencode_zen": "opencode",
    "zen": "opencode",
    "openrouter": "openrouter",
    "groq": "groq",
    "ollama": "ollama",
    "local": "ollama",
    "lmstudio": "ollama",
    "custom": "custom",
    "openai_compatible": "custom",
    "openai-compatible": "custom",
    "otro": "custom",
}

PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "deepseek": {
        "label": "DeepSeek",
        "protocol": "openai_compatible",
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-chat",
        "env_keys": ["DEEPSEEK_API_KEY"],
        "env_model_keys": ["DEEPSEEK_MODEL"],
        "requires_key": True,
        "suggested_models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "openai": {
        "label": "OpenAI (GPT / o-series)",
        "protocol": "openai_compatible",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "env_keys": ["OPENAI_API_KEY"],
        "env_model_keys": ["OPENAI_MODEL"],
        "requires_key": True,
        "suggested_models": ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4.1", "gpt-4o", "o4-mini"],
    },
    "gemini": {
        "label": "Google Gemini",
        "protocol": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "env_keys": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "env_model_keys": ["GEMINI_MODEL", "GOOGLE_MODEL"],
        "requires_key": True,
        "suggested_models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "protocol": "anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-sonnet-4-5",
        "env_keys": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        "env_model_keys": ["ANTHROPIC_MODEL", "CLAUDE_MODEL"],
        "requires_key": True,
        "suggested_models": [
            "claude-sonnet-4-5",
            "claude-3-7-sonnet-latest",
            "claude-3-5-haiku-latest",
        ],
    },
    "opencode": {
        "label": "OpenCode (Zen / Console)",
        "protocol": "openai_compatible",
        "base_url": "https://opencode.ai/zen/v1",
        "default_model": "deepseek-v4.1-flash",
        "env_keys": ["OPENCODE_API_KEY", "OPENCODE_ZEN_API_KEY"],
        "env_model_keys": ["OPENCODE_MODEL"],
        "requires_key": True,
        "suggested_models": ["deepseek-v4.1-flash", "minimax-m2.7", "qwen3-coder"],
    },
    "openrouter": {
        "label": "OpenRouter (multi-modelo)",
        "protocol": "openai_compatible",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o-mini",
        "env_keys": ["OPENROUTER_API_KEY"],
        "env_model_keys": ["OPENROUTER_MODEL"],
        "requires_key": True,
        "suggested_models": [
            "openai/gpt-4o-mini",
            "anthropic/claude-sonnet-4-5",
            "google/gemini-2.5-flash",
        ],
    },
    "groq": {
        "label": "Groq",
        "protocol": "openai_compatible",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "env_keys": ["GROQ_API_KEY"],
        "env_model_keys": ["GROQ_MODEL"],
        "requires_key": True,
        "suggested_models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    },
    "ollama": {
        "label": "Ollama / Local",
        "protocol": "openai_compatible",
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3.1",
        "env_keys": ["OLLAMA_API_KEY"],
        "env_model_keys": ["OLLAMA_MODEL"],
        "requires_key": False,
        "suggested_models": ["llama3.1", "qwen2.5", "mistral"],
    },
    "custom": {
        "label": "Personalizado (OpenAI-compatible)",
        "protocol": "openai_compatible",
        "base_url": "",
        "default_model": "gpt-4o-mini",
        "env_keys": ["LLM_API_KEY", "OPENAI_API_KEY"],
        "env_model_keys": ["LLM_MODEL"],
        "requires_key": False,
        "suggested_models": [],
    },
}

AUTO_ENV_ORDER = [
    "deepseek",
    "openai",
    "gemini",
    "anthropic",
    "opencode",
    "openrouter",
    "groq",
]


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: str
    base_url: str
    protocol: str
    source: str = "env"

    def public_info(self) -> dict[str, str]:
        meta = PROVIDER_CATALOG.get(self.provider, {})
        return {
            "provider": self.provider,
            "provider_label": meta.get("label", self.provider),
            "model": self.model,
            "protocol": self.protocol,
            "base_url": self.base_url,
            "source": self.source,
        }
