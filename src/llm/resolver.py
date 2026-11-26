"""Resolución dinámica de proveedor, modelo y credenciales LLM."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any

from dotenv import load_dotenv as _default_load_dotenv

from src.llm.catalog import (
    AUTO_ENV_ORDER,
    PROVIDER_ALIASES,
    PROVIDER_CATALOG,
    LLMConfig,
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def normalize_provider(provider: str | None) -> str:
    if not provider:
        return "auto"
    key = provider.strip().lower()
    return PROVIDER_ALIASES.get(key, key)


def _first_env(keys: list[str]) -> str:
    for k in keys:
        val = os.getenv(k, "").strip()
        if val:
            return val
    return ""


def infer_provider(
    *,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> str:
    """Infiere el proveedor a partir de base_url, prefijo de API key o nombre del modelo."""
    url_l = (base_url or "").strip().lower()
    if url_l:
        url_rules = [
            ("api.deepseek.com", "deepseek"),
            ("api.openai.com", "openai"),
            ("generativelanguage.googleapis.com", "gemini"),
            ("api.anthropic.com", "anthropic"),
            ("opencode.ai", "opencode"),
            ("openrouter.ai", "openrouter"),
            ("api.groq.com", "groq"),
            ("localhost:11434", "ollama"),
            ("127.0.0.1:11434", "ollama"),
        ]
        for needle, pid in url_rules:
            if needle in url_l:
                return pid
        return "custom"

    key = (api_key or "").strip()
    key_prefixes = [
        ("AIza", "gemini"),
        ("sk-ant-", "anthropic"),
        ("sk-or-", "openrouter"),
        ("gsk_", "groq"),
        ("sk-proj-", "openai"),
    ]
    for prefix, pid in key_prefixes:
        if key.startswith(prefix):
            return pid

    m = (model or "").strip().lower()
    if m:
        if m.startswith(("opencode/", "opencode-go/")):
            return "opencode"
        if m.startswith(("gemini", "models/gemini")):
            return "gemini"
        if m.startswith("claude"):
            return "anthropic"
        if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt-")):
            return "openai"
        if m.startswith("deepseek"):
            return "deepseek"
        if "/" in m:
            return "openrouter"

    return "openai" if key else "deepseek"


def _load_dotenv_fn():
    facade = sys.modules.get("src.llm_provider")
    return getattr(facade, "load_dotenv", _default_load_dotenv)


def detect_configured_providers() -> list[dict[str, Any]]:
    _load_dotenv_fn()(BASE_DIR / ".env")
    items: list[dict[str, Any]] = []
    for pid, meta in PROVIDER_CATALOG.items():
        if pid == "custom":
            configured = bool(os.getenv("LLM_BASE_URL", "").strip())
        elif pid == "ollama":
            configured = bool(
                os.getenv("OLLAMA_MODEL", "").strip()
                or os.getenv("OLLAMA_BASE_URL", "").strip()
            )
        else:
            configured = bool(_first_env(meta["env_keys"]))
        items.append(
            {
                "id": pid,
                "label": meta["label"],
                "default_model": meta["default_model"],
                "suggested_models": meta["suggested_models"],
                "configured": configured,
            }
        )
    return items


def resolve_llm_config(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLMConfig:
    """Resuelve proveedor, modelo, endpoint y API key desde runtime o .env."""
    _load_dotenv_fn()(BASE_DIR / ".env")

    req_provider = normalize_provider(provider)
    req_model = (model or "").strip()
    req_key = (api_key or "").strip()
    req_url = (base_url or "").strip()

    env_provider = normalize_provider(os.getenv("LLM_PROVIDER", "auto"))
    env_generic_key = os.getenv("LLM_API_KEY", "").strip()
    env_generic_model = os.getenv("LLM_MODEL", "").strip()
    env_generic_url = os.getenv("LLM_BASE_URL", "").strip()

    source = "runtime" if any([req_provider != "auto", req_model, req_key, req_url]) else "env"
    chosen_provider = req_provider

    if chosen_provider == "auto":
        if req_key or req_url:
            chosen_provider = infer_provider(
                api_key=req_key,
                model=req_model or env_generic_model,
                base_url=req_url or env_generic_url,
            )
        elif req_model:
            inferred = infer_provider(model=req_model)
            meta_inf = PROVIDER_CATALOG.get(inferred, {})
            if inferred in PROVIDER_CATALOG and (
                _first_env(meta_inf.get("env_keys", [])) or env_generic_key
            ):
                chosen_provider = inferred

        if chosen_provider == "auto":
            if env_provider != "auto":
                chosen_provider = env_provider
            elif env_generic_key or env_generic_url:
                chosen_provider = infer_provider(
                    api_key=env_generic_key,
                    model=req_model or env_generic_model,
                    base_url=req_url or env_generic_url,
                )
            else:
                for pid in AUTO_ENV_ORDER:
                    if _first_env(PROVIDER_CATALOG[pid]["env_keys"]):
                        chosen_provider = pid
                        break
                if chosen_provider == "auto" and (
                    os.getenv("OLLAMA_MODEL", "").strip()
                    or os.getenv("OLLAMA_BASE_URL", "").strip()
                ):
                    chosen_provider = "ollama"
                if chosen_provider == "auto":
                    chosen_provider = "deepseek"

    if chosen_provider not in PROVIDER_CATALOG:
        raise RuntimeError(
            f"Proveedor LLM no soportado: '{chosen_provider}'. "
            f"Opciones válidas: {', '.join(PROVIDER_CATALOG.keys())}."
        )

    meta = PROVIDER_CATALOG[chosen_provider]
    resolved_key = req_key or _first_env(meta["env_keys"]) or env_generic_key

    if chosen_provider == "ollama":
        resolved_key = resolved_key or "ollama"
        resolved_url = (
            req_url
            or os.getenv("OLLAMA_BASE_URL", "").strip()
            or env_generic_url
            or meta["base_url"]
        )
    elif chosen_provider == "custom":
        resolved_url = req_url or env_generic_url or os.getenv("OPENAI_BASE_URL", "").strip()
        if not resolved_url:
            raise RuntimeError(
                "Para el proveedor personalizado ('custom') debes indicar una Base URL "
                "(parámetro llm_base_url o variable LLM_BASE_URL en .env)."
            )
        resolved_key = resolved_key or "local-key"
    else:
        resolved_url = req_url or env_generic_url or meta["base_url"]

    resolved_model = (
        req_model
        or _first_env(meta["env_model_keys"])
        or env_generic_model
        or meta["default_model"]
    )

    if chosen_provider == "opencode":
        for prefix in ("opencode-go/", "opencode/"):
            if resolved_model.startswith(prefix):
                resolved_model = resolved_model[len(prefix) :]
    elif chosen_provider == "gemini" and resolved_model.startswith("models/"):
        resolved_model = resolved_model[len("models/") :]

    if meta["requires_key"] and not resolved_key:
        expected = " / ".join(meta["env_keys"] + ["LLM_API_KEY"])
        raise RuntimeError(
            f"Falta la API key para {meta['label']}. Configura {expected} en .env "
            f"o ingrésala en la interfaz/petición."
        )

    return LLMConfig(
        provider=chosen_provider,
        model=resolved_model,
        api_key=resolved_key,
        base_url=resolved_url.rstrip("/"),
        protocol=meta["protocol"],
        source=source,
    )
