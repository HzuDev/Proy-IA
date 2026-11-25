"""Adaptador universal multi-proveedor de LLMs (DeepSeek, OpenAI/GPT, Gemini, Claude, OpenCode, OpenRouter, Groq, Ollama y endpoints OpenAI-compatible)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

BASE_DIR = Path(__file__).resolve().parent.parent

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
    """Infiere el proveedor más probable a partir de base_url, nombre del modelo o prefijo de API key."""
    url_l = (base_url or "").strip().lower()
    if url_l:
        if "api.deepseek.com" in url_l:
            return "deepseek"
        if "api.openai.com" in url_l:
            return "openai"
        if "generativelanguage.googleapis.com" in url_l:
            return "gemini"
        if "api.anthropic.com" in url_l:
            return "anthropic"
        if "opencode.ai" in url_l:
            return "opencode"
        if "openrouter.ai" in url_l:
            return "openrouter"
        if "api.groq.com" in url_l:
            return "groq"
        if "localhost:11434" in url_l or "127.0.0.1:11434" in url_l:
            return "ollama"
        return "custom"

    key = (api_key or "").strip()
    if key.startswith("AIza"):
        return "gemini"
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("sk-or-"):
        return "openrouter"
    if key.startswith("gsk_"):
        return "groq"
    if key.startswith("sk-proj-"):
        return "openai"

    m = (model or "").strip().lower()
    if m:
        if m.startswith("opencode/") or m.startswith("opencode-go/"):
            return "opencode"
        if m.startswith("gemini") or m.startswith("models/gemini"):
            return "gemini"
        if m.startswith("claude"):
            return "anthropic"
        if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt-")):
            return "openai"
        if m.startswith("deepseek"):
            return "deepseek"
        if "/" in m:
            return "openrouter"

    if key:
        # Fallback razonable si el usuario dio una clave genérica sk-... sin especificar proveedor
        return "openai"
    return "deepseek"


def detect_configured_providers() -> list[dict[str, Any]]:
    """Lista proveedores y si tienen API key o URL configurada en .env/entorno (sin exponer secretos)."""
    load_dotenv(BASE_DIR / ".env")
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
    """Resuelve proveedor, modelo, endpoint y API key desde parámetros en tiempo de ejecución o .env."""
    load_dotenv(BASE_DIR / ".env")

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
            # Si pidió un modelo específico (ej. gemini-2.5-flash o gpt-4o-mini), inferimos proveedor si tiene key
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


def _chat_gemini(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> str:
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for msg in messages:
        role = msg.get("role", "user")
        text = msg.get("content", "")
        if role == "system":
            if text:
                system_parts.append(text)
        else:
            gemini_role = "model" if role == "assistant" else "user"
            contents.append({"role": gemini_role, "parts": [{"text": text}]})

    if not contents:
        contents = [{"role": "user", "parts": [{"text": "Hola"}]}]

    # Gemini 2.5 puede usar tokens internos de razonamiento dentro de maxOutputTokens
    safe_max_tokens = max(int(max_tokens), 600) if "2.5" in config.model else int(max_tokens)

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": safe_max_tokens,
        },
    }
    if system_parts:
        payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}

    url = f"{config.base_url}/models/{config.model}:generateContent"
    resp = requests.post(
        url,
        headers={
            "x-goog-api-key": config.api_key,
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if not resp.ok:
        raise RuntimeError(
            f"Error en Gemini API ({resp.status_code}): {resp.text[:400]}"
        )
    data = resp.json()
    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"Gemini no devolvió candidatos: {data}")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    texts = [
        p.get("text", "")
        for p in parts
        if isinstance(p, dict) and p.get("text") and not p.get("thought")
    ]
    if not texts:
        texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text")]
    return "".join(texts).strip()


def _chat_anthropic(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> str:
    system_parts: list[str] = []
    conv_messages: list[dict[str, str]] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            if content:
                system_parts.append(content)
        else:
            anth_role = "assistant" if role == "assistant" else "user"
            conv_messages.append({"role": anth_role, "content": content})

    if not conv_messages:
        conv_messages = [{"role": "user", "content": "Hola"}]

    payload: dict[str, Any] = {
        "model": config.model,
        "max_tokens": int(max_tokens),
        "temperature": temperature,
        "messages": conv_messages,
    }
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)

    url = f"{config.base_url}/messages"
    resp = requests.post(
        url,
        headers={
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if not resp.ok:
        raise RuntimeError(
            f"Error en Anthropic Claude API ({resp.status_code}): {resp.text[:400]}"
        )
    data = resp.json()
    blocks = data.get("content") or []
    texts = [
        b.get("text", "")
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text"
    ]
    return "".join(texts).strip()


def _chat_openai_compatible(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> str:
    extra_headers: dict[str, str] = {}
    if config.provider == "openrouter":
        extra_headers["X-Title"] = "Diagnostico-Ciberseguridad-LaPaz"

    client = OpenAI(
        api_key=config.api_key,
        base_url=config.base_url,
        timeout=timeout,
        default_headers=extra_headers or None,
    )

    kwargs: dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": int(max_tokens),
    }

    try:
        resp = client.chat.completions.create(**kwargs)
    except BadRequestError as exc:
        err_msg = str(exc).lower()
        retried_kwargs = dict(kwargs)
        changed = False
        if "max_completion_tokens" in err_msg or "max_tokens" in err_msg:
            val = retried_kwargs.pop("max_tokens", None)
            if val is not None:
                retried_kwargs["max_completion_tokens"] = max(int(val), 600)
                changed = True
        if "temperature" in err_msg:
            retried_kwargs.pop("temperature", None)
            changed = True
        if not changed:
            raise
        resp = client.chat.completions.create(**retried_kwargs)

    choice = resp.choices[0].message
    content = (choice.content or "").strip()
    if not content:
        # Algunos modelos de razonamiento devuelven texto en reasoning_content si alcanzaron el límite
        reasoning = getattr(choice, "reasoning_content", None)
        if isinstance(reasoning, str):
            content = reasoning.strip()
    return content


def chat_completion(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    max_tokens: int = 480,
    timeout: float = 45.0,
) -> str:
    """Ejecuta una llamada de chat unificada sobre cualquier proveedor configurado."""
    if config.protocol == "gemini":
        return _chat_gemini(config, messages, temperature, max_tokens, timeout)
    if config.protocol == "anthropic":
        return _chat_anthropic(config, messages, temperature, max_tokens, timeout)
    return _chat_openai_compatible(config, messages, temperature, max_tokens, timeout)


def main() -> int:
    config = resolve_llm_config()
    text = chat_completion(
        config,
        messages=[
            {
                "role": "system",
                "content": "Eres un asistente de ciberseguridad defensiva. Responde en una frase corta.",
            },
            {
                "role": "user",
                "content": "Confirma conexión operativa para diagnóstico preventivo.",
            },
        ],
        temperature=0.0,
        max_tokens=80,
    )
    print(
        f"OK | Proveedor: {config.provider} | Modelo: {config.model} | Respuesta: {text}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
