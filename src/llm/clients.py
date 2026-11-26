"""Clientes HTTP/SDK para Gemini, Anthropic Claude y endpoints OpenAI-compatible."""

from __future__ import annotations

import sys
from typing import Any

from openai import BadRequestError, OpenAI as _DefaultOpenAI
import requests as _default_requests

from src.llm.catalog import LLMConfig


def _requests_mod():
    facade = sys.modules.get("src.llm_provider")
    return getattr(facade, "requests", _default_requests)


def _openai_cls():
    facade = sys.modules.get("src.llm_provider")
    return getattr(facade, "OpenAI", _DefaultOpenAI)


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
            contents.append({"role": "model" if role == "assistant" else "user", "parts": [{"text": text}]})

    if not contents:
        contents = [{"role": "user", "parts": [{"text": "Hola"}]}]

    # Gemini 2.5 consume tokens de razonamiento dentro de maxOutputTokens
    safe_max_tokens = max(int(max_tokens), 600) if "2.5" in config.model else int(max_tokens)

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {"temperature": temperature, "maxOutputTokens": safe_max_tokens},
    }
    if system_parts:
        payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}

    resp = _requests_mod().post(
        f"{config.base_url}/models/{config.model}:generateContent",
        headers={"x-goog-api-key": config.api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    if not resp.ok:
        raise RuntimeError(f"Error en Gemini API ({resp.status_code}): {resp.text[:400]}")

    data = resp.json()
    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"Gemini no devolvió candidatos: {data}")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text") and not p.get("thought")]
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
            conv_messages.append({"role": "assistant" if role == "assistant" else "user", "content": content})

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

    resp = _requests_mod().post(
        f"{config.base_url}/messages",
        headers={
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if not resp.ok:
        raise RuntimeError(f"Error en Anthropic Claude API ({resp.status_code}): {resp.text[:400]}")

    blocks = resp.json().get("content") or []
    return "".join(
        b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
    ).strip()


def _chat_openai_compatible(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> str:
    extra_headers = {"X-Title": "Diagnostico-Ciberseguridad-LaPaz"} if config.provider == "openrouter" else None
    client = _openai_cls()(
        api_key=config.api_key,
        base_url=config.base_url,
        timeout=timeout,
        default_headers=extra_headers,
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
        retried = dict(kwargs)
        changed = False
        if "max_completion_tokens" in err_msg or "max_tokens" in err_msg:
            val = retried.pop("max_tokens", None)
            if val is not None:
                retried["max_completion_tokens"] = max(int(val), 600)
                changed = True
        if "temperature" in err_msg:
            retried.pop("temperature", None)
            changed = True
        if not changed:
            raise
        resp = client.chat.completions.create(**retried)

    choice = resp.choices[0].message
    content = (choice.content or "").strip()
    if not content:
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
    """Interfaz unificada de chat para cualquier proveedor configurado."""
    if config.protocol == "gemini":
        return _chat_gemini(config, messages, temperature, max_tokens, timeout)
    if config.protocol == "anthropic":
        return _chat_anthropic(config, messages, temperature, max_tokens, timeout)
    return _chat_openai_compatible(config, messages, temperature, max_tokens, timeout)
