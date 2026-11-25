"""Pruebas unitarias para el adaptador multi-proveedor de LLMs."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from openai import BadRequestError

from src.llm_provider import (
    LLMConfig,
    chat_completion,
    infer_provider,
    resolve_llm_config,
)


def _clear_llm_env(monkeypatch) -> None:
    keys = [
        "LLM_PROVIDER",
        "LLM_MODEL",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "OPENAI_BASE_URL",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_MODEL",
        "GOOGLE_MODEL",
        "ANTHROPIC_API_KEY",
        "CLAUDE_API_KEY",
        "ANTHROPIC_MODEL",
        "CLAUDE_MODEL",
        "OPENCODE_API_KEY",
        "OPENCODE_ZEN_API_KEY",
        "OPENCODE_MODEL",
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        "GROQ_API_KEY",
        "GROQ_MODEL",
        "OLLAMA_API_KEY",
        "OLLAMA_MODEL",
        "OLLAMA_BASE_URL",
    ]
    for k in keys:
        monkeypatch.delenv(k, raising=False)


def test_infer_provider_from_keys_and_models() -> None:
    assert infer_provider(api_key="AIzaSyDummyKey123") == "gemini"
    assert infer_provider(api_key="sk-ant-api03-dummy") == "anthropic"
    assert infer_provider(api_key="sk-or-v1-dummy") == "openrouter"
    assert infer_provider(api_key="gsk_dummy123") == "groq"
    assert infer_provider(model="gpt-4o-mini") == "openai"
    assert infer_provider(model="claude-sonnet-4-5") == "anthropic"
    assert infer_provider(model="gemini-2.5-flash") == "gemini"
    assert infer_provider(model="opencode/deepseek-v4.1-flash") == "opencode"
    assert infer_provider(base_url="https://mi-proxy.local/v1") == "custom"


def test_resolve_llm_config_aliases_and_env(monkeypatch) -> None:
    _clear_llm_env(monkeypatch)
    monkeypatch.setattr("src.llm_provider.load_dotenv", lambda *a, **kw: False)

    monkeypatch.setenv("GEMINI_API_KEY", "AIzaTestGemini")
    cfg_gem = resolve_llm_config()
    assert cfg_gem.provider == "gemini"
    assert cfg_gem.protocol == "gemini"
    assert cfg_gem.model == "gemini-2.5-flash"

    # Runtime override con alias "claude" y modelo cualquiera
    cfg_claude = resolve_llm_config(
        provider="claude",
        model="claude-3-7-sonnet-latest",
        api_key="sk-ant-test",
    )
    assert cfg_claude.provider == "anthropic"
    assert cfg_claude.protocol == "anthropic"
    assert cfg_claude.model == "claude-3-7-sonnet-latest"

    # Runtime override con alias "gpt"
    cfg_gpt = resolve_llm_config(
        provider="gpt",
        model="gpt-4.1-mini",
        api_key="sk-proj-test",
    )
    assert cfg_gpt.provider == "openai"
    assert cfg_gpt.base_url == "https://api.openai.com/v1"

    # OpenCode limpia prefijo opencode/
    cfg_oc = resolve_llm_config(
        provider="opencode",
        model="opencode/minimax-m2.7",
        api_key="oc-key-123",
    )
    assert cfg_oc.provider == "opencode"
    assert cfg_oc.model == "minimax-m2.7"
    assert cfg_oc.base_url == "https://opencode.ai/zen/v1"


def test_chat_gemini_native_payload_skips_thoughts() -> None:
    cfg = LLMConfig(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key="AIzaTest",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        protocol="gemini",
    )
    fake_resp = MagicMock()
    fake_resp.ok = True
    fake_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "Razonamiento interno", "thought": True},
                        {"text": "Respuesta final verificada."},
                    ]
                }
            }
        ]
    }
    with patch("src.llm_provider.requests.post", return_value=fake_resp) as mock_post:
        out = chat_completion(
            cfg,
            messages=[
                {"role": "system", "content": "Reglas"},
                {"role": "user", "content": "Hola"},
            ],
            temperature=0.0,
            max_tokens=150,
        )
    assert out == "Respuesta final verificada."
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["headers"]["x-goog-api-key"] == "AIzaTest"
    assert call_kwargs["json"]["systemInstruction"]["parts"][0]["text"] == "Reglas"
    assert call_kwargs["json"]["generationConfig"]["maxOutputTokens"] == 600


def test_chat_anthropic_native_payload() -> None:
    cfg = LLMConfig(
        provider="anthropic",
        model="claude-sonnet-4-5",
        api_key="sk-ant-test",
        base_url="https://api.anthropic.com/v1",
        protocol="anthropic",
    )
    fake_resp = MagicMock()
    fake_resp.ok = True
    fake_resp.json.return_value = {
        "content": [{"type": "text", "text": "Diagnóstico Claude OK."}]
    }
    with patch("src.llm_provider.requests.post", return_value=fake_resp) as mock_post:
        out = chat_completion(
            cfg,
            messages=[
                {"role": "system", "content": "Sistema"},
                {"role": "user", "content": "Diagnostica"},
            ],
            temperature=0.1,
            max_tokens=400,
        )
    assert out == "Diagnóstico Claude OK."
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["headers"]["x-api-key"] == "sk-ant-test"
    assert call_kwargs["json"]["system"] == "Sistema"
    assert call_kwargs["json"]["messages"] == [{"role": "user", "content": "Diagnostica"}]


def test_chat_openai_compatible_retries_max_completion_tokens_and_temperature() -> None:
    cfg = LLMConfig(
        provider="openai",
        model="o4-mini",
        api_key="sk-proj-test",
        base_url="https://api.openai.com/v1",
        protocol="openai_compatible",
    )
    bad_resp = MagicMock()
    bad_resp.status_code = 400
    bad_resp.headers = {}
    err = BadRequestError(
        "Unsupported parameter: 'max_tokens' and 'temperature'",
        response=bad_resp,
        body=None,
    )
    ok_resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Respuesta o4-mini OK"))]
    )
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [err, ok_resp]

    with patch("src.llm_provider.OpenAI", return_value=mock_client):
        out = chat_completion(
            cfg,
            messages=[{"role": "user", "content": "Hola"}],
            temperature=0.0,
            max_tokens=180,
        )
    assert out == "Respuesta o4-mini OK"
    assert mock_client.chat.completions.create.call_count == 2
    second_kwargs = mock_client.chat.completions.create.call_args_list[1].kwargs
    assert "max_tokens" not in second_kwargs
    assert "temperature" not in second_kwargs
    assert second_kwargs["max_completion_tokens"] == 600
