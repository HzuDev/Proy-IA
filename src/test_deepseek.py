"""Script mínimo de verificación de conexión con cualquier proveedor LLM configurado."""

import argparse
import sys

from src.llm_provider import chat_completion, resolve_llm_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Verifica conexión con el proveedor LLM.")
    parser.add_argument("--provider", default=None, help="deepseek, openai, gemini, anthropic, opencode, etc.")
    parser.add_argument("--model", default=None, help="ID del modelo")
    parser.add_argument("--api-key", default=None, help="API key opcional")
    parser.add_argument("--base-url", default=None, help="Base URL opcional")
    args = parser.parse_args()

    try:
        config = resolve_llm_config(
            provider=args.provider,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url,
        )
        content = chat_completion(
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
            max_tokens=80,
            temperature=0.0,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"HTTP 200 OK | Proveedor: {config.provider} | Modelo: {config.model} | Respuesta: {content}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
