"""Script mínimo de verificación de conexión con DeepSeek API."""

import os
import sys
from dotenv import load_dotenv
from openai import OpenAI


def main() -> int:
    load_dotenv()
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip() or "deepseek-chat"

    if not api_key:
        print(
            "ERROR: DEEPSEEK_API_KEY no está configurada en .env.",
            file=sys.stderr,
        )
        return 1

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    response = client.chat.completions.create(
        model=model,
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
        max_tokens=50,
        temperature=0.0,
    )

    content = response.choices[0].message.content
    print(f"HTTP 200 OK | Modelo: {response.model} | Respuesta: {content}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
