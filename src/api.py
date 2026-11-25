"""Fase 6: API FastAPI para monitoreo y diagnóstico preventivo 24/7."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.agent import ejecutar_diagnostico
from src.llm_provider import detect_configured_providers
from src.tools import obtener_tipo_cambio_oficial_bcb

app = FastAPI(
    title="API Diagnóstico Preventivo de Ciberseguridad 24/7 - La Paz",
    version="1.3.0",
)


class DiagnosticoRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Consulta o solicitud de diagnóstico")
    perfil_id: str | None = Field(
        default=None, description="ID de perfil en data/perfiles_lapaz.json (ej. LPZ-MY-01)"
    )
    features_trafico: dict[str, Any] | None = Field(
        default=None, description="Opcional: características de flujo de red UNSW-NB15"
    )
    url_sospechosa: str | None = Field(
        default=None, description="Opcional: URL sospechosa para análisis de phishing/URLhaus"
    )
    tipo_cambio_bob: float | None = Field(
        default=None,
        gt=0,
        description="Opcional: sobrescribe el tipo de cambio oficial BCB en Bs por USD",
    )
    llm_provider: str | None = Field(
        default=None,
        description="Opcional: proveedor LLM (auto, deepseek, openai, gemini, anthropic, opencode, openrouter, groq, ollama, custom)",
    )
    llm_model: str | None = Field(
        default=None,
        description="Opcional: nombre del modelo a usar (ej. deepseek-chat, gpt-4o-mini, gemini-2.5-flash, claude-sonnet-4-5)",
    )
    llm_api_key: str | None = Field(
        default=None,
        description="Opcional: API key del proveedor elegido (si no se envía, usa .env)",
    )
    llm_base_url: str | None = Field(
        default=None,
        description="Opcional: Base URL para endpoints OpenAI-compatible personalizados",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ciberseguridad-preventiva-lapaz"}


@app.get("/tipo-cambio")
def tipo_cambio(refresh: bool = False) -> dict[str, Any]:
    """Devuelve el Tipo de Cambio Oficial (TCO) diario del BCB consultado vía API pública."""
    return obtener_tipo_cambio_oficial_bcb(force_refresh=refresh)


@app.get("/proveedores-llm")
def proveedores_llm() -> dict[str, Any]:
    """Lista los proveedores LLM soportados y cuáles tienen clave configurada en .env."""
    return {"proveedores": detect_configured_providers()}


@app.post("/diagnosticar")
def diagnosticar(req: DiagnosticoRequest) -> dict[str, Any]:
    try:
        return ejecutar_diagnostico(
            query=req.query,
            perfil_id=req.perfil_id,
            features_trafico=req.features_trafico,
            url_sospechosa=req.url_sospechosa,
            tipo_cambio_bob=req.tipo_cambio_bob,
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            llm_api_key=req.llm_api_key,
            llm_base_url=req.llm_base_url,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
