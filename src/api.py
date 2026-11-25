"""Fase 6: API FastAPI para monitoreo y diagnóstico preventivo 24/7."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.agent import ejecutar_diagnostico

app = FastAPI(
    title="API Diagnóstico Preventivo de Ciberseguridad 24/7 - La Paz",
    version="1.0.0",
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ciberseguridad-preventiva-lapaz"}


@app.post("/diagnosticar")
def diagnosticar(req: DiagnosticoRequest) -> dict[str, Any]:
    try:
        return ejecutar_diagnostico(
            query=req.query,
            perfil_id=req.perfil_id,
            features_trafico=req.features_trafico,
            url_sospechosa=req.url_sospechosa,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
