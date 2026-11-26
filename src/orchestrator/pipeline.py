"""Pipeline principal de orquestación multi-agente con Guardrails."""

from __future__ import annotations

from pathlib import Path
import re
import time
from typing import Any

from dotenv import load_dotenv

from src.guardrails import validar_entrada, validar_salida
from src.llm_provider import resolve_llm_config
from src.orchestrator.executor import _ejecutor_tools
from src.orchestrator.planner import _agente_planificador, cargar_perfil
from src.orchestrator.writer import _agente_redactor, _fallback_determinista
from src.tools import get_tipo_cambio_bob

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def ejecutar_diagnostico(
    query: str,
    perfil_id: str | None = None,
    features_trafico: dict[str, Any] | None = None,
    url_sospechosa: str | None = None,
    tipo_cambio_bob: float | None = None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    llm_api_key: str | None = None,
    llm_base_url: str | None = None,
) -> dict[str, Any]:
    """Orquesta: Input Guardrail -> Planificador -> Ejecutor -> Redactor -> Output Guardrail."""
    t0 = time.perf_counter()
    load_dotenv(BASE_DIR / ".env")
    perfil = cargar_perfil(perfil_id)
    tc = get_tipo_cambio_bob(tipo_cambio_bob)

    in_check = validar_entrada(query)
    if not in_check["permitido"]:
        return {
            "respuesta": in_check["motivo"],
            "bloqueado": True,
            "estado_guardrail": f"BLOQUEADO_ENTRADA ({in_check['categoria']})",
            "perfil": perfil,
            "registro_tools": {},
            "validacion_salida": {"aprobado": True, "errores": []},
            "latencia_seg": round(time.perf_counter() - t0, 3),
        }

    llm_config = resolve_llm_config(
        provider=llm_provider,
        model=llm_model,
        api_key=llm_api_key,
        base_url=llm_base_url,
    )

    if not url_sospechosa:
        url_match = re.search(r"https?://\S+", query)
        if url_match:
            url_sospechosa = url_match.group(0).rstrip(".,;)")

    plan = _agente_planificador(
        llm_config,
        query,
        perfil,
        has_traffic_features=bool(features_trafico),
        tipo_cambio_bob=tc,
    )
    registro_tools = _ejecutor_tools(
        plan, features_trafico, url_sospechosa, query=query, tipo_cambio_bob=tc
    )

    pide_stats = bool(in_check["pide_estadisticas_lapaz"])
    borrador = _agente_redactor(llm_config, query, perfil, registro_tools, pide_stats)
    out_check = validar_salida(borrador, registro_tools, pide_estadisticas_lapaz=pide_stats)
    estado = "APROBADO"

    if not out_check["aprobado"]:
        feedback = "; ".join(out_check["errores"])
        borrador = _agente_redactor(
            llm_config, query, perfil, registro_tools, pide_stats, feedback_guardrail=feedback
        )
        out_check = validar_salida(borrador, registro_tools, pide_estadisticas_lapaz=pide_stats)
        if out_check["aprobado"]:
            estado = "CORREGIDO_POR_GUARDRAIL"
        else:
            borrador = _fallback_determinista(registro_tools, pide_stats)
            out_check = validar_salida(borrador, registro_tools, pide_estadisticas_lapaz=pide_stats)
            estado = "RESPALDO_DETERMINISTA"

    return {
        "respuesta": borrador,
        "bloqueado": False,
        "estado_guardrail": estado,
        "perfil": perfil,
        "registro_tools": registro_tools,
        "validacion_salida": out_check,
        "llm_info": llm_config.public_info(),
        "latencia_seg": round(time.perf_counter() - t0, 3),
    }
