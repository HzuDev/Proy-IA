"""Agente Redactor Técnico y respaldo determinista anti-alucinación."""

from __future__ import annotations

import json
import re
from typing import Any

from src.llm_provider import LLMConfig, chat_completion
from src.orchestrator.executor import _compactar_registro_para_llm


def _agente_redactor(
    llm_config: LLMConfig,
    query: str,
    perfil: dict[str, Any] | None,
    registro_tools: dict[str, Any],
    pide_estadisticas_lapaz: bool,
    feedback_guardrail: str | None = None,
) -> str:
    """Redacta diagnóstico trazable estrictamente a la evidencia de registro_tools."""
    cves_en_consulta = re.findall(r"CVE-\d{4}-\d+", query, flags=re.IGNORECASE)
    reglas_extra = []
    if pide_estadisticas_lapaz:
        reglas_extra.append(
            "OBLIGATORIO: El usuario pidió estadísticas de incidentes por zona/barrio de La Paz. "
            "Declara explícitamente que 'no existen estadísticas reales de incidentes por zona o barrio en data/' "
            "y NO inventes ningún número ni porcentaje por barrio."
        )
    if cves_en_consulta:
        reglas_extra.append(
            f"El usuario mencionó {', '.join(cves_en_consulta)}. Si alguno NO aparece en el JSON de herramientas, "
            "indica explícitamente que no existe en la caché real verificada (y NO repitas el ID inventado)."
        )
    if feedback_guardrail:
        reglas_extra.append(f"CORRECCIÓN OBLIGATORIA DEL VERIFICADOR: {feedback_guardrail}")

    system_msg = (
        "Eres el Redactor Técnico de ciberseguridad preventiva para entidades de la ciudad y departamento de La Paz, Bolivia.\n"
        "REGLAS ESTRICTAS:\n"
        "1. Usa ÚNICAMENTE los CVE-IDs, puntajes CVSS/EPSS, costos (USD y Bs), horas y porcentajes que aparecen literalmente en el JSON de herramientas.\n"
        "2. Nunca inventes CVEs, métricas ni estadísticas.\n"
        "3. Presenta el plan priorizado generado por el Algoritmo Genético de forma clara y accionable, indicando costo en USD y su equivalente en Bs al tipo de cambio oficial BCB indicado en el JSON.\n"
        "4. Si existe una alerta en phishing_url (especialmente suplantacion_bolivia) o en_agetic_csirt, destácala e incluye los canales oficiales verificados de reporte en Bolivia (CGII/AGETIC, ATT, ASFI) que aparecen en canales_oficiales_bolivia.\n"
        + ("\n".join(reglas_extra) if reglas_extra else "")
    )

    compact_tools = _compactar_registro_para_llm(registro_tools)
    perfil_desc = (
        f"{perfil.get('nombre', 'N/A')} ({perfil.get('municipio', 'La Paz')} - {perfil.get('macrodistrito', 'N/A')})"
        if perfil
        else "N/A"
    )
    user_msg = (
        f"Consulta: {query}\n"
        f"Perfil: {perfil_desc}\n"
        f"Datos verificados:\n{json.dumps(compact_tools, ensure_ascii=False)}"
    )

    return chat_completion(
        llm_config,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.1,
        max_tokens=650,
    )


def _fallback_determinista(
    registro_tools: dict[str, Any], pide_estadisticas_lapaz: bool
) -> str:
    """Respuesta determinista segura cuando el Redactor no supera el Output Guardrail."""
    ag = registro_tools.get("algoritmo_genetico", {})
    controles = ag.get("controles_seleccionados", [])
    lines = []
    if pide_estadisticas_lapaz:
        lines.append(
            "Transparencia de datos: no existen estadísticas reales de incidentes por zona o barrio de La Paz en data/."
        )
    phish = registro_tools.get("phishing_url")
    if phish and not phish.get("error"):
        lines.append(
            f"Análisis de URL ({phish['url']}): veredicto {phish['veredicto']}, "
            f"probabilidad phishing {phish['probabilidad_phishing']}."
        )
        if phish.get("alerta_bolivia"):
            lines.append(f"Alerta local Bolivia: {phish['alerta_bolivia']}")

    lines.append(
        f"Plan de mitigación optimizado por Algoritmo Genético: "
        f"riesgo reducido {ag.get('riesgo_reducido_pct', 0.0)}%, "
        f"costo total ${ag.get('costo_total_usd', 0.0)} USD (Bs {ag.get('costo_total_bob', 0.0)} a TC {ag.get('tipo_cambio_bob')}), "
        f"horas totales {ag.get('horas_totales', 0.0)} h."
    )
    for c in controles:
        lines.append(
            f"- {c['cve_id']} ({c['tecnologia']}): CVSS {c['cvss']}, EPSS {c['epss']}, "
            f"costo ${c['costo_remediacion_usd']} USD (Bs {c.get('costo_remediacion_bob', 0.0)}), "
            f"{c['horas_remediacion']} h."
        )
    canales = registro_tools.get("canales_oficiales_bolivia", {}).get("canales_reporte", [])
    if canales:
        lines.append("Canales oficiales de reporte en Bolivia:")
        for ch in canales:
            lines.append(f"- {ch['entidad']}: {ch['url_portal']} ({ch['contacto']})")
    return "\n".join(lines)
