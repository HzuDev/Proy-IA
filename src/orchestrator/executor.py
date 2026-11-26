"""Agente Ejecutor de Tools deterministas y compactador de evidencia."""

from __future__ import annotations

import re
from typing import Any

from src.tools import (
    get_tipo_cambio_bob,
    tool_analizar_url_phishing,
    tool_clasificar_trafico_ml,
    tool_consultar_vulnerabilidades,
    tool_contexto_oficial_bolivia,
    tool_optimizar_mitigacion_ag,
)


def _ejecutor_tools(
    plan: dict[str, Any],
    features_trafico: dict[str, Any] | None,
    url_sospechosa: str | None = None,
    query: str = "",
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Ejecuta herramientas de ML, inteligencia de CVEs, Algoritmo Genético y contexto Bolivia."""
    tc = get_tipo_cambio_bob(tipo_cambio_bob or plan.get("tipo_cambio_bob"))
    registro: dict[str, Any] = {"plan": plan, "tools_ejecutadas": []}
    tipos_alerta: list[str] = ["vulnerabilidades"]

    if features_trafico:
        try:
            registro["ml_trafico"] = tool_clasificar_trafico_ml(features_trafico)
            registro["tools_ejecutadas"].append("tool_clasificar_trafico_ml")
            tipos_alerta.append("trafico_red")
        except FileNotFoundError as exc:
            registro["ml_trafico"] = {"error": str(exc)}

    if url_sospechosa:
        try:
            registro["phishing_url"] = tool_analizar_url_phishing(url_sospechosa)
            registro["tools_ejecutadas"].append("tool_analizar_url_phishing")
            tipos_alerta.append("phishing_qr")
        except FileNotFoundError as exc:
            registro["phishing_url"] = {"error": str(exc)}
    elif re.search(r"\b(phishing|quishing|qr|estafa|suplantaci[oó]n|asfi|att)\b", query, re.I):
        tipos_alerta.append("phishing_qr")

    vuln_res = tool_consultar_vulnerabilidades(plan["tecnologias"], tipo_cambio_bob=tc)
    registro["vulnerabilidades"] = vuln_res
    registro["tools_ejecutadas"].append("tool_consultar_vulnerabilidades")

    registro["algoritmo_genetico"] = tool_optimizar_mitigacion_ag(
        vuln_res["vulnerabilidades"],
        plan["presupuesto_max_usd"],
        plan["horas_max"],
        tipo_cambio_bob=tc,
    )
    registro["tools_ejecutadas"].append("tool_optimizar_mitigacion_ag")

    registro["canales_oficiales_bolivia"] = tool_contexto_oficial_bolivia(
        tipos_alerta, tipo_cambio_bob=tc
    )
    registro["tools_ejecutadas"].append("tool_contexto_oficial_bolivia")

    return registro


def _compactar_registro_para_llm(registro_tools: dict[str, Any]) -> dict[str, Any]:
    """Resume registro_tools para minimizar tokens preservando trazabilidad de CVEs y cifras."""
    ag = registro_tools.get("algoritmo_genetico", {})
    controles_compactos = [
        {
            "cve_id": c["cve_id"],
            "tecnologia": c["tecnologia"],
            "cvss": c["cvss"],
            "epss": c["epss"],
            "en_cisa_kev": c.get("en_cisa_kev", False),
            "en_agetic_csirt": c.get("en_agetic_csirt", False),
            "riesgo_ponderado": c["riesgo_ponderado"],
            "costo_remediacion_usd": c["costo_remediacion_usd"],
            "costo_remediacion_bob": c.get("costo_remediacion_bob"),
            "horas_remediacion": c["horas_remediacion"],
        }
        for c in ag.get("controles_seleccionados", [])
    ]
    compacto: dict[str, Any] = {
        "plan": registro_tools.get("plan", {}),
        "total_vulnerabilidades": registro_tools.get("vulnerabilidades", {}).get(
            "total_vulnerabilidades", 0
        ),
        "algoritmo_genetico": {
            "riesgo_inicial": ag.get("riesgo_inicial", 0.0),
            "riesgo_mitigado": ag.get("riesgo_mitigado", 0.0),
            "riesgo_residual": ag.get("riesgo_residual", 0.0),
            "riesgo_reducido_pct": ag.get("riesgo_reducido_pct", 0.0),
            "costo_total_usd": ag.get("costo_total_usd", 0.0),
            "costo_total_bob": ag.get("costo_total_bob", 0.0),
            "tipo_cambio_bob": ag.get("tipo_cambio_bob"),
            "horas_totales": ag.get("horas_totales", 0.0),
            "controles_seleccionados": controles_compactos,
        },
    }
    for key in ("ml_trafico", "phishing_url", "canales_oficiales_bolivia"):
        if key in registro_tools:
            compacto[key] = registro_tools[key]
    return compacto
