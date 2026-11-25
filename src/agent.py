"""Fase 5: Orquestador Multi-Agente multi-proveedor (DeepSeek, OpenAI, Gemini, Claude, OpenCode, etc.), Tools, contexto Bolivia/La Paz y Guardrails."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from src.guardrails import validar_entrada, validar_salida
from src.llm_provider import LLMConfig, chat_completion, resolve_llm_config
from src.tools import (
    get_tipo_cambio_bob,
    tool_analizar_url_phishing,
    tool_clasificar_trafico_ml,
    tool_consultar_vulnerabilidades,
    tool_contexto_oficial_bolivia,
    tool_optimizar_mitigacion_ag,
)

BASE_DIR = Path(__file__).resolve().parent.parent
PERFILES_PATH = BASE_DIR / "data" / "perfiles_lapaz.json"

DEFAULT_TECHS = ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]


def _get_llm_config(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLMConfig:
    return resolve_llm_config(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )


def cargar_perfil(perfil_id: str | None) -> dict[str, Any] | None:
    if not perfil_id or not PERFILES_PATH.exists():
        return None
    with PERFILES_PATH.open("r", encoding="utf-8") as f:
        perfiles = json.load(f)
    for p in perfiles:
        if p.get("id") == perfil_id:
            return p
    return None


def _extraer_presupuesto_bob_a_usd(
    query: str, tipo_cambio_bob: float | None = None
) -> float | None:
    """Si la consulta expresa un presupuesto explícito en Bolivianos (Bs), lo convierte a USD."""
    match = re.search(
        r"(?:bs\.?\s*(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*(?:bs\.?|bolivianos))",
        query,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    raw = match.group(1) or match.group(2)
    tc = get_tipo_cambio_bob(tipo_cambio_bob)
    return round(float(raw) / tc, 2)


def _agente_planificador(
    llm_config: LLMConfig,
    query: str,
    perfil: dict[str, Any] | None,
    has_traffic_features: bool,
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Agente Planificador: decide qué herramientas y parámetros ejecutar."""
    tc = get_tipo_cambio_bob(tipo_cambio_bob)
    perfil_ctx = json.dumps(perfil, ensure_ascii=False) if perfil else "Sin perfil preseleccionado"
    prompt = (
        "Eres el Agente Planificador de un sistema defensivo de ciberseguridad para la ciudad y departamento de La Paz, Bolivia.\n"
        "Analiza la consulta y el perfil operativo, y devuelve EXCLUSIVAMENTE un JSON válido con las claves:\n"
        '- "tecnologias": lista con subconjunto de ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]\n'
        f'- "presupuesto_max_usd": número float en USD (si la consulta está en Bs/bolivianos divide entre {tc}; usa el del perfil si existe, o 50.0 por defecto)\n'
        '- "horas_max": número float (usa el del perfil si existe, o 6.0 por defecto)\n'
        '- "ejecutar_ml": booleano (true si hay features de tráfico de red)\n\n'
        f"Perfil: {perfil_ctx}\n"
        f"¿Tiene features de tráfico?: {has_traffic_features}\n"
        f"Consulta: {query}"
    )

    raw = chat_completion(
        llm_config,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=180,
    )
    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    plan: dict[str, Any] = {}
    if match:
        try:
            plan = json.loads(match.group(0))
        except json.JSONDecodeError:
            plan = {}

    techs = [t for t in plan.get("tecnologias", []) if t in DEFAULT_TECHS]
    if not techs:
        techs = perfil.get("tecnologias", DEFAULT_TECHS) if perfil else DEFAULT_TECHS

    presupuesto_default = (
        perfil.get("presupuesto_disponible_usd", 50.0) if perfil else 50.0
    )
    presupuesto_bob_usd = _extraer_presupuesto_bob_a_usd(query, tipo_cambio_bob=tc)
    if presupuesto_bob_usd is not None and "presupuesto_max_usd" not in plan:
        presupuesto = presupuesto_bob_usd
    else:
        presupuesto = float(plan.get("presupuesto_max_usd", presupuesto_default))

    horas = float(
        plan.get(
            "horas_max",
            perfil.get("horas_tecnicas_disponibles", 6.0) if perfil else 6.0,
        )
    )

    presupuesto_limpio = max(0.0, round(presupuesto, 2))
    return {
        "tecnologias": techs,
        "presupuesto_max_usd": presupuesto_limpio,
        "presupuesto_max_bob": round(presupuesto_limpio * tc, 2),
        "tipo_cambio_bob": tc,
        "horas_max": max(0.5, horas),
        "ejecutar_ml": bool(has_traffic_features or plan.get("ejecutar_ml", False)),
    }


def _ejecutor_tools(
    plan: dict[str, Any],
    features_trafico: dict[str, Any] | None,
    url_sospechosa: str | None = None,
    query: str = "",
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Ejecutor de Tools: corre las herramientas deterministas y guarda el registro."""
    tc = get_tipo_cambio_bob(tipo_cambio_bob or plan.get("tipo_cambio_bob"))
    registro: dict[str, Any] = {
        "plan": plan,
        "tools_ejecutadas": [],
    }
    tipos_alerta: list[str] = ["vulnerabilidades"]

    if features_trafico:
        try:
            ml_res = tool_clasificar_trafico_ml(features_trafico)
            registro["ml_trafico"] = ml_res
            registro["tools_ejecutadas"].append("tool_clasificar_trafico_ml")
            tipos_alerta.append("trafico_red")
        except FileNotFoundError as exc:
            registro["ml_trafico"] = {"error": str(exc)}

    if url_sospechosa:
        try:
            phish_res = tool_analizar_url_phishing(url_sospechosa)
            registro["phishing_url"] = phish_res
            registro["tools_ejecutadas"].append("tool_analizar_url_phishing")
            tipos_alerta.append("phishing_qr")
        except FileNotFoundError as exc:
            registro["phishing_url"] = {"error": str(exc)}
    elif re.search(
        r"\b(phishing|quishing|qr|estafa|suplantaci[oó]n|asfi|att)\b",
        query,
        re.IGNORECASE,
    ):
        tipos_alerta.append("phishing_qr")

    vuln_res = tool_consultar_vulnerabilidades(plan["tecnologias"], tipo_cambio_bob=tc)
    registro["vulnerabilidades"] = vuln_res
    registro["tools_ejecutadas"].append("tool_consultar_vulnerabilidades")

    ag_res = tool_optimizar_mitigacion_ag(
        vuln_res["vulnerabilidades"],
        plan["presupuesto_max_usd"],
        plan["horas_max"],
        tipo_cambio_bob=tc,
    )
    registro["algoritmo_genetico"] = ag_res
    registro["tools_ejecutadas"].append("tool_optimizar_mitigacion_ag")

    ctx_bo = tool_contexto_oficial_bolivia(tipos_alerta, tipo_cambio_bob=tc)
    registro["canales_oficiales_bolivia"] = ctx_bo
    registro["tools_ejecutadas"].append("tool_contexto_oficial_bolivia")

    return registro


def _compactar_registro_para_llm(registro_tools: dict[str, Any]) -> dict[str, Any]:
    """Resume registro_tools para minimizar consumo de tokens sin perder trazabilidad."""
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
    if "ml_trafico" in registro_tools:
        compacto["ml_trafico"] = registro_tools["ml_trafico"]
    if "phishing_url" in registro_tools:
        compacto["phishing_url"] = registro_tools["phishing_url"]
    if "canales_oficiales_bolivia" in registro_tools:
        compacto["canales_oficiales_bolivia"] = registro_tools["canales_oficiales_bolivia"]
    return compacto


def _agente_redactor(
    llm_config: LLMConfig,
    query: str,
    perfil: dict[str, Any] | None,
    registro_tools: dict[str, Any],
    pide_estadisticas_lapaz: bool,
    feedback_guardrail: str | None = None,
) -> str:
    """Agente Redactor Técnico: redacta diagnóstico trazable estrictamente a registro_tools."""
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
    """Respuesta determinista segura si el Redactor falla la verificación."""
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
    """Ejecuta el pipeline multi-agente completo con Guardrails, cualquier proveedor LLM y medición de latencia."""
    t0 = time.perf_counter()
    load_dotenv(BASE_DIR / ".env")
    perfil = cargar_perfil(perfil_id)
    tc = get_tipo_cambio_bob(tipo_cambio_bob)

    # 1. Input Guardrail
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

    llm_config = _get_llm_config(
        provider=llm_provider,
        model=llm_model,
        api_key=llm_api_key,
        base_url=llm_base_url,
    )

    # Detectar URL en consulta si no vino explícita
    if not url_sospechosa:
        url_match = re.search(r"https?://\S+", query)
        if url_match:
            url_sospechosa = url_match.group(0).rstrip(".,;)")

    # 2. Planificador
    plan = _agente_planificador(
        llm_config,
        query,
        perfil,
        has_traffic_features=bool(features_trafico),
        tipo_cambio_bob=tc,
    )

    # 3. Ejecutor de Tools
    registro_tools = _ejecutor_tools(
        plan, features_trafico, url_sospechosa, query=query, tipo_cambio_bob=tc
    )

    # 4. Redactor Técnico + 5. Verificador (Output Guardrail) con 1 reintento
    pide_stats = bool(in_check["pide_estadisticas_lapaz"])
    borrador = _agente_redactor(
        llm_config, query, perfil, registro_tools, pide_stats
    )
    out_check = validar_salida(
        borrador, registro_tools, pide_estadisticas_lapaz=pide_stats
    )
    estado = "APROBADO"

    if not out_check["aprobado"]:
        feedback = "; ".join(out_check["errores"])
        borrador = _agente_redactor(
            llm_config,
            query,
            perfil,
            registro_tools,
            pide_stats,
            feedback_guardrail=feedback,
        )
        out_check = validar_salida(
            borrador, registro_tools, pide_estadisticas_lapaz=pide_stats
        )
        if out_check["aprobado"]:
            estado = "CORREGIDO_POR_GUARDRAIL"
        else:
            borrador = _fallback_determinista(registro_tools, pide_stats)
            out_check = validar_salida(
                borrador, registro_tools, pide_estadisticas_lapaz=pide_stats
            )
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
