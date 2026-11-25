"""Fase 5: Orquestador Multi-Agente con DeepSeek API, Tools y Guardrails."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from src.guardrails import validar_entrada, validar_salida
from src.tools import (
    tool_analizar_url_phishing,
    tool_clasificar_trafico_ml,
    tool_consultar_vulnerabilidades,
    tool_optimizar_mitigacion_ag,
)

BASE_DIR = Path(__file__).resolve().parent.parent
PERFILES_PATH = BASE_DIR / "data" / "perfiles_lapaz.json"

DEFAULT_TECHS = ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]


def _get_client_and_model() -> tuple[OpenAI, str]:
    load_dotenv(BASE_DIR / ".env")
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip() or "deepseek-chat"
    if not api_key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY no está configurada en .env. Agrégala antes de ejecutar el agente."
        )
    return OpenAI(api_key=api_key, base_url="https://api.deepseek.com"), model


def cargar_perfil(perfil_id: str | None) -> dict[str, Any] | None:
    if not perfil_id or not PERFILES_PATH.exists():
        return None
    with PERFILES_PATH.open("r", encoding="utf-8") as f:
        perfiles = json.load(f)
    for p in perfiles:
        if p.get("id") == perfil_id:
            return p
    return None


def _agente_planificador(
    client: OpenAI,
    model: str,
    query: str,
    perfil: dict[str, Any] | None,
    has_traffic_features: bool,
) -> dict[str, Any]:
    """Agente Planificador: decide qué herramientas y parámetros ejecutar."""
    perfil_ctx = json.dumps(perfil, ensure_ascii=False) if perfil else "Sin perfil preseleccionado"
    prompt = (
        "Eres el Agente Planificador de un sistema defensivo de ciberseguridad para La Paz.\n"
        "Analiza la consulta y el perfil operativo, y devuelve EXCLUSIVAMENTE un JSON válido con las claves:\n"
        '- "tecnologias": lista con subconjunto de ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]\n'
        '- "presupuesto_max_usd": número float (usa el del perfil si existe, o 50.0 por defecto)\n'
        '- "horas_max": número float (usa el del perfil si existe, o 6.0 por defecto)\n'
        '- "ejecutar_ml": booleano (true si hay features de tráfico de red)\n\n'
        f"Perfil: {perfil_ctx}\n"
        f"¿Tiene features de tráfico?: {has_traffic_features}\n"
        f"Consulta: {query}"
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=120,
    )
    raw = (resp.choices[0].message.content or "").strip()
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

    presupuesto = float(
        plan.get(
            "presupuesto_max_usd",
            perfil.get("presupuesto_disponible_usd", 50.0) if perfil else 50.0,
        )
    )
    horas = float(
        plan.get(
            "horas_max",
            perfil.get("horas_tecnicas_disponibles", 6.0) if perfil else 6.0,
        )
    )

    return {
        "tecnologias": techs,
        "presupuesto_max_usd": max(0.0, presupuesto),
        "horas_max": max(0.5, horas),
        "ejecutar_ml": bool(has_traffic_features or plan.get("ejecutar_ml", False)),
    }


def _ejecutor_tools(
    plan: dict[str, Any],
    features_trafico: dict[str, Any] | None,
    url_sospechosa: str | None = None,
) -> dict[str, Any]:
    """Ejecutor de Tools: corre las herramientas deterministas y guarda el registro."""
    registro: dict[str, Any] = {
        "plan": plan,
        "tools_ejecutadas": [],
    }

    if features_trafico:
        try:
            ml_res = tool_clasificar_trafico_ml(features_trafico)
            registro["ml_trafico"] = ml_res
            registro["tools_ejecutadas"].append("tool_clasificar_trafico_ml")
        except FileNotFoundError as exc:
            registro["ml_trafico"] = {"error": str(exc)}

    if url_sospechosa:
        try:
            phish_res = tool_analizar_url_phishing(url_sospechosa)
            registro["phishing_url"] = phish_res
            registro["tools_ejecutadas"].append("tool_analizar_url_phishing")
        except FileNotFoundError as exc:
            registro["phishing_url"] = {"error": str(exc)}

    vuln_res = tool_consultar_vulnerabilidades(plan["tecnologias"])
    registro["vulnerabilidades"] = vuln_res
    registro["tools_ejecutadas"].append("tool_consultar_vulnerabilidades")

    ag_res = tool_optimizar_mitigacion_ag(
        vuln_res["vulnerabilidades"],
        plan["presupuesto_max_usd"],
        plan["horas_max"],
    )
    registro["algoritmo_genetico"] = ag_res
    registro["tools_ejecutadas"].append("tool_optimizar_mitigacion_ag")

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
            "riesgo_ponderado": c["riesgo_ponderado"],
            "costo_remediacion_usd": c["costo_remediacion_usd"],
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
            "horas_totales": ag.get("horas_totales", 0.0),
            "controles_seleccionados": controles_compactos,
        },
    }
    if "ml_trafico" in registro_tools:
        compacto["ml_trafico"] = registro_tools["ml_trafico"]
    if "phishing_url" in registro_tools:
        compacto["phishing_url"] = registro_tools["phishing_url"]
    return compacto


def _agente_redactor(
    client: OpenAI,
    model: str,
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
            "indica explícitamente que no existe en la caché real verificada (y NO repitas el ID inventado salvo para indicar que no consta, o mejor indica que el CVE consultado no figura en NIST NVD/caché)."
        )
    if feedback_guardrail:
        reglas_extra.append(f"CORRECCIÓN OBLIGATORIA DEL VERIFICADOR: {feedback_guardrail}")

    system_msg = (
        "Eres el Redactor Técnico de ciberseguridad preventiva para entidades de La Paz.\n"
        "REGLAS ESTRICTAS:\n"
        "1. Usa ÚNICAMENTE los CVE-IDs, puntajes CVSS/EPSS, costos, horas y porcentajes que aparecen literalmente en el JSON de herramientas.\n"
        "2. Nunca inventes CVEs, métricas ni estadísticas.\n"
        "3. Presenta el plan priorizado generado por el Algoritmo Genético de forma clara y accionable.\n"
        + ("\n".join(reglas_extra) if reglas_extra else "")
    )

    compact_tools = _compactar_registro_para_llm(registro_tools)
    user_msg = (
        f"Consulta: {query}\n"
        f"Perfil: {perfil.get('nombre', 'N/A') if perfil else 'N/A'}\n"
        f"Datos verificados:\n{json.dumps(compact_tools, ensure_ascii=False)}"
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.1,
        max_tokens=400,
    )
    return (resp.choices[0].message.content or "").strip()


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
    lines.append(
        f"Plan de mitigación optimizado por Algoritmo Genético: "
        f"riesgo reducido {ag.get('riesgo_reducido_pct', 0.0)}%, "
        f"costo total ${ag.get('costo_total_usd', 0.0)} USD, "
        f"horas totales {ag.get('horas_totales', 0.0)} h."
    )
    for c in controles:
        lines.append(
            f"- {c['cve_id']} ({c['tecnologia']}): CVSS {c['cvss']}, EPSS {c['epss']}, "
            f"costo ${c['costo_remediacion_usd']} USD, {c['horas_remediacion']} h."
        )
    return "\n".join(lines)


def ejecutar_diagnostico(
    query: str,
    perfil_id: str | None = None,
    features_trafico: dict[str, Any] | None = None,
    url_sospechosa: str | None = None,
) -> dict[str, Any]:
    """Ejecuta el pipeline multi-agente completo con Guardrails y medición de latencia."""
    t0 = time.perf_counter()
    perfil = cargar_perfil(perfil_id)

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

    client, model = _get_client_and_model()

    # Detectar URL en consulta si no vino explícita
    if not url_sospechosa:
        url_match = re.search(r"https?://\S+", query)
        if url_match:
            url_sospechosa = url_match.group(0).rstrip(".,;)")

    # 2. Planificador
    plan = _agente_planificador(
        client, model, query, perfil, has_traffic_features=bool(features_trafico)
    )

    # 3. Ejecutor de Tools
    registro_tools = _ejecutor_tools(plan, features_trafico, url_sospechosa)

    # 4. Redactor Técnico + 5. Verificador (Output Guardrail) con 1 reintento
    pide_stats = bool(in_check["pide_estadisticas_lapaz"])
    borrador = _agente_redactor(
        client, model, query, perfil, registro_tools, pide_stats
    )
    out_check = validar_salida(
        borrador, registro_tools, pide_estadisticas_lapaz=pide_stats
    )
    estado = "APROBADO"

    if not out_check["aprobado"]:
        feedback = "; ".join(out_check["errores"])
        borrador = _agente_redactor(
            client,
            model,
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
        "latencia_seg": round(time.perf_counter() - t0, 3),
    }
