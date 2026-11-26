"""Agente Planificador y carga de perfiles operativos de La Paz."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from src.llm_provider import LLMConfig, chat_completion
from src.tools import get_tipo_cambio_bob

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PERFILES_PATH = BASE_DIR / "data" / "perfiles_lapaz.json"
DEFAULT_TECHS = ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]


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
    """Agente Planificador (Plan-and-Execute): infiere tecnologías, presupuesto y herramientas."""
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

    presupuesto_default = perfil.get("presupuesto_disponible_usd", 50.0) if perfil else 50.0
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
