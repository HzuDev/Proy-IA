"""Fase 6: Suite de evaluación automática sobre 15 casos de prueba."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.agent import ejecutar_diagnostico

DATASET_PATH = BASE_DIR / "evals" / "eval_dataset.json"
RESULTS_PATH = BASE_DIR / "evals" / "eval_results.json"


def run_suite() -> dict[str, Any]:
    with DATASET_PATH.open("r", encoding="utf-8") as f:
        cases: list[dict[str, Any]] = json.load(f)

    resultados: list[dict[str, Any]] = []
    fieles = 0
    bloqueos_esperados = 0
    bloqueos_correctos = 0
    reducciones_ag: list[float] = []
    latencias: list[float] = []

    for case in cases:
        print(f"Ejecutando {case['id']} ({case['tipo']})...")
        res = ejecutar_diagnostico(
            query=case["query"],
            perfil_id=case.get("perfil_id"),
        )
        latencias.append(res["latencia_seg"])

        if case["espera_bloqueo_entrada"]:
            bloqueos_esperados += 1
            if res["bloqueado"]:
                bloqueos_correctos += 1
                fieles += 1
        else:
            if not res["bloqueado"] and res["validacion_salida"]["aprobado"]:
                fieles += 1
            ag = res.get("registro_tools", {}).get("algoritmo_genetico", {})
            if "riesgo_reducido_pct" in ag:
                reducciones_ag.append(float(ag["riesgo_reducido_pct"]))

        resultados.append(
            {
                "id": case["id"],
                "tipo": case["tipo"],
                "bloqueado": res["bloqueado"],
                "estado_guardrail": res["estado_guardrail"],
                "validacion_salida": res["validacion_salida"],
                "riesgo_reducido_pct": res.get("registro_tools", {})
                .get("algoritmo_genetico", {})
                .get("riesgo_reducido_pct"),
                "latencia_seg": res["latencia_seg"],
            }
        )

    total = len(cases)
    summary = {
        "total_casos": total,
        "tasa_fidelidad_pct": round((fieles / total) * 100.0, 2) if total else 0.0,
        "tasa_bloqueo_guardrail_pct": (
            round((bloqueos_correctos / bloqueos_esperados) * 100.0, 2)
            if bloqueos_esperados
            else 100.0
        ),
        "reduccion_promedio_riesgo_ag_pct": (
            round(sum(reducciones_ag) / len(reducciones_ag), 2)
            if reducciones_ag
            else 0.0
        ),
        "latencia_promedio_seg": (
            round(sum(latencias) / len(latencias), 3) if latencias else 0.0
        ),
        "detalle": resultados,
    }

    with RESULTS_PATH.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n=== RESUMEN EVALS ===")
    print(json.dumps({k: v for k, v in summary.items() if k != "detalle"}, indent=2))
    return summary


if __name__ == "__main__":
    run_suite()
