"""Tests unitarios para Fase 4: Algoritmo Genético y consulta de CVEs."""

import numpy as np

from src.tools import (
    tool_analizar_url_phishing,
    tool_consultar_vulnerabilidades,
    tool_optimizar_mitigacion_ag,
)


def _random_feasible_baseline(
    vulns: list[dict], max_cost: float, max_hours: float, trials: int = 30
) -> float:
    rng = np.random.default_rng(123)
    best_pct = 0.0
    total_risk = sum(v["cvss"] * v["epss"] for v in vulns)
    if total_risk == 0:
        return 0.0

    for _ in range(trials):
        order = rng.permutation(len(vulns))
        cost = 0.0
        hours = 0.0
        mitigated = 0.0
        for idx in order:
            v = vulns[idx]
            if (
                cost + v["costo_remediacion_usd"] <= max_cost
                and hours + v["horas_remediacion"] <= max_hours
            ):
                cost += v["costo_remediacion_usd"]
                hours += v["horas_remediacion"]
                mitigated += v["cvss"] * v["epss"]
        best_pct = max(best_pct, (mitigated / total_risk) * 100.0)
    return best_pct


def test_ag_respects_budget_and_hours_and_beats_random() -> None:
    consulta = tool_consultar_vulnerabilidades(
        ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]
    )
    vulns = consulta["vulnerabilidades"]
    assert len(vulns) >= 10

    presupuesto_max = 45.0
    horas_max = 5.5

    res_ag = tool_optimizar_mitigacion_ag(vulns, presupuesto_max, horas_max)

    assert res_ag["costo_total_usd"] <= presupuesto_max + 1e-6
    assert res_ag["horas_totales"] <= horas_max + 1e-6
    assert res_ag["riesgo_reducido_pct"] > 0.0

    # El AG debe igualar o superar una selección aleatoria factible promedio
    rng = np.random.default_rng(99)
    total_risk = sum(v["cvss"] * v["epss"] for v in vulns)
    random_pcts = []
    for _ in range(50):
        order = rng.permutation(len(vulns))
        c, h, m = 0.0, 0.0, 0.0
        for idx in order:
            v = vulns[idx]
            if (
                c + v["costo_remediacion_usd"] <= presupuesto_max
                and h + v["horas_remediacion"] <= horas_max
            ):
                c += v["costo_remediacion_usd"]
                h += v["horas_remediacion"]
                m += v["cvss"] * v["epss"]
        random_pcts.append((m / total_risk) * 100.0)

    avg_random = float(np.mean(random_pcts))
    assert res_ag["riesgo_reducido_pct"] >= avg_random


def test_phishing_and_urlhaus_tool() -> None:
    mal = tool_analizar_url_phishing("http://115.230.67.252:50864/bin.sh")
    assert mal["en_urlhaus"] is True
    assert mal["veredicto"] == "peligrosa"

    legit = tool_analizar_url_phishing("https://www.agetic.gob.bo")
    assert legit["en_urlhaus"] is False
    assert legit["etiqueta_ml"] == "legitima"
    assert legit["veredicto"] == "segura"
