"""Tool metaheurística: Algoritmo Genético para optimización de controles defensivos."""

from __future__ import annotations

from typing import Any

import numpy as np

from src.tools.bolivia_context import get_tipo_cambio_bob


def _repair_chromosome(
    chrom: np.ndarray,
    risks: np.ndarray,
    costs: np.ndarray,
    hours: np.ndarray,
    max_cost: float,
    max_hours: float,
) -> np.ndarray:
    """Repara soluciones infactibles removiendo los genes con menor razón riesgo/(costo+horas)."""
    repaired = chrom.copy()
    while True:
        if float(np.dot(repaired, costs)) <= max_cost + 1e-9 and float(np.dot(repaired, hours)) <= max_hours + 1e-9:
            break
        active = np.where(repaired == 1)[0]
        if len(active) == 0:
            break
        efficiencies = risks[active] / (costs[active] + hours[active] + 0.1)
        repaired[active[int(np.argmin(efficiencies))]] = 0
    return repaired


def tool_optimizar_mitigacion_ag(
    vulnerabilidades: list[dict[str, Any]],
    presupuesto_max_usd: float,
    horas_max: float,
    seed: int = 42,
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Algoritmo Genético binario (elitismo, torneo, cruce y reparación) bajo presupuesto y horas."""
    tc_bob = get_tipo_cambio_bob(tipo_cambio_bob)

    if not vulnerabilidades:
        return {
            "controles_seleccionados": [],
            "riesgo_inicial": 0.0,
            "riesgo_mitigado": 0.0,
            "riesgo_residual": 0.0,
            "riesgo_reducido_pct": 0.0,
            "costo_total_usd": 0.0,
            "costo_total_bob": 0.0,
            "horas_totales": 0.0,
            "presupuesto_max_usd": float(presupuesto_max_usd),
            "presupuesto_max_bob": round(float(presupuesto_max_usd) * tc_bob, 2),
            "tipo_cambio_bob": tc_bob,
            "horas_max": float(horas_max),
            "parametros_ag": {
                "poblacion": 0, "generaciones": 0, "tasa_cruce": 0.8, "tasa_mutacion": 0.08,
            },
        }

    rng = np.random.default_rng(seed)
    n_items = len(vulnerabilidades)
    risks = np.array(
        [float(v.get("riesgo_ponderado", float(v["cvss"]) * float(v["epss"]))) for v in vulnerabilidades],
        dtype=float,
    )
    costs = np.array([float(v["costo_remediacion_usd"]) for v in vulnerabilidades], dtype=float)
    hours = np.array([float(v["horas_remediacion"]) for v in vulnerabilidades], dtype=float)
    total_initial_risk = float(np.sum(risks))

    pop_size, generations, crossover_rate, elitism_count = 60, 80, 0.8, 2
    mutation_rate = max(0.05, min(0.15, 1.0 / max(n_items, 1)))
    population = rng.integers(0, 2, size=(pop_size, n_items), dtype=int)

    def fitness(chrom: np.ndarray) -> float:
        c, h = float(np.dot(chrom, costs)), float(np.dot(chrom, hours))
        gain = float(np.dot(chrom, risks))
        penalty = 0.0
        if c > presupuesto_max_usd:
            penalty += 100.0 * (c - presupuesto_max_usd + 1.0)
        if h > horas_max:
            penalty += 100.0 * (h - horas_max + 1.0)
        return gain - penalty

    best_chrom = np.zeros(n_items, dtype=int)
    best_gain = -1.0

    for _ in range(generations):
        scores = np.array([fitness(ind) for ind in population], dtype=float)
        sorted_idx = np.argsort(scores)[::-1]

        for idx in sorted_idx[:5]:
            candidate = _repair_chromosome(
                population[idx], risks, costs, hours, presupuesto_max_usd, horas_max
            )
            gain = float(np.dot(candidate, risks))
            if gain > best_gain:
                best_gain = gain
                best_chrom = candidate.copy()

        new_pop = [population[idx].copy() for idx in sorted_idx[:elitism_count]]
        while len(new_pop) < pop_size:
            t1 = rng.choice(pop_size, size=3, replace=False)
            p1 = population[t1[int(np.argmax(scores[t1]))]]
            t2 = rng.choice(pop_size, size=3, replace=False)
            p2 = population[t2[int(np.argmax(scores[t2]))]]

            c1, c2 = p1.copy(), p2.copy()
            if n_items > 1 and rng.random() < crossover_rate:
                point = int(rng.integers(1, n_items))
                c1 = np.concatenate([p1[:point], p2[point:]])
                c2 = np.concatenate([p2[:point], p1[point:]])

            for child in (c1, c2):
                mut_mask = rng.random(n_items) < mutation_rate
                child[mut_mask] = 1 - child[mut_mask]
                new_pop.append(child)
                if len(new_pop) >= pop_size:
                    break

        population = np.array(new_pop[:pop_size], dtype=int)

    selected = [vulnerabilidades[i] for i in range(n_items) if int(best_chrom[i]) == 1]
    selected.sort(
        key=lambda x: float(x.get("riesgo_ponderado", float(x["cvss"]) * float(x["epss"]))),
        reverse=True,
    )

    riesgo_mitigado = float(np.dot(best_chrom, risks))
    riesgo_residual = max(0.0, total_initial_risk - riesgo_mitigado)
    riesgo_reducido_pct = (riesgo_mitigado / total_initial_risk) * 100.0 if total_initial_risk > 0 else 0.0
    costo_total_usd = round(float(np.dot(best_chrom, costs)), 2)

    return {
        "controles_seleccionados": selected,
        "riesgo_inicial": round(total_initial_risk, 4),
        "riesgo_mitigado": round(riesgo_mitigado, 4),
        "riesgo_residual": round(riesgo_residual, 4),
        "riesgo_reducido_pct": round(riesgo_reducido_pct, 2),
        "costo_total_usd": costo_total_usd,
        "costo_total_bob": round(costo_total_usd * tc_bob, 2),
        "horas_totales": round(float(np.dot(best_chrom, hours)), 2),
        "presupuesto_max_usd": float(presupuesto_max_usd),
        "presupuesto_max_bob": round(float(presupuesto_max_usd) * tc_bob, 2),
        "tipo_cambio_bob": tc_bob,
        "horas_max": float(horas_max),
        "parametros_ag": {
            "poblacion": pop_size,
            "generaciones": generations,
            "tasa_cruce": crossover_rate,
            "tasa_mutacion": round(mutation_rate, 3),
        },
    }
