"""Fase 4: Herramientas puras de IA (ML, consulta de CVEs y Algoritmo Genético)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

from src.train_phishing import URL_FEATURE_COLUMNS, extract_url_features

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

CVE_CACHE_PATH = DATA_DIR / "cve_cache.json"
KEV_CSV_PATH = DATA_DIR / "known_exploited_vulnerabilities.csv"
URLHAUS_CSV_PATH = DATA_DIR / "urlhaus_recent.csv"
MODEL_PATH = MODELS_DIR / "modelo_red_unsw.joblib"
PHISHING_MODEL_PATH = MODELS_DIR / "modelo_phishing_url.joblib"

FEATURE_COLUMNS = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_src_ltm",
    "ct_srv_dst",
    "proto",
    "service",
    "state",
]

TECH_ALIASES = {
    "router": "router_wifi",
    "wifi": "router_wifi",
    "wi-fi": "router_wifi",
    "router_wifi": "router_wifi",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "apache": "servidor_web",
    "nginx": "servidor_web",
    "web": "servidor_web",
    "servidor_web": "servidor_web",
    "http": "servidor_web",
    "smb": "smb",
    "samba": "smb",
    "rdp": "rdp",
    "escritorio_remoto": "rdp",
}


@lru_cache(maxsize=1)
def _load_ml_pipeline() -> Any:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modelo ML no encontrado en {MODEL_PATH}. Ejecute src/train_ml.py primero."
        )
    return joblib.load(MODEL_PATH)


def tool_clasificar_trafico_ml(features_dict: dict[str, Any]) -> dict[str, Any]:
    """Clasifica un flujo de red usando el pipeline RandomForest entrenado en UNSW-NB15."""
    pipeline = _load_ml_pipeline()
    row = {col: features_dict.get(col, np.nan) for col in FEATURE_COLUMNS}
    df_row = pd.DataFrame([row], columns=FEATURE_COLUMNS)

    pred = int(pipeline.predict(df_row)[0])
    probs = pipeline.predict_proba(df_row)[0]
    prob_normal = float(probs[0])
    prob_ataque = float(probs[1])
    etiqueta = "ataque" if pred == 1 else "normal"

    return {
        "etiqueta": etiqueta,
        "probabilidad_ataque": round(prob_ataque, 4),
        "probabilidad_normal": round(prob_normal, 4),
        "confianza": round(max(prob_normal, prob_ataque), 4),
    }


def _normalize_tech(name: str) -> str:
    cleaned = name.strip().lower().replace(" ", "_")
    return TECH_ALIASES.get(cleaned, cleaned)


@lru_cache(maxsize=1)
def _load_cisa_kev() -> set[str]:
    if not KEV_CSV_PATH.exists():
        return set()
    df = pd.read_csv(KEV_CSV_PATH, usecols=["cveID"])
    return set(df["cveID"].dropna().astype(str).str.upper().str.strip())


@lru_cache(maxsize=1)
def _load_phishing_pipeline() -> Any:
    if not PHISHING_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modelo de phishing no encontrado en {PHISHING_MODEL_PATH}. Ejecute src/train_phishing.py primero."
        )
    return joblib.load(PHISHING_MODEL_PATH)


@lru_cache(maxsize=1)
def _load_urlhaus_index() -> dict[str, str]:
    if not URLHAUS_CSV_PATH.exists():
        return {}
    df = pd.read_csv(
        URLHAUS_CSV_PATH,
        comment="#",
        names=[
            "id",
            "dateadded",
            "url",
            "url_status",
            "last_online",
            "threat",
            "tags",
            "urlhaus_link",
            "reporter",
        ],
        usecols=["url", "threat"],
    )
    index: dict[str, str] = {}
    for _, row in df.dropna(subset=["url"]).iterrows():
        u = str(row["url"]).strip().lower()
        t = str(row.get("threat", "malware_download")).strip()
        index[u] = t
    return index


def tool_analizar_url_phishing(url: str) -> dict[str, Any]:
    """Analiza una URL sospechosa combinando URLhaus (threat intel) y modelo ML PhiUSIIL."""
    u_clean = url.strip()
    urlhaus = _load_urlhaus_index()
    threat = urlhaus.get(u_clean.lower())
    en_urlhaus = threat is not None

    pipeline = _load_phishing_pipeline()
    feats = extract_url_features(u_clean)
    df_row = pd.DataFrame([feats], columns=URL_FEATURE_COLUMNS)
    pred = int(pipeline.predict(df_row)[0])
    prob_phish = float(pipeline.predict_proba(df_row)[0][1])

    etiqueta_ml = "phishing" if pred == 1 else "legitima"
    veredicto = "peligrosa" if (en_urlhaus or pred == 1) else "segura"

    return {
        "url": u_clean,
        "en_urlhaus": en_urlhaus,
        "amenaza_urlhaus": threat,
        "etiqueta_ml": etiqueta_ml,
        "probabilidad_phishing": round(prob_phish, 4),
        "veredicto": veredicto,
    }


def tool_consultar_vulnerabilidades(tecnologias: list[str]) -> dict[str, Any]:
    """Consulta CVEs reales en data/cve_cache.json filtrados por tecnología y CISA KEV."""
    if not CVE_CACHE_PATH.exists():
        raise FileNotFoundError(
            f"Caché de CVEs no encontrada en {CVE_CACHE_PATH}. Ejecute src/build_data.py."
        )

    with CVE_CACHE_PATH.open("r", encoding="utf-8") as f:
        cache: list[dict[str, Any]] = json.load(f)

    kev_set = _load_cisa_kev()
    normalized = [_normalize_tech(t) for t in tecnologias if str(t).strip()]
    target_set = set(normalized)

    matched: list[dict[str, Any]] = []
    for item in cache:
        if item.get("tecnologia") in target_set:
            cvss = float(item["cvss"])
            epss = float(item["epss"])
            en_kev = item["cve_id"].upper() in kev_set
            peso_kev = 1.5 if en_kev else 1.0
            matched.append(
                {
                    "cve_id": item["cve_id"],
                    "tecnologia": item["tecnologia"],
                    "cvss": cvss,
                    "epss": epss,
                    "en_cisa_kev": en_kev,
                    "riesgo_ponderado": round(cvss * epss * peso_kev, 4),
                    "costo_remediacion_usd": float(item["costo_remediacion_usd"]),
                    "horas_remediacion": float(item["horas_remediacion"]),
                    "descripcion": item.get("descripcion", ""),
                    "fuente": item.get("fuente", "NIST NVD v2.0 + FIRST EPSS"),
                }
            )

    matched.sort(key=lambda x: x["riesgo_ponderado"], reverse=True)
    return {
        "tecnologias_consultadas": sorted(target_set),
        "total_vulnerabilidades": len(matched),
        "vulnerabilidades": matched,
    }


def _repair_chromosome(
    chrom: np.ndarray,
    risks: np.ndarray,
    costs: np.ndarray,
    hours: np.ndarray,
    max_cost: float,
    max_hours: float,
) -> np.ndarray:
    """Repara un cromosoma removiendo controles menos eficientes si excede restricciones."""
    repaired = chrom.copy()
    while True:
        total_cost = float(np.dot(repaired, costs))
        total_hours = float(np.dot(repaired, hours))
        if total_cost <= max_cost + 1e-9 and total_hours <= max_hours + 1e-9:
            break
        active = np.where(repaired == 1)[0]
        if len(active) == 0:
            break
        # Eliminar el control activo con menor relación riesgo / (costo + horas + eps)
        efficiencies = risks[active] / (costs[active] + hours[active] + 0.1)
        worst_idx = active[int(np.argmin(efficiencies))]
        repaired[worst_idx] = 0
    return repaired


def tool_optimizar_mitigacion_ag(
    vulnerabilidades: list[dict[str, Any]],
    presupuesto_max_usd: float,
    horas_max: float,
    seed: int = 42,
) -> dict[str, Any]:
    """Optimiza la selección de controles de mitigación mediante Algoritmo Genético."""
    if not vulnerabilidades:
        return {
            "controles_seleccionados": [],
            "riesgo_inicial": 0.0,
            "riesgo_mitigado": 0.0,
            "riesgo_residual": 0.0,
            "riesgo_reducido_pct": 0.0,
            "costo_total_usd": 0.0,
            "horas_totales": 0.0,
            "presupuesto_max_usd": float(presupuesto_max_usd),
            "horas_max": float(horas_max),
            "parametros_ag": {
                "poblacion": 0,
                "generaciones": 0,
                "tasa_cruce": 0.8,
                "tasa_mutacion": 0.08,
            },
        }

    rng = np.random.default_rng(seed)
    n_items = len(vulnerabilidades)
    risks = np.array(
        [
            float(v.get("riesgo_ponderado", float(v["cvss"]) * float(v["epss"])))
            for v in vulnerabilidades
        ],
        dtype=float,
    )
    costs = np.array(
        [float(v["costo_remediacion_usd"]) for v in vulnerabilidades], dtype=float
    )
    hours = np.array(
        [float(v["horas_remediacion"]) for v in vulnerabilidades], dtype=float
    )
    total_initial_risk = float(np.sum(risks))

    pop_size = 60
    generations = 80
    crossover_rate = 0.8
    mutation_rate = max(0.05, min(0.15, 1.0 / max(n_items, 1)))
    elitism_count = 2

    population = rng.integers(0, 2, size=(pop_size, n_items), dtype=int)

    def fitness(chrom: np.ndarray) -> float:
        c = float(np.dot(chrom, costs))
        h = float(np.dot(chrom, hours))
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
            # Selección por torneo (k=3)
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

    selected = [
        vulnerabilidades[i] for i in range(n_items) if int(best_chrom[i]) == 1
    ]
    selected.sort(
        key=lambda x: float(x["cvss"]) * float(x["epss"]), reverse=True
    )

    riesgo_mitigado = float(np.dot(best_chrom, risks))
    riesgo_residual = max(0.0, total_initial_risk - riesgo_mitigado)
    riesgo_reducido_pct = (
        (riesgo_mitigado / total_initial_risk) * 100.0
        if total_initial_risk > 0
        else 0.0
    )

    return {
        "controles_seleccionados": selected,
        "riesgo_inicial": round(total_initial_risk, 4),
        "riesgo_mitigado": round(riesgo_mitigado, 4),
        "riesgo_residual": round(riesgo_residual, 4),
        "riesgo_reducido_pct": round(riesgo_reducido_pct, 2),
        "costo_total_usd": round(float(np.dot(best_chrom, costs)), 2),
        "horas_totales": round(float(np.dot(best_chrom, hours)), 2),
        "presupuesto_max_usd": float(presupuesto_max_usd),
        "horas_max": float(horas_max),
        "parametros_ag": {
            "poblacion": pop_size,
            "generaciones": generations,
            "tasa_cruce": crossover_rate,
            "tasa_mutacion": round(mutation_rate, 3),
        },
    }
