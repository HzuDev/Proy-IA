"""Tool de inteligencia de vulnerabilidades (NVD, FIRST EPSS, CISA KEV y AGETIC CSIRT)."""

from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any

import pandas as pd

from src.tools.bolivia_context import get_tipo_cambio_bob

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CVE_CACHE_PATH = DATA_DIR / "cve_cache.json"
KEV_CSV_PATH = DATA_DIR / "known_exploited_vulnerabilities.csv"
AGETIC_CSIRT_CSV_PATH = DATA_DIR / "alertas_agetic_csirt.csv"

TECH_ALIASES = {
    "router": "router_wifi",
    "wifi": "router_wifi",
    "wi-fi": "router_wifi",
    "mikrotik": "router_wifi",
    "tp-link": "router_wifi",
    "tplink": "router_wifi",
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
def _load_agetic_csirt_cves() -> set[str]:
    if not AGETIC_CSIRT_CSV_PATH.exists():
        return set()
    try:
        df = pd.read_csv(AGETIC_CSIRT_CSV_PATH)
    except Exception:
        return set()

    cves: set[str] = set()
    for col in df.columns:
        for val in df[col].dropna().astype(str):
            for match in re.findall(r"CVE-\d{4}-\d{4,7}", val, flags=re.IGNORECASE):
                cves.add(match.upper())
    return cves


def tool_consultar_vulnerabilidades(
    tecnologias: list[str],
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Consulta CVEs verificados ponderando riesgo por CVSS × EPSS y bonos CISA KEV / AGETIC CSIRT."""
    if not CVE_CACHE_PATH.exists():
        raise FileNotFoundError(
            f"Caché de CVEs no encontrada en {CVE_CACHE_PATH}. Ejecute src/build_data.py."
        )

    with CVE_CACHE_PATH.open("r", encoding="utf-8") as f:
        cache: list[dict[str, Any]] = json.load(f)

    kev_set = _load_cisa_kev()
    agetic_set = _load_agetic_csirt_cves()
    tc_bob = get_tipo_cambio_bob(tipo_cambio_bob)
    target_set = {_normalize_tech(t) for t in tecnologias if str(t).strip()}

    matched: list[dict[str, Any]] = []
    for item in cache:
        if item.get("tecnologia") not in target_set:
            continue
        cvss = float(item["cvss"])
        epss = float(item["epss"])
        cid_upper = item["cve_id"].upper()
        en_kev = cid_upper in kev_set
        en_agetic = cid_upper in agetic_set
        peso_kev = 1.5 if en_kev else 1.0
        peso_agetic = 1.25 if en_agetic else 1.0
        costo_usd = float(item["costo_remediacion_usd"])
        matched.append(
            {
                "cve_id": item["cve_id"],
                "tecnologia": item["tecnologia"],
                "cvss": cvss,
                "epss": epss,
                "en_cisa_kev": en_kev,
                "en_agetic_csirt": en_agetic,
                "riesgo_ponderado": round(cvss * epss * peso_kev * peso_agetic, 4),
                "costo_remediacion_usd": costo_usd,
                "costo_remediacion_bob": round(costo_usd * tc_bob, 2),
                "horas_remediacion": float(item["horas_remediacion"]),
                "descripcion": item.get("descripcion", ""),
                "fuente": item.get("fuente", "NIST NVD v2.0 + FIRST EPSS"),
            }
        )

    matched.sort(key=lambda x: x["riesgo_ponderado"], reverse=True)
    return {
        "tecnologias_consultadas": sorted(target_set),
        "total_vulnerabilidades": len(matched),
        "alertas_agetic_cargadas": len(agetic_set),
        "tipo_cambio_bob": tc_bob,
        "vulnerabilidades": matched,
    }
