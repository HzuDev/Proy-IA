"""Constructor de caché verificada de CVEs desde NIST NVD v2.0 y FIRST EPSS."""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

import requests

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CVE_CACHE_PATH = DATA_DIR / "cve_cache.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

TECH_QUERIES: list[dict[str, Any]] = [
    {"tecnologia": "router_wifi", "keyword": "router wireless", "max_items": 6, "costo_base": 0.0, "horas_base": 1.0},
    {"tecnologia": "wordpress", "keyword": "WordPress plugin", "max_items": 6, "costo_base": 15.0, "horas_base": 1.5},
    {"tecnologia": "servidor_web", "keyword": "Apache HTTP Server", "max_items": 6, "costo_base": 20.0, "horas_base": 2.0},
    {"tecnologia": "smb", "keyword": "Microsoft Server Message Block", "max_items": 5, "costo_base": 0.0, "horas_base": 1.5},
    {"tecnologia": "rdp", "keyword": "Remote Desktop Services", "max_items": 5, "costo_base": 10.0, "horas_base": 1.5},
]


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()[:400]
    if descriptions and descriptions[0].get("value"):
        return str(descriptions[0]["value"]).strip()[:400]
    return "Sin descripción disponible en NVD."


def _fetch_nvd_with_retry(
    session: requests.Session, keyword: str, results_per_page: int = 20
) -> list[dict[str, Any]]:
    params = {"keywordSearch": keyword, "resultsPerPage": results_per_page}
    headers = {"User-Agent": "ProyIA-LaPaz-Thesis/1.0"}
    backoff = 6.0

    for attempt in range(4):
        try:
            resp = session.get(NVD_URL, params=params, headers=headers, timeout=25)
            if resp.status_code == 200:
                return resp.json().get("vulnerabilities", [])
            if resp.status_code in (403, 429, 503):
                print(f"[NVD] Rate limit ({resp.status_code}) para '{keyword}'. Esperando {backoff:.1f}s...")
                time.sleep(backoff)
                backoff *= 1.5
                continue
            print(f"[NVD] HTTP {resp.status_code} para '{keyword}'.")
            return []
        except requests.RequestException as exc:
            print(f"[NVD] Error para '{keyword}': {exc} (intento {attempt + 1}/4)")
            time.sleep(backoff)
            backoff *= 1.5
    return []


def _fetch_epss_batch(session: requests.Session, cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    epss_map: dict[str, float] = {}
    for i in range(0, len(cve_ids), 25):
        chunk = cve_ids[i : i + 25]
        for attempt in range(3):
            try:
                resp = session.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=20)
                if resp.status_code == 200:
                    for row in resp.json().get("data", []):
                        cid, val = row.get("cve"), row.get("epss")
                        if cid and val is not None:
                            epss_map[cid] = round(float(val), 6)
                    break
                time.sleep(2.0 * (attempt + 1))
            except requests.RequestException as exc:
                print(f"[EPSS] Error (intento {attempt + 1}/3): {exc}")
                time.sleep(2.0 * (attempt + 1))
    return epss_map


def _estimate_remediation(cvss: float, costo_base: float, horas_base: float) -> tuple[float, float]:
    if cvss >= 9.0:
        return round(costo_base + 15.0, 2), round(horas_base + 1.0, 1)
    if cvss >= 7.0:
        return round(costo_base + 5.0, 2), round(horas_base + 0.5, 1)
    return round(costo_base, 2), round(horas_base, 1)


def build_cve_cache() -> list[dict[str, Any]]:
    """Construye y guarda data/cve_cache.json desde NIST NVD v2.0 y FIRST EPSS."""
    session = requests.Session()
    collected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for spec in TECH_QUERIES:
        vulns = _fetch_nvd_with_retry(session, spec["keyword"], results_per_page=25)
        count_for_tech = 0
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen_ids:
                continue
            cvss = _extract_cvss(cve.get("metrics", {}))
            if cvss is None:
                continue

            costo, horas = _estimate_remediation(cvss, spec["costo_base"], spec["horas_base"])
            seen_ids.add(cve_id)
            collected.append(
                {
                    "cve_id": cve_id,
                    "descripcion": _extract_description(cve.get("descriptions", [])),
                    "tecnologia": spec["tecnologia"],
                    "cvss": round(cvss, 1),
                    "epss": None,
                    "costo_remediacion_usd": costo,
                    "horas_remediacion": horas,
                    "fuente": "NIST NVD v2.0 + FIRST EPSS",
                }
            )
            count_for_tech += 1
            if count_for_tech >= spec["max_items"]:
                break

        time.sleep(6.2)

    epss_scores = _fetch_epss_batch(session, [c["cve_id"] for c in collected])
    final_cves = []
    for entry in collected:
        cid = entry["cve_id"]
        if cid in epss_scores:
            entry["epss"] = epss_scores[cid]
            final_cves.append(entry)

    if len(final_cves) < 20 and CVE_CACHE_PATH.exists():
        print("[AVISO] Respuesta parcial de NVD/EPSS; conservando caché existente válida.")
        with CVE_CACHE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with CVE_CACHE_PATH.open("w", encoding="utf-8") as f:
        json.dump(final_cves, f, ensure_ascii=False, indent=2)

    print(f"[OK] Guardados {len(final_cves)} CVEs reales en {CVE_CACHE_PATH}")
    return final_cves
