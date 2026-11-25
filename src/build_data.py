"""Fase 2: Construcción de caché real de CVEs (NIST NVD v2.0 + FIRST EPSS)
y generación de 14 perfiles operativos de la ciudad y departamento de La Paz.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CVE_CACHE_PATH = DATA_DIR / "cve_cache.json"
PERFILES_PATH = DATA_DIR / "perfiles_lapaz.json"
TIPO_CAMBIO_BOB = float(os.getenv("TIPO_CAMBIO_BOB", "11.83"))

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

TECH_QUERIES: list[dict[str, Any]] = [
    {
        "tecnologia": "router_wifi",
        "keyword": "router wireless",
        "max_items": 6,
        "costo_base": 0.0,
        "horas_base": 1.0,
    },
    {
        "tecnologia": "wordpress",
        "keyword": "WordPress plugin",
        "max_items": 6,
        "costo_base": 15.0,
        "horas_base": 1.5,
    },
    {
        "tecnologia": "servidor_web",
        "keyword": "Apache HTTP Server",
        "max_items": 6,
        "costo_base": 20.0,
        "horas_base": 2.0,
    },
    {
        "tecnologia": "smb",
        "keyword": "Microsoft Server Message Block",
        "max_items": 5,
        "costo_base": 0.0,
        "horas_base": 1.5,
    },
    {
        "tecnologia": "rdp",
        "keyword": "Remote Desktop Services",
        "max_items": 5,
        "costo_base": 10.0,
        "horas_base": 1.5,
    },
]


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    """Extrae puntaje base CVSS real desde métricas NVD v3.1, v3.0 o v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    entries_v2 = metrics.get("cvssMetricV2") or []
    if entries_v2:
        score = entries_v2[0].get("cvssData", {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    """Prefiere descripción en inglés y acota longitud para trazabilidad."""
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()[:400]
    if descriptions and descriptions[0].get("value"):
        return str(descriptions[0]["value"]).strip()[:400]
    return "Sin descripción disponible en NVD."


def _fetch_nvd_with_retry(
    session: requests.Session, keyword: str, results_per_page: int = 20
) -> list[dict[str, Any]]:
    """Consulta NIST NVD v2.0 con manejo de rate limit y reintentos."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    headers = {"User-Agent": "ProyIA-LaPaz-Thesis/1.0"}
    backoff = 6.0

    for attempt in range(4):
        try:
            resp = session.get(NVD_URL, params=params, headers=headers, timeout=25)
            if resp.status_code == 200:
                return resp.json().get("vulnerabilities", [])
            if resp.status_code in (403, 429, 503):
                print(
                    f"[NVD] Rate limit/servicio ({resp.status_code}) para '{keyword}'. "
                    f"Esperando {backoff:.1f}s (intento {attempt + 1}/4)..."
                )
                time.sleep(backoff)
                backoff *= 1.5
                continue
            print(f"[NVD] HTTP {resp.status_code} para '{keyword}'.")
            return []
        except requests.RequestException as exc:
            print(
                f"[NVD] Error/timeout para '{keyword}': {exc}. "
                f"Reintento {attempt + 1}/4 en {backoff:.1f}s..."
            )
            time.sleep(backoff)
            backoff *= 1.5
    return []


def _fetch_epss_batch(
    session: requests.Session, cve_ids: list[str]
) -> dict[str, float]:
    """Consulta FIRST EPSS en lote para una lista de CVE IDs reales."""
    if not cve_ids:
        return {}
    epss_map: dict[str, float] = {}
    chunk_size = 25
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        params = {"cve": ",".join(chunk)}
        for attempt in range(3):
            try:
                resp = session.get(EPSS_URL, params=params, timeout=20)
                if resp.status_code == 200:
                    for row in resp.json().get("data", []):
                        cid = row.get("cve")
                        val = row.get("epss")
                        if cid and val is not None:
                            epss_map[cid] = round(float(val), 6)
                    break
                time.sleep(2.0 * (attempt + 1))
            except requests.RequestException as exc:
                print(f"[EPSS] Error/timeout (intento {attempt + 1}/3): {exc}")
                time.sleep(2.0 * (attempt + 1))
    return epss_map


def _estimate_remediation(
    cvss: float, costo_base: float, horas_base: float
) -> tuple[float, float]:
    """Estima costo (USD) y horas realistas para entidades de La Paz."""
    if cvss >= 9.0:
        return round(costo_base + 15.0, 2), round(horas_base + 1.0, 1)
    if cvss >= 7.0:
        return round(costo_base + 5.0, 2), round(horas_base + 0.5, 1)
    return round(costo_base, 2), round(horas_base, 1)


def build_cve_cache() -> list[dict[str, Any]]:
    """Construye y guarda data/cve_cache.json desde NIST NVD + FIRST EPSS."""
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

            desc = _extract_description(cve.get("descriptions", []))
            costo, horas = _estimate_remediation(
                cvss, spec["costo_base"], spec["horas_base"]
            )
            seen_ids.add(cve_id)
            collected.append(
                {
                    "cve_id": cve_id,
                    "descripcion": desc,
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

        # Respetar rate limit público de NVD (5 req / 30s sin API key)
        time.sleep(6.2)

    epss_scores = _fetch_epss_batch(session, [c["cve_id"] for c in collected])

    final_cves: list[dict[str, Any]] = []
    for entry in collected:
        cid = entry["cve_id"]
        if cid in epss_scores:
            entry["epss"] = epss_scores[cid]
            final_cves.append(entry)

    # Respaldo controlado si la red falló por completo y ya existía caché previa
    if len(final_cves) < 20 and CVE_CACHE_PATH.exists():
        print(
            "[AVISO] Respuesta parcial de NVD/EPSS; conservando caché existente válida."
        )
        with CVE_CACHE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with CVE_CACHE_PATH.open("w", encoding="utf-8") as f:
        json.dump(final_cves, f, ensure_ascii=False, indent=2)

    print(f"[OK] Guardados {len(final_cves)} CVEs reales en {CVE_CACHE_PATH}")
    return final_cves


def build_perfiles_lapaz() -> list[dict[str, Any]]:
    """Genera 14 perfiles técnicos representativos de la ciudad y departamento de La Paz."""
    perfiles = [
        {
            "id": "LPZ-CC-01",
            "nombre": "Centro Comunitario Alto Lima",
            "tipo": "Centro Comunitario",
            "municipio": "La Paz",
            "macrodistrito": "Max Paredes",
            "isp_tipico": "Entel",
            "usa_pagos_qr": False,
            "activos_digitales": [
                "Router Wi-Fi TP-Link para telecentro vecinal",
                "PCs compartidas con carpetas SMB en red local",
            ],
            "tecnologias": ["router_wifi", "smb"],
            "presupuesto_disponible_usd": 20.0,
            "horas_tecnicas_disponibles": 4.0,
            "contexto_operativo": "Telecentro comunitario con 12 equipos usados por jóvenes y vecinos.",
        },
        {
            "id": "LPZ-CC-02",
            "nombre": "Casa Cultural Comunitaria Villa Fátima",
            "tipo": "Centro Comunitario",
            "municipio": "La Paz",
            "macrodistrito": "Periférica",
            "isp_tipico": "Cotel",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Portal informativo en WordPress",
                "Router Wi-Fi abierto para talleres",
                "Servidor web Apache de eventos",
            ],
            "tecnologias": ["wordpress", "router_wifi", "servidor_web"],
            "presupuesto_disponible_usd": 35.0,
            "horas_tecnicas_disponibles": 5.0,
            "contexto_operativo": "Espacio cultural barrial administrado por voluntarios; recibe aportes e inscripciones por QR.",
        },
        {
            "id": "LPZ-CC-03",
            "nombre": "Centro de Capacitación Digital Cotahuma",
            "tipo": "Centro Comunitario",
            "municipio": "La Paz",
            "macrodistrito": "Cotahuma",
            "isp_tipico": "Entel",
            "usa_pagos_qr": False,
            "activos_digitales": [
                "Laboratorio con acceso remoto RDP para soporte",
                "Carpetas compartidas SMB",
                "Router Wi-Fi institucional",
            ],
            "tecnologias": ["rdp", "smb", "router_wifi"],
            "presupuesto_disponible_usd": 45.0,
            "horas_tecnicas_disponibles": 6.0,
            "contexto_operativo": "Centro de alfabetización digital para adultos mayores y escolares.",
        },
        {
            "id": "LPZ-CC-04",
            "nombre": "Telecentro Comunitario Municipal Viacha",
            "tipo": "Centro Comunitario",
            "municipio": "Viacha",
            "macrodistrito": "Provincia Ingavi",
            "isp_tipico": "Entel",
            "usa_pagos_qr": False,
            "activos_digitales": [
                "Router MikroTik de acceso comunitario",
                "PCs compartidas con carpetas SMB",
                "Portal vecinal en WordPress",
            ],
            "tecnologias": ["router_wifi", "smb", "wordpress"],
            "presupuesto_disponible_usd": 25.0,
            "horas_tecnicas_disponibles": 4.5,
            "contexto_operativo": "Telecentro provincial del departamento de La Paz con conectividad limitada y soporte eventual.",
        },
        {
            "id": "LPZ-UE-01",
            "nombre": "Unidad Educativa 6 de Junio - Turno Mañana",
            "tipo": "Unidad Educativa",
            "municipio": "La Paz",
            "macrodistrito": "San Antonio",
            "isp_tipico": "Entel",
            "usa_pagos_qr": False,
            "activos_digitales": [
                "Plataforma escolar en WordPress",
                "Servidor web Apache en aula de computación",
                "Router Wi-Fi docente",
            ],
            "tecnologias": ["wordpress", "servidor_web", "router_wifi"],
            "presupuesto_disponible_usd": 50.0,
            "horas_tecnicas_disponibles": 6.0,
            "contexto_operativo": "Colegio fiscal con laboratorio de informática y registro de notas local.",
        },
        {
            "id": "LPZ-UE-02",
            "nombre": "Unidad Educativa Técnico Humanístico Sopocachi",
            "tipo": "Unidad Educativa",
            "municipio": "La Paz",
            "macrodistrito": "Cotahuma",
            "isp_tipico": "Tigo",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Servidor de archivos SMB para material didáctico",
                "Acceso RDP para administración de aula",
                "Servidor web interno",
            ],
            "tecnologias": ["smb", "rdp", "servidor_web"],
            "presupuesto_disponible_usd": 75.0,
            "horas_tecnicas_disponibles": 8.0,
            "contexto_operativo": "Institución educativa con 25 computadoras en red y soporte técnico eventual.",
        },
        {
            "id": "LPZ-UE-03",
            "nombre": "Unidad Educativa Valle de Mallasa",
            "tipo": "Unidad Educativa",
            "municipio": "La Paz",
            "macrodistrito": "Mallasa",
            "isp_tipico": "Entel",
            "usa_pagos_qr": False,
            "activos_digitales": [
                "Router Wi-Fi de cobertura escolar",
                "Sitio web institucional en WordPress",
            ],
            "tecnologias": ["router_wifi", "wordpress"],
            "presupuesto_disponible_usd": 0.0,
            "horas_tecnicas_disponibles": 3.5,
            "contexto_operativo": "Escuela periurbana con presupuesto cero para licencias; depende de ajustes gratuitos.",
        },
        {
            "id": "LPZ-UE-04",
            "nombre": "Instituto Tecnológico Comunal El Tejar",
            "tipo": "Unidad Educativa",
            "municipio": "La Paz",
            "macrodistrito": "Max Paredes",
            "isp_tipico": "AXS",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Servidor web Apache para prácticas",
                "Acceso RDP a máquinas virtuales",
                "Carpetas SMB compartidas",
                "Router Wi-Fi de campus",
            ],
            "tecnologias": ["servidor_web", "rdp", "smb", "router_wifi"],
            "presupuesto_disponible_usd": 90.0,
            "horas_tecnicas_disponibles": 10.0,
            "contexto_operativo": "Centro de formación técnica con alta rotación de estudiantes en red.",
        },
        {
            "id": "LPZ-MY-01",
            "nombre": "Textiles Artesanales Illimani SRL (MYPE)",
            "tipo": "MYPE",
            "municipio": "La Paz",
            "macrodistrito": "Centro",
            "isp_tipico": "Tigo",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Tienda catálogo en WordPress",
                "Router Wi-Fi de oficina y taller",
            ],
            "tecnologias": ["wordpress", "router_wifi"],
            "presupuesto_disponible_usd": 40.0,
            "horas_tecnicas_disponibles": 4.0,
            "contexto_operativo": "Microempresa textil exportadora que gestiona pedidos por web, WhatsApp y pagos QR.",
        },
        {
            "id": "LPZ-MY-02",
            "nombre": "Imprenta y Diseño Gráfico Prado (MYPE)",
            "tipo": "MYPE",
            "municipio": "La Paz",
            "macrodistrito": "Centro",
            "isp_tipico": "AXS",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Servidor de archivos SMB con diseños de clientes",
                "Acceso RDP desde domicilio del diseñador",
                "Router Wi-Fi comercial",
            ],
            "tecnologias": ["smb", "rdp", "router_wifi"],
            "presupuesto_disponible_usd": 65.0,
            "horas_tecnicas_disponibles": 5.5,
            "contexto_operativo": "MYPE gráfica con cobros por QR y riesgo alto de pérdida de archivos por ransomware.",
        },
        {
            "id": "LPZ-MY-03",
            "nombre": "Café y Tostaduría Altura Sur (MYPE)",
            "tipo": "MYPE",
            "municipio": "La Paz",
            "macrodistrito": "Sur",
            "isp_tipico": "Tigo",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Router Wi-Fi para clientes y punto de venta",
                "Sitio WordPress con reservas",
                "Servidor web de menú digital",
            ],
            "tecnologias": ["router_wifi", "wordpress", "servidor_web"],
            "presupuesto_disponible_usd": 55.0,
            "horas_tecnicas_disponibles": 5.0,
            "contexto_operativo": "Negocio gastronómico con Wi-Fi compartido entre invitados, caja y cobros diarios por QR.",
        },
        {
            "id": "LPZ-MY-04",
            "nombre": "Ferretería y Materiales Obrajes (MYPE)",
            "tipo": "MYPE",
            "municipio": "La Paz",
            "macrodistrito": "Sur",
            "isp_tipico": "Cotel",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "PC inventario con carpetas SMB",
                "Acceso RDP de contador externo",
            ],
            "tecnologias": ["smb", "rdp"],
            "presupuesto_disponible_usd": 30.0,
            "horas_tecnicas_disponibles": 3.5,
            "contexto_operativo": "Pequeña ferretería con facturación, cobro por QR e inventario en una PC de escritorio.",
        },
        {
            "id": "LPZ-MY-05",
            "nombre": "Consultora Agrícola y Turística Hampaturi (MYPE)",
            "tipo": "MYPE",
            "municipio": "La Paz",
            "macrodistrito": "Hampaturi",
            "isp_tipico": "Entel LTE",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Portal WordPress de turismo comunitario",
                "Servidor web Apache",
                "Router Wi-Fi satelital/LTE",
            ],
            "tecnologias": ["wordpress", "servidor_web", "router_wifi"],
            "presupuesto_disponible_usd": 80.0,
            "horas_tecnicas_disponibles": 7.0,
            "contexto_operativo": "MYPE rural-urbana con conectividad intermitente, reservas en línea y cobros por QR.",
        },
        {
            "id": "LPZ-MY-06",
            "nombre": "Taller Textil y Comercializadora 16 de Julio (MYPE)",
            "tipo": "MYPE",
            "municipio": "El Alto",
            "macrodistrito": "Distrito 6",
            "isp_tipico": "Entel",
            "usa_pagos_qr": True,
            "activos_digitales": [
                "Router Wi-Fi TP-Link de taller y ventas",
                "PC de pedidos con carpetas compartidas SMB",
                "Catálogo web en WordPress",
            ],
            "tecnologias": ["router_wifi", "smb", "wordpress"],
            "presupuesto_disponible_usd": 30.0,
            "horas_tecnicas_disponibles": 4.0,
            "contexto_operativo": "MYPE manufacturera y comercial en El Alto que opera ventas por redes sociales y pagos QR.",
        },
    ]

    for p in perfiles:
        p["presupuesto_disponible_bob"] = round(
            float(p["presupuesto_disponible_usd"]) * TIPO_CAMBIO_BOB, 2
        )

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with PERFILES_PATH.open("w", encoding="utf-8") as f:
        json.dump(perfiles, f, ensure_ascii=False, indent=2)

    print(f"[OK] Generados {len(perfiles)} perfiles en {PERFILES_PATH}")
    return perfiles


def check_unsw_files() -> None:
    """Verifica presencia de los CSV de UNSW-NB15 en data/."""
    train_csv = DATA_DIR / "UNSW_NB15_training-set.csv"
    test_csv = DATA_DIR / "UNSW_NB15_testing-set.csv"
    print(f"[CHECK] {train_csv}: {'EXISTE' if train_csv.exists() else 'FALTA'}")
    print(f"[CHECK] {test_csv}: {'EXISTE' if test_csv.exists() else 'FALTA'}")


if __name__ == "__main__":
    check_unsw_files()
    cves = build_cve_cache()
    perfiles = build_perfiles_lapaz()
    print(
        f"Resumen Fase 2: {len(cves)} CVEs en caché, {len(perfiles)} perfiles de La Paz."
    )
