"""Fase 4: Herramientas puras de IA (ML, consulta de CVEs, contexto Bolivia, API BCB y Algoritmo Genético)."""

from __future__ import annotations

from html.parser import HTMLParser
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import requests

from src.train_phishing import URL_FEATURE_COLUMNS, extract_url_features

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

CVE_CACHE_PATH = DATA_DIR / "cve_cache.json"
KEV_CSV_PATH = DATA_DIR / "known_exploited_vulnerabilities.csv"
AGETIC_CSIRT_CSV_PATH = DATA_DIR / "alertas_agetic_csirt.csv"
INE_MYPES_XLS_PATH = DATA_DIR / "INE-MYPES_DEPTO.xls"
CONTEXTO_BOLIVIA_PATH = DATA_DIR / "contexto_bolivia_lapaz.json"
URLHAUS_CSV_PATH = DATA_DIR / "urlhaus_recent.csv"
MODEL_PATH = MODELS_DIR / "modelo_red_unsw.joblib"
PHISHING_MODEL_PATH = MODELS_DIR / "modelo_phishing_url.joblib"

# Respaldo local si no hay conexión a APIs públicas del TCO BCB
TIPO_CAMBIO_BOB = 11.83
_TC_CACHE_TTL_SEG = 3600.0
_tc_api_cache: dict[str, Any] = {"ts": 0.0, "data": None}

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


class _SimpleHTMLTableParser(HTMLParser):
    """Extrae filas y celdas de tablas HTML (como el .xls exportado por SIIP/INE)."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._in_cell = False
        self._current_row: list[str] = []
        self._current_cell: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "tr":
            self._current_row = []
        elif t in ("td", "th"):
            self._in_cell = True
            self._current_cell = []

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("td", "th") and self._in_cell:
            text = " ".join("".join(self._current_cell).split())
            self._current_row.append(text)
            self._in_cell = False
        elif t == "tr" and self._current_row:
            self.rows.append(self._current_row)
            self._current_row = []

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._current_cell.append(data)


def _fix_mojibake(text: str) -> str:
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def _parse_int_es(val: str) -> int:
    cleaned = val.replace(".", "").replace(",", "").strip()
    return int(cleaned) if cleaned.isdigit() else 0


@lru_cache(maxsize=1)
def _load_ine_mypes_lapaz() -> dict[str, Any] | None:
    """Lee data/INE-MYPES_DEPTO.xls (tabla HTML exportada del SIIP/INE para La Paz)."""
    if not INE_MYPES_XLS_PATH.exists():
        return None
    try:
        raw = INE_MYPES_XLS_PATH.read_bytes().decode("latin-1", errors="replace")
    except Exception:
        return None

    parser = _SimpleHTMLTableParser()
    parser.feed(raw)

    sectores: list[dict[str, Any]] = []
    fuente = "INE-MYPES, Elaboración DGAPI"
    for row in parser.rows:
        if len(row) == 1 and "fuente:" in row[0].lower():
            fuente = _fix_mojibake(row[0])
            continue
        if len(row) != 6:
            continue
        if "actividad economica" in row[0].lower():
            continue
        actividad = _fix_mojibake(row[0]).strip()
        empresas = _parse_int_es(row[5])
        personal = _parse_int_es(row[4])
        if empresas > 0:
            sectores.append(
                {
                    "actividad_economica": actividad,
                    "valor_bruto_produccion": _parse_int_es(row[1]),
                    "consumo_intermedio": _parse_int_es(row[2]),
                    "valor_agregado": _parse_int_es(row[3]),
                    "personal_ocupado": personal,
                    "numero_empresas": empresas,
                }
            )

    if not sectores:
        return None

    sectores.sort(key=lambda x: x["numero_empresas"], reverse=True)
    total_empresas = sum(s["numero_empresas"] for s in sectores)
    total_personal = sum(s["personal_ocupado"] for s in sectores)
    return {
        "departamento": "La Paz",
        "fuente": fuente,
        "archivo": INE_MYPES_XLS_PATH.name,
        "total_empresas": total_empresas,
        "total_personal_ocupado": total_personal,
        "sector_principal": sectores[0]["actividad_economica"],
        "sectores": sectores,
    }


@lru_cache(maxsize=1)
def _load_contexto_bolivia() -> dict[str, Any]:
    if not CONTEXTO_BOLIVIA_PATH.exists():
        return {}
    with CONTEXTO_BOLIVIA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def obtener_tipo_cambio_oficial_bcb(force_refresh: bool = False) -> dict[str, Any]:
    """Consulta APIs públicas gratuitas del Tipo de Cambio Oficial (TCO) del BCB con caché y respaldo local."""
    now = time.time()
    cached = _tc_api_cache.get("data")
    if (
        not force_refresh
        and cached is not None
        and (now - float(_tc_api_cache.get("ts", 0.0))) < _TC_CACHE_TTL_SEG
    ):
        return dict(cached)

    proveedores = [
        (
            "https://apibcb.cucu.bo/api/v1/tc/oficial",
            lambda j: (
                float(j["tc_oficial"]["valor"]),
                str(j["tc_oficial"].get("fecha", "")),
                "BCB Oficial (vía apibcb.cucu.bo)",
            ),
        ),
        (
            "https://www.impuestos.wiki/api/v1/tipo-cambio",
            lambda j: (
                float(j["data"]["tipo_cambio"]),
                str(j["data"].get("fecha", "")),
                "BCB Oficial (vía impuestos.wiki)",
            ),
        ),
        (
            "https://bo.dolarapi.com/v1/dolares/oficial",
            lambda j: (
                float(j.get("venta") or j.get("compra")),
                str(j.get("fechaActualizacion", ""))[:10],
                "BCB Oficial (vía bo.dolarapi.com)",
            ),
        ),
    ]

    for url, extractor in proveedores:
        try:
            resp = requests.get(
                url,
                timeout=4,
                headers={"User-Agent": "ProyIA-LaPaz-Thesis/1.2"},
            )
            if resp.status_code != 200:
                continue
            valor, fecha, fuente = extractor(resp.json())
            if 1.0 < valor < 100.0:
                result = {
                    "valor_bob": round(valor, 4),
                    "fecha": fecha,
                    "fuente": fuente,
                    "en_vivo": True,
                }
                _tc_api_cache["ts"] = now
                _tc_api_cache["data"] = result
                return dict(result)
        except Exception:
            continue

    ctx_meta = _load_contexto_bolivia().get("metadata", {})
    fallback = {
        "valor_bob": float(ctx_meta.get("tipo_cambio_referencial_bob", TIPO_CAMBIO_BOB)),
        "fecha": str(ctx_meta.get("fecha_tipo_cambio", "")),
        "fuente": "Respaldo local (data/contexto_bolivia_lapaz.json)",
        "en_vivo": False,
    }
    _tc_api_cache["ts"] = now
    _tc_api_cache["data"] = fallback
    return dict(fallback)


def get_tipo_cambio_bob(override: float | None = None, usar_api: bool = True) -> float:
    """Obtiene el tipo de cambio oficial BCB (Bs/USD): override -> env TIPO_CAMBIO_BOB -> API pública -> JSON."""
    if override is not None and override > 0:
        return round(float(override), 4)
    env_val = os.getenv("TIPO_CAMBIO_BOB", "").strip()
    if env_val:
        try:
            parsed = float(env_val)
            if parsed > 0:
                return round(parsed, 4)
        except ValueError:
            pass
    if usar_api:
        return float(obtener_tipo_cambio_oficial_bcb()["valor_bob"])
    ctx = _load_contexto_bolivia()
    return float(ctx.get("metadata", {}).get("tipo_cambio_referencial_bob", TIPO_CAMBIO_BOB))


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
def _load_agetic_csirt_cves() -> set[str]:
    """Carga CVEs alertados por AGETIC CSIRT Bolivia si existe data/alertas_agetic_csirt.csv."""
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


def _token_en_texto(token: str, texto: str) -> bool:
    return bool(re.search(rf"(?:^|[.\-_/]){re.escape(token)}(?:$|[.\-_/])", texto))


def _es_dominio_oficial(host: str, dominios_permitidos: list[str]) -> bool:
    for dom in dominios_permitidos:
        d = dom.lower().strip()
        if host == d or host.endswith(f".{d}"):
            return True
    return False


def _evaluar_suplantacion_bolivia(url: str) -> dict[str, Any]:
    """Evalúa patrones de suplantación de entidades bolivianas y fraude QR/quishing."""
    ctx = _load_contexto_bolivia().get("deteccion_suplantacion_bolivia", {})
    entidades_gob = ctx.get("entidades_gobierno_requieren_gob_bo", [])
    entidades_fin = ctx.get("entidades_finanzas_telecom", [])
    dominios_ok = ctx.get("dominios_oficiales_permitidos", [])
    senuelos = ctx.get("palabras_senuelo_fraude", [])

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower().strip()
    full_lower = f"{host}{parsed.path.lower()}{'?' + parsed.query.lower() if parsed.query else ''}"

    if not host:
        return {
            "suplantacion_bolivia": False,
            "entidad_suplantada": None,
            "alerta_bolivia": None,
        }

    # 1. Entidades estatales bolivianas fuera de .gob.bo
    es_gob_bo = host.endswith(".gob.bo") or host == "gob.bo"
    if not es_gob_bo and not _es_dominio_oficial(host, dominios_ok):
        for ent in entidades_gob:
            if _token_en_texto(ent, host):
                return {
                    "suplantacion_bolivia": True,
                    "entidad_suplantada": ent,
                    "alerta_bolivia": (
                        f"Posible suplantación de entidad pública boliviana ('{ent}') "
                        f"en dominio no oficial '{host}' (los portales oficiales usan .gob.bo)."
                    ),
                }

    # 2. Bancos, telecomunicaciones o pagos QR bolivianos en dominios no oficiales con señuelos
    if not es_gob_bo and not _es_dominio_oficial(host, dominios_ok):
        for ent in entidades_fin:
            if _token_en_texto(ent, host):
                senuelos_detectados = [s for s in senuelos if _token_en_texto(s, full_lower)]
                if senuelos_detectados or not host.endswith(".bo"):
                    detalle = (
                        f" con señuelos {senuelos_detectados[:3]}" if senuelos_detectados else ""
                    )
                    return {
                        "suplantacion_bolivia": True,
                        "entidad_suplantada": ent,
                        "alerta_bolivia": (
                            f"Posible phishing/quishing suplantando '{ent}' en dominio no oficial "
                            f"'{host}'{detalle}. Verificar en canales oficiales de ASFI/ATT."
                        ),
                    }

    return {
        "suplantacion_bolivia": False,
        "entidad_suplantada": None,
        "alerta_bolivia": None,
    }


def tool_analizar_url_phishing(url: str) -> dict[str, Any]:
    """Analiza una URL sospechosa combinando URLhaus, modelo ML PhiUSIIL y heurística Bolivia/QR."""
    u_clean = url.strip()
    urlhaus = _load_urlhaus_index()
    threat = urlhaus.get(u_clean.lower())
    en_urlhaus = threat is not None

    pipeline = _load_phishing_pipeline()
    feats = extract_url_features(u_clean)
    df_row = pd.DataFrame([feats], columns=URL_FEATURE_COLUMNS)
    pred = int(pipeline.predict(df_row)[0])
    prob_phish = float(pipeline.predict_proba(df_row)[0][1])

    bolivia_check = _evaluar_suplantacion_bolivia(u_clean)
    suplantacion_bo = bool(bolivia_check["suplantacion_bolivia"])

    etiqueta_ml = "phishing" if pred == 1 else "legitima"
    veredicto = "peligrosa" if (en_urlhaus or pred == 1 or suplantacion_bo) else "segura"

    return {
        "url": u_clean,
        "en_urlhaus": en_urlhaus,
        "amenaza_urlhaus": threat,
        "etiqueta_ml": etiqueta_ml,
        "probabilidad_phishing": round(prob_phish, 4),
        "suplantacion_bolivia": suplantacion_bo,
        "entidad_suplantada": bolivia_check["entidad_suplantada"],
        "alerta_bolivia": bolivia_check["alerta_bolivia"],
        "veredicto": veredicto,
    }


def tool_contexto_oficial_bolivia(
    tipos_alerta: list[str] | None = None,
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Devuelve canales oficiales de reporte en Bolivia, TCO BCB vigente y resumen INE-MYPES La Paz."""
    ctx = _load_contexto_bolivia()
    canales_dict = ctx.get("canales_oficiales_reporte", {})
    objetivos = set(tipos_alerta or ["general"])

    seleccionados: list[dict[str, str]] = []
    for _, canal in canales_dict.items():
        ambitos = set(canal.get("ambito", []))
        if ambitos & objetivos or "general" in objetivos:
            seleccionados.append(
                {
                    "entidad": canal["entidad"],
                    "url_portal": canal["url_portal"],
                    "contacto": canal["contacto"],
                    "descripcion": canal["descripcion"],
                }
            )

    tc_info = obtener_tipo_cambio_oficial_bcb()
    tc_val = get_tipo_cambio_bob(tipo_cambio_bob)
    ine_mypes = _load_ine_mypes_lapaz()

    res: dict[str, Any] = {
        "region": ctx.get("metadata", {}).get("region", "La Paz, Bolivia"),
        "tipo_cambio_referencial_bob": tc_val,
        "tipo_cambio_fuente": (
            "Parámetro manual" if tipo_cambio_bob is not None else tc_info["fuente"]
        ),
        "tipo_cambio_fecha": tc_info.get("fecha", ""),
        "canales_reporte": seleccionados,
    }
    if ine_mypes:
        res["ine_mypes_lapaz"] = {
            "fuente": ine_mypes["fuente"],
            "total_empresas": ine_mypes["total_empresas"],
            "total_personal_ocupado": ine_mypes["total_personal_ocupado"],
            "sector_principal": ine_mypes["sector_principal"],
        }
    return res


def tool_consultar_vulnerabilidades(
    tecnologias: list[str],
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Consulta CVEs reales en data/cve_cache.json filtrados por tecnología, CISA KEV y AGETIC CSIRT."""
    if not CVE_CACHE_PATH.exists():
        raise FileNotFoundError(
            f"Caché de CVEs no encontrada en {CVE_CACHE_PATH}. Ejecute src/build_data.py."
        )

    with CVE_CACHE_PATH.open("r", encoding="utf-8") as f:
        cache: list[dict[str, Any]] = json.load(f)

    kev_set = _load_cisa_kev()
    agetic_set = _load_agetic_csirt_cves()
    tc_bob = get_tipo_cambio_bob(tipo_cambio_bob)
    normalized = [_normalize_tech(t) for t in tecnologias if str(t).strip()]
    target_set = set(normalized)

    matched: list[dict[str, Any]] = []
    for item in cache:
        if item.get("tecnologia") in target_set:
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
        efficiencies = risks[active] / (costs[active] + hours[active] + 0.1)
        worst_idx = active[int(np.argmin(efficiencies))]
        repaired[worst_idx] = 0
    return repaired


def tool_optimizar_mitigacion_ag(
    vulnerabilidades: list[dict[str, Any]],
    presupuesto_max_usd: float,
    horas_max: float,
    seed: int = 42,
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Optimiza la selección de controles de mitigación mediante Algoritmo Genético."""
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
        key=lambda x: float(x.get("riesgo_ponderado", float(x["cvss"]) * float(x["epss"]))),
        reverse=True,
    )

    riesgo_mitigado = float(np.dot(best_chrom, risks))
    riesgo_residual = max(0.0, total_initial_risk - riesgo_mitigado)
    riesgo_reducido_pct = (
        (riesgo_mitigado / total_initial_risk) * 100.0
        if total_initial_risk > 0
        else 0.0
    )
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
