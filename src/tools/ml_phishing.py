"""Tool híbrida de detección de phishing y quishing (PhiUSIIL + URLhaus + heurística Bolivia)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

import joblib
import pandas as pd

from src.tools.bolivia_context import _load_contexto_bolivia
from src.train_phishing import URL_FEATURE_COLUMNS, extract_url_features

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
PHISHING_MODEL_PATH = BASE_DIR / "models" / "modelo_phishing_url.joblib"
URLHAUS_CSV_PATH = DATA_DIR / "urlhaus_recent.csv"


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
            "id", "dateadded", "url", "url_status", "last_online",
            "threat", "tags", "urlhaus_link", "reporter",
        ],
        usecols=["url", "threat"],
    )
    return {
        str(row["url"]).strip().lower(): str(row.get("threat", "malware_download")).strip()
        for _, row in df.dropna(subset=["url"]).iterrows()
    }


def _token_en_texto(token: str, texto: str) -> bool:
    return bool(re.search(rf"(?:^|[.\-_/]){re.escape(token)}(?:$|[.\-_/])", texto))


def _es_dominio_oficial(host: str, dominios_permitidos: list[str]) -> bool:
    return any(
        host == d or host.endswith(f".{d}")
        for d in (dom.lower().strip() for dom in dominios_permitidos)
    )


def _evaluar_suplantacion_bolivia(url: str) -> dict[str, Any]:
    """Detecta suplantación de entidades bolivianas (.gob.bo, bancos, QR) en dominios no oficiales."""
    ctx = _load_contexto_bolivia().get("deteccion_suplantacion_bolivia", {})
    entidades_gob = ctx.get("entidades_gobierno_requieren_gob_bo", [])
    entidades_fin = ctx.get("entidades_finanzas_telecom", [])
    dominios_ok = ctx.get("dominios_oficiales_permitidos", [])
    senuelos = ctx.get("palabras_senuelo_fraude", [])

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower().strip()
    full_lower = f"{host}{parsed.path.lower()}{'?' + parsed.query.lower() if parsed.query else ''}"

    if not host or host.endswith(".gob.bo") or host == "gob.bo" or _es_dominio_oficial(host, dominios_ok):
        return {"suplantacion_bolivia": False, "entidad_suplantada": None, "alerta_bolivia": None}

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

    for ent in entidades_fin:
        if _token_en_texto(ent, host):
            senuelos_detectados = [s for s in senuelos if _token_en_texto(s, full_lower)]
            if senuelos_detectados or not host.endswith(".bo"):
                detalle = f" con señuelos {senuelos_detectados[:3]}" if senuelos_detectados else ""
                return {
                    "suplantacion_bolivia": True,
                    "entidad_suplantada": ent,
                    "alerta_bolivia": (
                        f"Posible phishing/quishing suplantando '{ent}' en dominio no oficial "
                        f"'{host}'{detalle}. Verificar en canales oficiales de ASFI/ATT."
                    ),
                }

    return {"suplantacion_bolivia": False, "entidad_suplantada": None, "alerta_bolivia": None}


def tool_analizar_url_phishing(url: str) -> dict[str, Any]:
    """Combina inteligencia URLhaus, Random Forest (PhiUSIIL) y heurística anti-suplantación Bolivia."""
    u_clean = url.strip()
    threat = _load_urlhaus_index().get(u_clean.lower())
    en_urlhaus = threat is not None

    pipeline = _load_phishing_pipeline()
    df_row = pd.DataFrame([extract_url_features(u_clean)], columns=URL_FEATURE_COLUMNS)
    pred = int(pipeline.predict(df_row)[0])
    prob_phish = float(pipeline.predict_proba(df_row)[0][1])

    bolivia_check = _evaluar_suplantacion_bolivia(u_clean)
    suplantacion_bo = bool(bolivia_check["suplantacion_bolivia"])
    veredicto = "peligrosa" if (en_urlhaus or pred == 1 or suplantacion_bo) else "segura"

    return {
        "url": u_clean,
        "en_urlhaus": en_urlhaus,
        "amenaza_urlhaus": threat,
        "etiqueta_ml": "phishing" if pred == 1 else "legitima",
        "probabilidad_phishing": round(prob_phish, 4),
        "suplantacion_bolivia": suplantacion_bo,
        "entidad_suplantada": bolivia_check["entidad_suplantada"],
        "alerta_bolivia": bolivia_check["alerta_bolivia"],
        "veredicto": veredicto,
    }
