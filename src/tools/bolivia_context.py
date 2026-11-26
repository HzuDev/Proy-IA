"""Herramienta de contexto oficial boliviano, estadísticas INE-MYPES y TCO BCB en vivo."""

from __future__ import annotations

from functools import lru_cache
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import time
from typing import Any

import requests

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
INE_MYPES_XLS_PATH = DATA_DIR / "INE-MYPES_DEPTO.xls"
CONTEXTO_BOLIVIA_PATH = DATA_DIR / "contexto_bolivia_lapaz.json"

TIPO_CAMBIO_BOB = 11.83
_TC_CACHE_TTL_SEG = 3600.0
_tc_api_cache: dict[str, Any] = {"ts": 0.0, "data": None}


class _SimpleHTMLTableParser(HTMLParser):
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
            self._current_row.append(" ".join("".join(self._current_cell).split()))
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
        if len(row) != 6 or "actividad economica" in row[0].lower():
            continue
        empresas = _parse_int_es(row[5])
        if empresas > 0:
            sectores.append(
                {
                    "actividad_economica": _fix_mojibake(row[0]).strip(),
                    "valor_bruto_produccion": _parse_int_es(row[1]),
                    "consumo_intermedio": _parse_int_es(row[2]),
                    "valor_agregado": _parse_int_es(row[3]),
                    "personal_ocupado": _parse_int_es(row[4]),
                    "numero_empresas": empresas,
                }
            )

    if not sectores:
        return None

    sectores.sort(key=lambda x: x["numero_empresas"], reverse=True)
    return {
        "departamento": "La Paz",
        "fuente": fuente,
        "archivo": INE_MYPES_XLS_PATH.name,
        "total_empresas": sum(s["numero_empresas"] for s in sectores),
        "total_personal_ocupado": sum(s["personal_ocupado"] for s in sectores),
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
    """Consulta APIs públicas del Tipo de Cambio Oficial (TCO) del BCB con caché y respaldo local."""
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
    """Resuelve el TCO BCB (Bs/USD): override manual -> env TIPO_CAMBIO_BOB -> API -> respaldo JSON."""
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


def tool_contexto_oficial_bolivia(
    tipos_alerta: list[str] | None = None,
    tipo_cambio_bob: float | None = None,
) -> dict[str, Any]:
    """Tool de contexto regional: canales oficiales CGII/AGETIC, ATT, ASFI, TCO BCB e INE-MYPES."""
    ctx = _load_contexto_bolivia()
    canales_dict = ctx.get("canales_oficiales_reporte", {})
    objetivos = set(tipos_alerta or ["general"])

    seleccionados = [
        {
            "entidad": canal["entidad"],
            "url_portal": canal["url_portal"],
            "contacto": canal["contacto"],
            "descripcion": canal["descripcion"],
        }
        for canal in canales_dict.values()
        if set(canal.get("ambito", [])) & objetivos or "general" in objetivos
    ]

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
