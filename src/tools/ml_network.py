"""Tool de clasificación supervisada de tráfico de red (Random Forest sobre UNSW-NB15)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "models" / "modelo_red_unsw.joblib"

FEATURE_COLUMNS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
    "proto", "service", "state",
]


@lru_cache(maxsize=1)
def _load_ml_pipeline() -> Any:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modelo ML no encontrado en {MODEL_PATH}. Ejecute src/train_ml.py primero."
        )
    return joblib.load(MODEL_PATH)


def tool_clasificar_trafico_ml(features_dict: dict[str, Any]) -> dict[str, Any]:
    """Clasifica un flujo de red mediante el pipeline Random Forest entrenado en UNSW-NB15."""
    pipeline = _load_ml_pipeline()
    row = {col: features_dict.get(col, np.nan) for col in FEATURE_COLUMNS}
    df_row = pd.DataFrame([row], columns=FEATURE_COLUMNS)

    pred = int(pipeline.predict(df_row)[0])
    probs = pipeline.predict_proba(df_row)[0]
    prob_normal, prob_ataque = float(probs[0]), float(probs[1])

    return {
        "etiqueta": "ataque" if pred == 1 else "normal",
        "probabilidad_ataque": round(prob_ataque, 4),
        "probabilidad_normal": round(prob_normal, 4),
        "confianza": round(max(prob_normal, prob_ataque), 4),
    }
