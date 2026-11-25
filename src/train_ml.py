"""Fase 3: Entrenamiento y evaluación del modelo de detección de intrusiones (UNSW-NB15)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

TRAIN_CSV = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = DATA_DIR / "UNSW_NB15_testing-set.csv"
MODEL_PATH = MODELS_DIR / "modelo_red_unsw.joblib"
METRICS_PATH = MODELS_DIR / "ml_metrics.json"

NUMERIC_FEATURES = [
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
]

CATEGORICAL_FEATURES = ["proto", "service", "state"]
ALL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def _load_dataset(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="utf-8-sig")
    df.columns = [c.strip() for c in df.columns]
    return df


def train_and_evaluate() -> dict[str, Any]:
    if not TRAIN_CSV.exists() or not TEST_CSV.exists():
        missing = [str(p) for p in (TRAIN_CSV, TEST_CSV) if not p.exists()]
        raise FileNotFoundError(
            f"Faltan archivos UNSW-NB15 requeridos para entrenar: {', '.join(missing)}"
        )

    df_train = _load_dataset(TRAIN_CSV)
    df_test = _load_dataset(TEST_CSV)

    X_train_full = df_train[ALL_FEATURES].copy()
    y_train_full = df_train["label"].astype(int).values

    if len(X_train_full) > 30_000:
        X_train, _, y_train, _ = train_test_split(
            X_train_full,
            y_train_full,
            train_size=30_000,
            stratify=y_train_full,
            random_state=42,
        )
    else:
        X_train, y_train = X_train_full, y_train_full

    X_test = df_test[ALL_FEATURES].copy()
    y_test = df_test["label"].astype(int).values

    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=22,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", clf),
        ]
    )

    print(f"Entrenando RandomForestClassifier con {len(X_train)} filas estratificadas...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "feature_columns": ALL_FEATURES,
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    with METRICS_PATH.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    print("Métricas reales sobre test set:")
    print(json.dumps(metrics, indent=2))
    return metrics


def verify_inference_sample() -> None:
    """Prueba de inferencia con 2 filas reales del test set."""
    pipeline = joblib.load(MODEL_PATH)
    df_test = _load_dataset(TEST_CSV)
    sample = df_test[ALL_FEATURES].head(2)
    preds = pipeline.predict(sample)
    probs = pipeline.predict_proba(sample)[:, 1]
    for idx, (pred, prob) in enumerate(zip(preds, probs)):
        label = "ataque" if int(pred) == 1 else "normal"
        print(f"Fila test #{idx}: predicción={label}, probabilidad_ataque={prob:.4f}")


if __name__ == "__main__":
    train_and_evaluate()
    verify_inference_sample()
