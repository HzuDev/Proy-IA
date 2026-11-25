"""Entrenamiento y evaluación del detector de URLs de phishing (PhiUSIIL)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

PHISHING_CSV = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
PHISHING_MODEL_PATH = MODELS_DIR / "modelo_phishing_url.joblib"
PHISHING_METRICS_PATH = MODELS_DIR / "phishing_metrics.json"

SUSPICIOUS_WORDS = (
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "signin",
    "confirm",
    "webscr",
    "paypal",
    "token",
    "auth",
    "wallet",
)

IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def extract_url_features(url: str) -> dict[str, float]:
    """Extrae características léxicas deterministas directamente de una URL."""
    u = str(url).strip()
    if not u.startswith(("http://", "https://")):
        u_parsed = urlparse("http://" + u)
    else:
        u_parsed = urlparse(u)

    host = (u_parsed.hostname or "").lower()
    path_and_query = (u_parsed.path or "") + ("?" + u_parsed.query if u_parsed.query else "")
    url_len = max(len(u), 1)
    domain_len = len(host)

    letters = sum(c.isalpha() for c in u)
    digits = sum(c.isdigit() for c in u)
    equals = u.count("=")
    qmarks = u.count("?")
    ampersands = u.count("&")
    hyphens = u.count("-")
    at_signs = u.count("@")
    dots = host.count(".")
    slashes = path_and_query.count("/")
    specials = sum(not c.isalnum() for c in u)

    parts = [p for p in host.split(".") if p]
    subdomains = max(len(parts) - 2, 0) if len(parts) > 2 else 0
    tld_len = len(parts[-1]) if parts else 0

    is_https = 1.0 if u.lower().startswith("https://") else 0.0
    is_ip = 1.0 if IP_REGEX.match(host) else 0.0
    has_obfuscation = 1.0 if ("%" in u or "@" in u) else 0.0
    suspicious_kw_count = sum(1 for kw in SUSPICIOUS_WORDS if kw in u.lower())

    return {
        "url_length": float(url_len),
        "domain_length": float(domain_len),
        "is_https": is_https,
        "is_ip": is_ip,
        "tld_length": float(tld_len),
        "num_subdomains": float(subdomains),
        "num_dots_host": float(dots),
        "num_slashes_path": float(slashes),
        "num_hyphens": float(hyphens),
        "num_at": float(at_signs),
        "num_qmark": float(qmarks),
        "num_equals": float(equals),
        "num_ampersand": float(ampersands),
        "num_letters": float(letters),
        "letter_ratio": float(letters / url_len),
        "num_digits": float(digits),
        "digit_ratio": float(digits / url_len),
        "special_ratio": float(specials / url_len),
        "has_obfuscation": has_obfuscation,
        "suspicious_kw_count": float(suspicious_kw_count),
    }


URL_FEATURE_COLUMNS = list(extract_url_features("https://example.com").keys())


def train_and_evaluate() -> dict[str, Any]:
    if not PHISHING_CSV.exists():
        raise FileNotFoundError(f"No se encontró {PHISHING_CSV}")

    df = pd.read_csv(PHISHING_CSV, encoding="utf-8-sig", usecols=["URL", "label"])
    df = df.dropna(subset=["URL", "label"]).copy()

    # En PhiUSIIL: label=1 es legítima, label=0 es phishing -> invertimos a 1=phishing, 0=legítima
    df["is_phishing"] = (1 - df["label"].astype(int)).clip(0, 1)

    if len(df) > 40_000:
        df_sample, _ = train_test_split(
            df,
            train_size=40_000,
            stratify=df["is_phishing"],
            random_state=42,
        )
    else:
        df_sample = df

    feat_rows = [extract_url_features(u) for u in df_sample["URL"].tolist()]
    X = pd.DataFrame(feat_rows, columns=URL_FEATURE_COLUMNS)
    y = df_sample["is_phishing"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    max_depth=22,
                    min_samples_split=4,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    print(f"Entrenando detector de phishing con {len(X_train)} URLs...")
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
        "feature_columns": URL_FEATURE_COLUMNS,
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, PHISHING_MODEL_PATH)
    with PHISHING_METRICS_PATH.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    print("Métricas reales de phishing (PhiUSIIL test split):")
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
