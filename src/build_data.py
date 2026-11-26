"""CLI para regenerar caché de CVEs (NVD/EPSS) y perfiles de La Paz."""

from __future__ import annotations

from pathlib import Path

from src.data_builders import build_cve_cache, build_perfiles_lapaz

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def check_unsw_files() -> None:
    for name in ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"):
        path = DATA_DIR / name
        print(f"[CHECK] {path}: {'EXISTE' if path.exists() else 'FALTA'}")


if __name__ == "__main__":
    check_unsw_files()
    cves = build_cve_cache()
    perfiles = build_perfiles_lapaz()
    print(f"Resumen: {len(cves)} CVEs en caché, {len(perfiles)} perfiles de La Paz.")
