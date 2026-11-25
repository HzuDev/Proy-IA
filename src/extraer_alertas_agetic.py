"""Extractor opcional de alertas públicas del portal AGETIC CSIRT (https://csirt.gob.bo)."""

from __future__ import annotations

from pathlib import Path
import pandas as pd
from playwright.sync_api import sync_playwright

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_CSV = BASE_DIR / "data" / "alertas_agetic_csirt.csv"


def extraer_alertas() -> None:
    url = "https://csirt.gob.bo"
    alertas: list[dict[str, str]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        print(f"Conectando a {url}...")
        page.goto(url, wait_until="networkidle")

        try:
            boton_50 = page.locator("button:has-text('50'), a:has-text('50')").first
            if boton_50.is_visible():
                boton_50.click()
                page.wait_for_timeout(2000)
        except Exception:
            pass

        while True:
            page.wait_for_selector("text=CVSS", timeout=10000)
            enlaces = page.locator("a[href*='/alerts/']").all()

            for enlace in enlaces:
                try:
                    contenedor = enlace.locator("xpath=ancestor::div[contains(., 'CVSS')][1]")
                    texto_completo = contenedor.inner_text()
                    lineas = [l.strip() for l in texto_completo.split("\n") if l.strip()]

                    severidad = lineas[0] if len(lineas) > 0 else "N/A"
                    fecha_tipo = lineas[1] if len(lineas) > 1 else "N/A"
                    cve = lineas[2] if len(lineas) > 2 else "N/A"
                    titulo = enlace.inner_text().strip()
                    link_detalle = f"https://csirt.gob.bo{enlace.get_attribute('href')}"

                    cvss = "N/A"
                    if "CVSS" in lineas:
                        idx = lineas.index("CVSS")
                        if idx + 1 < len(lineas):
                            cvss = lineas[idx + 1]

                    resumen = max(lineas, key=len) if lineas else ""

                    registro = {
                        "Severidad": severidad,
                        "Fecha_y_Tipo": fecha_tipo,
                        "CVE": cve,
                        "Titulo": titulo,
                        "CVSS": cvss,
                        "Resumen": resumen,
                        "URL": link_detalle,
                    }
                    if registro not in alertas:
                        alertas.append(registro)
                except Exception:
                    continue

            siguiente = page.locator(
                "button[aria-label*='Siguiente'], button:has-text('>')"
            ).first
            if siguiente.is_visible() and siguiente.is_enabled():
                siguiente.click()
                page.wait_for_timeout(2000)
            else:
                break

        browser.close()

    if alertas:
        OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(alertas)
        df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
        print(f"Extracción completada: {len(df)} alertas guardadas en '{OUTPUT_CSV}'.")
    else:
        print("No se encontraron alertas. Verifica si la estructura HTML del sitio cambió.")


if __name__ == "__main__":
    extraer_alertas()
