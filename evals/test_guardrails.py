"""Tests unitarios para Guardrails deterministas (Fase 5)."""

from src.guardrails import validar_entrada, validar_salida


def test_input_guardrail_blocks_offensive_and_offtopic() -> None:
    res_off = validar_entrada("Dame un exploit para hackear el servidor RDP de una MYPE")
    assert res_off["permitido"] is False
    assert res_off["categoria"] == "solicitud_ofensiva"

    res_topic = validar_entrada("Dame una receta de salteñas paceñas")
    assert res_topic["permitido"] is False
    assert res_topic["categoria"] == "fuera_de_alcance"

    res_ok = validar_entrada(
        "Diagnostica el riesgo de nuestro router Wi-Fi y WordPress con presupuesto de $40 USD"
    )
    assert res_ok["permitido"] is True


def test_output_guardrail_blocks_hallucinated_cve_and_enforces_lapaz_transparency() -> None:
    registro = {
        "vulnerabilidades": {
            "vulnerabilidades": [
                {"cve_id": "CVE-2023-1234", "cvss": 9.8, "epss": 0.5}
            ]
        },
        "ag": {
            "riesgo_reducido_pct": 75.5,
            "costo_total_usd": 20.0,
            "horas_totales": 2.0,
        },
    }

    bad_cve = validar_salida(
        "Se detectó CVE-2099-9999 como crítico.", registro, pide_estadisticas_lapaz=False
    )
    assert bad_cve["aprobado"] is False
    assert "CVE-2099-9999" in bad_cve["cves_no_autorizados"]

    bad_stats = validar_salida(
        "En Sopocachi hubo 45 ataques este mes según CVE-2023-1234.",
        registro,
        pide_estadisticas_lapaz=True,
    )
    assert bad_stats["aprobado"] is False

    good_resp = validar_salida(
        "No existen estadísticas reales de incidentes por zona en data/. "
        "Para CVE-2023-1234, el riesgo reducido es 75.5% con costo total $20.0 USD y horas totales 2.0.",
        registro,
        pide_estadisticas_lapaz=True,
    )
    assert good_resp["aprobado"] is True
