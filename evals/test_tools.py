"""Tests unitarios para Fase 4: Algoritmo Genético, CVEs, contexto Bolivia, API BCB y phishing/URLhaus."""

import numpy as np

from src.tools import (
    _load_ine_mypes_lapaz,
    get_tipo_cambio_bob,
    obtener_tipo_cambio_oficial_bcb,
    tool_analizar_url_phishing,
    tool_consultar_vulnerabilidades,
    tool_contexto_oficial_bolivia,
    tool_optimizar_mitigacion_ag,
)


def _random_feasible_baseline(
    vulns: list[dict], max_cost: float, max_hours: float, trials: int = 30
) -> float:
    rng = np.random.default_rng(123)
    best_pct = 0.0
    total_risk = sum(v["cvss"] * v["epss"] for v in vulns)
    if total_risk == 0:
        return 0.0

    for _ in range(trials):
        order = rng.permutation(len(vulns))
        cost = 0.0
        hours = 0.0
        mitigated = 0.0
        for idx in order:
            v = vulns[idx]
            if (
                cost + v["costo_remediacion_usd"] <= max_cost
                and hours + v["horas_remediacion"] <= max_hours
            ):
                cost += v["costo_remediacion_usd"]
                hours += v["horas_remediacion"]
                mitigated += v["cvss"] * v["epss"]
        best_pct = max(best_pct, (mitigated / total_risk) * 100.0)
    return best_pct


def test_ag_respects_budget_and_hours_and_beats_random() -> None:
    tc_bob = get_tipo_cambio_bob()
    assert tc_bob > 10.0  # Tipo de cambio oficial BCB vigente (ya no 6.96 fijo)

    consulta = tool_consultar_vulnerabilidades(
        ["router_wifi", "wordpress", "servidor_web", "smb", "rdp"]
    )
    vulns = consulta["vulnerabilidades"]
    assert len(vulns) >= 10
    assert "en_agetic_csirt" in vulns[0]
    assert "costo_remediacion_bob" in vulns[0]

    presupuesto_max = 45.0
    horas_max = 5.5

    res_ag = tool_optimizar_mitigacion_ag(vulns, presupuesto_max, horas_max)

    assert res_ag["costo_total_usd"] <= presupuesto_max + 1e-6
    assert res_ag["costo_total_bob"] == round(res_ag["costo_total_usd"] * tc_bob, 2)
    assert res_ag["presupuesto_max_bob"] == round(presupuesto_max * tc_bob, 2)
    assert res_ag["horas_totales"] <= horas_max + 1e-6
    assert res_ag["riesgo_reducido_pct"] > 0.0

    # Validar sobrescritura dinámica del tipo de cambio diario BCB
    res_ag_custom = tool_optimizar_mitigacion_ag(
        vulns, presupuesto_max, horas_max, tipo_cambio_bob=12.10
    )
    assert res_ag_custom["tipo_cambio_bob"] == 12.10
    assert res_ag_custom["presupuesto_max_bob"] == round(presupuesto_max * 12.10, 2)

    # El AG debe igualar o superar una selección aleatoria factible promedio
    rng = np.random.default_rng(99)
    total_risk = sum(v["cvss"] * v["epss"] for v in vulns)
    random_pcts = []
    for _ in range(50):
        order = rng.permutation(len(vulns))
        c, h, m = 0.0, 0.0, 0.0
        for idx in order:
            v = vulns[idx]
            if (
                c + v["costo_remediacion_usd"] <= presupuesto_max
                and h + v["horas_remediacion"] <= horas_max
            ):
                c += v["costo_remediacion_usd"]
                h += v["horas_remediacion"]
                m += v["cvss"] * v["epss"]
        random_pcts.append((m / total_risk) * 100.0)

    avg_random = float(np.mean(random_pcts))
    assert res_ag["riesgo_reducido_pct"] >= avg_random


def test_phishing_and_urlhaus_tool() -> None:
    mal = tool_analizar_url_phishing("http://115.230.67.252:50864/bin.sh")
    assert mal["en_urlhaus"] is True
    assert mal["veredicto"] == "peligrosa"

    legit = tool_analizar_url_phishing("https://www.agetic.gob.bo")
    assert legit["en_urlhaus"] is False
    assert legit["suplantacion_bolivia"] is False
    assert legit["etiqueta_ml"] == "legitima"
    assert legit["veredicto"] == "segura"


def test_suplantacion_bolivia_y_quishing() -> None:
    # Caso real reportado por ASFI: entidad pública boliviana fuera de .gob.bo
    fake_asfi = tool_analizar_url_phishing("https://asfi-renta.com/login")
    assert fake_asfi["suplantacion_bolivia"] is True
    assert fake_asfi["entidad_suplantada"] == "asfi"
    assert fake_asfi["veredicto"] == "peligrosa"

    # Suplantación de banco / pago QR en dominio no oficial
    fake_qr = tool_analizar_url_phishing("https://bancounion-pago-qr.xyz/verificar")
    assert fake_qr["suplantacion_bolivia"] is True
    assert fake_qr["veredicto"] == "peligrosa"

    # Dominio oficial bancario boliviano no debe marcar suplantación
    real_bank = tool_analizar_url_phishing("https://www.bancounion.com.bo")
    assert real_bank["suplantacion_bolivia"] is False


def test_contexto_oficial_bolivia_y_bcb_api() -> None:
    tc = obtener_tipo_cambio_oficial_bcb()
    assert 1.0 < tc["valor_bob"] < 100.0
    assert tc["fuente"]

    ctx_qr = tool_contexto_oficial_bolivia(["phishing_qr"])
    entidades = [c["entidad"] for c in ctx_qr["canales_reporte"]]
    assert any("CGII" in e for e in entidades)
    assert any("ATT" in e for e in entidades)
    assert any("ASFI" in e for e in entidades)

    ine = _load_ine_mypes_lapaz()
    if ine is not None:
        assert ine["total_empresas"] == 11743
        assert "Textiles" in ine["sector_principal"]
