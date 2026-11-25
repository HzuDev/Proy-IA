"""Fase 6: Interfaz Web Streamlit para Diagnóstico Preventivo 24/7 en La Paz."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.agent import ejecutar_diagnostico
from src.llm_provider import PROVIDER_CATALOG, detect_configured_providers
from src.tools import get_tipo_cambio_bob, obtener_tipo_cambio_oficial_bcb

BASE_DIR = Path(__file__).resolve().parent
PERFILES_PATH = BASE_DIR / "data" / "perfiles_lapaz.json"

st.set_page_config(
    page_title="Diagnóstico Preventivo Ciberseguridad - La Paz",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sistema Multi-Agente de Ciberseguridad Preventiva 24/7 — La Paz")
st.caption(
    "Ciudad y Departamento de La Paz (Centros Comunitarios, Unidades Educativas y MYPES) | "
    "ML (UNSW-NB15 + PhiUSIIL) + NVD/EPSS/KEV/AGETIC + Algoritmo Genético + Guardrails"
)

perfiles = []
if PERFILES_PATH.exists():
    with PERFILES_PATH.open("r", encoding="utf-8") as f:
        perfiles = json.load(f)

perfil_map = {
    f"{p['id']} — {p['nombre']} ({p.get('municipio', 'La Paz')} · {p['tipo']})": p
    for p in perfiles
}

tc_info = obtener_tipo_cambio_oficial_bcb()
providers_status = detect_configured_providers()
configured_labels = [p["label"] for p in providers_status if p["configured"]]

with st.sidebar:
    st.header("Configuración del Diagnóstico")

    with st.expander("🤖 Modelo de IA (Multi-Proveedor)", expanded=False):
        provider_options = ["auto"] + list(PROVIDER_CATALOG.keys())
        provider_labels = {
            "auto": "Auto (detectar desde .env o API key)",
            **{k: v["label"] for k, v in PROVIDER_CATALOG.items()},
        }
        llm_provider = st.selectbox(
            "Proveedor IA:",
            options=provider_options,
            format_func=lambda x: provider_labels.get(x, x),
        )
        default_model_hint = (
            PROVIDER_CATALOG[llm_provider]["default_model"]
            if llm_provider in PROVIDER_CATALOG
            else ""
        )
        suggested = (
            PROVIDER_CATALOG[llm_provider]["suggested_models"]
            if llm_provider in PROVIDER_CATALOG
            else []
        )
        help_models = (
            f"Sugeridos: {', '.join(suggested)}"
            if suggested
            else "Escribe el ID exacto de cualquier modelo."
        )
        llm_model = st.text_input(
            "Modelo (cualquier ID compatible):",
            value=default_model_hint,
            placeholder="ej. gpt-4o-mini, gemini-2.5-flash, claude-sonnet-4-5, deepseek-chat",
            help=help_models,
        )
        llm_api_key = st.text_input(
            "API Key (opcional — usa .env si está vacío):",
            type="password",
            placeholder="AIza... / sk-... / sk-ant-... / opencode...",
        )
        llm_base_url = ""
        if llm_provider in ("custom", "ollama", "opencode", "auto"):
            default_url = (
                PROVIDER_CATALOG[llm_provider]["base_url"]
                if llm_provider in PROVIDER_CATALOG
                else ""
            )
            llm_base_url = st.text_input(
                "Base URL (solo si usas endpoint propio):",
                value=default_url if llm_provider in ("custom", "ollama") else "",
                placeholder="https://tu-endpoint.com/v1",
            )
        if configured_labels:
            st.caption(f"Detectados en `.env`: {', '.join(configured_labels)}")
        else:
            st.caption("Sin API keys detectadas en `.env`: ingresa una arriba.")

    tipo_cambio_bob = st.number_input(
        "Tipo de cambio oficial BCB (Bs / USD):",
        min_value=1.0,
        max_value=50.0,
        value=float(get_tipo_cambio_bob()),
        step=0.01,
        format="%.2f",
        help=f"Fuente automática: {tc_info['fuente']} (fecha {tc_info.get('fecha', 'N/A')}).",
    )
    st.caption(
        f"Fuente TC: {tc_info['fuente']} · Fecha: {tc_info.get('fecha') or 'N/A'}"
    )
    opciones = ["(Consulta libre sin perfil)"] + list(perfil_map.keys())
    seleccion = st.selectbox("Perfil de La Paz:", opciones)
    perfil_sel = perfil_map.get(seleccion)

    if perfil_sel:
        presupuesto_bob_calc = round(
            float(perfil_sel["presupuesto_disponible_usd"]) * tipo_cambio_bob, 2
        )
        st.json(
            {
                "municipio": perfil_sel.get("municipio", "La Paz"),
                "macrodistrito": perfil_sel["macrodistrito"],
                "isp_tipico": perfil_sel.get("isp_tipico", "N/A"),
                "usa_pagos_qr": perfil_sel.get("usa_pagos_qr", False),
                "tecnologias": perfil_sel["tecnologias"],
                "presupuesto_usd": perfil_sel["presupuesto_disponible_usd"],
                "presupuesto_bob": presupuesto_bob_calc,
                "horas_disponibles": perfil_sel["horas_tecnicas_disponibles"],
            }
        )

default_query = (
    f"Realiza un diagnóstico preventivo y plan de mitigación priorizado para {perfil_sel['nombre']} "
    f"({perfil_sel.get('municipio', 'La Paz')}) considerando sus tecnologías {', '.join(perfil_sel['tecnologias'])}."
    if perfil_sel
    else f"Diagnostica vulnerabilidades para router Wi-Fi y WordPress con Bs {round(40 * tipo_cambio_bob)} ($40 USD) y 4 horas."
)

query = st.text_area("Consulta de diagnóstico:", value=default_query, height=100)
url_sospechosa = st.text_input(
    "URL sospechosa / enlace QR a verificar (opcional — PhiUSIIL + URLhaus + Heurística Bolivia):",
    placeholder="https://asfi-renta.com/login",
)

if st.button("Ejecutar Diagnóstico Multi-Agente", type="primary"):
    with st.spinner("Ejecutando Planificador, Tools, Algoritmo Genético y Guardrails..."):
        try:
            res = ejecutar_diagnostico(
                query=query,
                perfil_id=perfil_sel["id"] if perfil_sel else None,
                url_sospechosa=url_sospechosa.strip() or None,
                tipo_cambio_bob=float(tipo_cambio_bob),
                llm_provider=llm_provider,
                llm_model=llm_model.strip() or None,
                llm_api_key=llm_api_key.strip() or None,
                llm_base_url=llm_base_url.strip() or None,
            )
        except Exception as exc:
            st.error(f"Error al ejecutar diagnóstico: {exc}")
            st.stop()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Estado Guardrail", res["estado_guardrail"])
    col2.metric("Latencia", f"{res['latencia_seg']} s")

    ag = res.get("registro_tools", {}).get("algoritmo_genetico", {})
    col3.metric(
        "Reducción de Riesgo (AG)",
        f"{ag.get('riesgo_reducido_pct', 0.0)} %",
    )
    llm_info = res.get("llm_info") or {}
    col4.metric(
        "Modelo IA",
        llm_info.get("model", "N/A"),
        help=f"Proveedor: {llm_info.get('provider_label', 'N/A')}",
    )

    st.subheader("📋 Diagnóstico y Plan Priorizado")
    if res["bloqueado"]:
        st.warning(res["respuesta"])
    else:
        st.markdown(res["respuesta"])

    phish = res.get("registro_tools", {}).get("phishing_url")
    if phish and not phish.get("error"):
        st.subheader("🔍 Verificación de URL / Phishing y Quishing Bolivia")
        if phish.get("veredicto") == "peligrosa":
            st.error(
                f"URL PELIGROSA: {phish['url']} | Prob. ML: {phish['probabilidad_phishing']} | "
                f"URLhaus: {phish['en_urlhaus']} | Suplantación Bolivia: {phish.get('suplantacion_bolivia', False)}"
            )
            if phish.get("alerta_bolivia"):
                st.warning(phish["alerta_bolivia"])
        else:
            st.success(
                f"URL sin señales de phishing/suplantación: {phish['url']} "
                f"(Prob. ML: {phish['probabilidad_phishing']})"
            )

    if ag:
        st.subheader("🧬 Optimización por Algoritmo Genético")
        c1, c2, c3 = st.columns(3)
        c1.metric("Riesgo Inicial", ag.get("riesgo_inicial", 0.0))
        c2.metric(
            "Costo Total",
            f"${ag.get('costo_total_usd', 0.0)} USD / Bs {ag.get('costo_total_bob', 0.0)}",
            help=f"Calculado a TC oficial BCB Bs {ag.get('tipo_cambio_bob', tipo_cambio_bob)} por USD.",
        )
        c3.metric("Horas Totales", f"{ag.get('horas_totales', 0.0)} h")

        controles = ag.get("controles_seleccionados", [])
        if controles:
            st.dataframe(pd.DataFrame(controles), width="stretch")

    canales = (
        res.get("registro_tools", {})
        .get("canales_oficiales_bolivia", {})
        .get("canales_reporte", [])
    )
    if canales:
        st.subheader("🇧🇴 Canales Oficiales de Reporte en Bolivia")
        for ch in canales:
            st.markdown(
                f"- **{ch['entidad']}** — [{ch['url_portal']}]({ch['url_portal']}) | `{ch['contacto']}`"
            )

    with st.expander("🔧 Registro de Tools Ejecutadas y Validación"):
        if llm_info:
            st.write("LLM utilizado:", llm_info)
        st.write("Tools ejecutadas:", res.get("registro_tools", {}).get("tools_ejecutadas", []))
        st.json(res.get("validacion_salida", {}))
