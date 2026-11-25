"""Fase 6: Interfaz Web Streamlit para Diagnóstico Preventivo 24/7 en La Paz."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.agent import ejecutar_diagnostico

BASE_DIR = Path(__file__).resolve().parent
PERFILES_PATH = BASE_DIR / "data" / "perfiles_lapaz.json"

st.set_page_config(
    page_title="Diagnóstico Preventivo Ciberseguridad - La Paz",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sistema Multi-Agente de Ciberseguridad Preventiva 24/7 — La Paz")
st.caption(
    "Centros Comunitarios, Unidades Educativas y MYPES | ML (UNSW-NB15) + NVD/EPSS + Algoritmo Genético + Guardrails"
)

perfiles = []
if PERFILES_PATH.exists():
    with PERFILES_PATH.open("r", encoding="utf-8") as f:
        perfiles = json.load(f)

perfil_map = {f"{p['id']} — {p['nombre']} ({p['tipo']})": p for p in perfiles}

with st.sidebar:
    st.header("Configuración del Diagnóstico")
    opciones = ["(Consulta libre sin perfil)"] + list(perfil_map.keys())
    seleccion = st.selectbox("Perfil de La Paz:", opciones)
    perfil_sel = perfil_map.get(seleccion)

    if perfil_sel:
        st.json(
            {
                "macrodistrito": perfil_sel["macrodistrito"],
                "tecnologias": perfil_sel["tecnologias"],
                "presupuesto_usd": perfil_sel["presupuesto_disponible_usd"],
                "horas_disponibles": perfil_sel["horas_tecnicas_disponibles"],
            }
        )

default_query = (
    f"Realiza un diagnóstico preventivo y plan de mitigación priorizado para {perfil_sel['nombre']} "
    f"considerando sus tecnologías {', '.join(perfil_sel['tecnologias'])}."
    if perfil_sel
    else "Diagnostica vulnerabilidades para router Wi-Fi y WordPress con $40 USD y 4 horas."
)

query = st.text_area("Consulta de diagnóstico:", value=default_query, height=100)
url_sospechosa = st.text_input(
    "URL sospechosa a verificar (opcional — PhiUSIIL + URLhaus):",
    placeholder="https://ejemplo-sospechoso.com/login",
)

if st.button("Ejecutar Diagnóstico Multi-Agente", type="primary"):
    with st.spinner("Ejecutando Planificador, Tools, Algoritmo Genético y Guardrails..."):
        try:
            res = ejecutar_diagnostico(
                query=query,
                perfil_id=perfil_sel["id"] if perfil_sel else None,
                url_sospechosa=url_sospechosa.strip() or None,
            )
        except Exception as exc:
            st.error(f"Error al ejecutar diagnóstico: {exc}")
            st.stop()

    col1, col2, col3 = st.columns(3)
    col1.metric("Estado Guardrail", res["estado_guardrail"])
    col2.metric("Latencia", f"{res['latencia_seg']} s")

    ag = res.get("registro_tools", {}).get("algoritmo_genetico", {})
    col3.metric(
        "Reducción de Riesgo (AG)",
        f"{ag.get('riesgo_reducido_pct', 0.0)} %",
    )

    st.subheader("📋 Diagnóstico y Plan Priorizado")
    if res["bloqueado"]:
        st.warning(res["respuesta"])
    else:
        st.markdown(res["respuesta"])

    if ag:
        st.subheader("🧬 Optimización por Algoritmo Genético")
        c1, c2, c3 = st.columns(3)
        c1.metric("Riesgo Inicial", ag.get("riesgo_inicial", 0.0))
        c2.metric("Costo Total", f"${ag.get('costo_total_usd', 0.0)} USD")
        c3.metric("Horas Totales", f"{ag.get('horas_totales', 0.0)} h")

        controles = ag.get("controles_seleccionados", [])
        if controles:
            st.dataframe(pd.DataFrame(controles), use_container_width=True)

    with st.expander("🔧 Registro de Tools Ejecutadas y Validación"):
        st.write("Tools ejecutadas:", res.get("registro_tools", {}).get("tools_ejecutadas", []))
        st.json(res.get("validacion_salida", {}))
