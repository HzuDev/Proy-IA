"""Generador de los 14 perfiles operativos de La Paz, El Alto y Viacha."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
PERFILES_PATH = DATA_DIR / "perfiles_lapaz.json"
TIPO_CAMBIO_BOB = float(os.getenv("TIPO_CAMBIO_BOB", "11.83"))

_RAW_PERFILES: list[tuple[Any, ...]] = [
    ("LPZ-CC-01", "Centro Comunitario Alto Lima", "Centro Comunitario", "La Paz", "Max Paredes", "Entel", False,
     ["Router Wi-Fi TP-Link para telecentro vecinal", "PCs compartidas con carpetas SMB en red local"],
     ["router_wifi", "smb"], 20.0, 4.0,
     "Telecentro comunitario con 12 equipos usados por jóvenes y vecinos."),
    ("LPZ-CC-02", "Casa Cultural Comunitaria Villa Fátima", "Centro Comunitario", "La Paz", "Periférica", "Cotel", True,
     ["Portal informativo en WordPress", "Router Wi-Fi abierto para talleres", "Servidor web Apache de eventos"],
     ["wordpress", "router_wifi", "servidor_web"], 35.0, 5.0,
     "Espacio cultural barrial administrado por voluntarios; recibe aportes e inscripciones por QR."),
    ("LPZ-CC-03", "Centro de Capacitación Digital Cotahuma", "Centro Comunitario", "La Paz", "Cotahuma", "Entel", False,
     ["Laboratorio con acceso remoto RDP para soporte", "Carpetas compartidas SMB", "Router Wi-Fi institucional"],
     ["rdp", "smb", "router_wifi"], 45.0, 6.0,
     "Centro de alfabetización digital para adultos mayores y escolares."),
    ("LPZ-CC-04", "Telecentro Comunitario Municipal Viacha", "Centro Comunitario", "Viacha", "Provincia Ingavi", "Entel", False,
     ["Router MikroTik de acceso comunitario", "PCs compartidas con carpetas SMB", "Portal vecinal en WordPress"],
     ["router_wifi", "smb", "wordpress"], 25.0, 4.5,
     "Telecentro provincial del departamento de La Paz con conectividad limitada y soporte eventual."),
    ("LPZ-UE-01", "Unidad Educativa 6 de Junio - Turno Mañana", "Unidad Educativa", "La Paz", "San Antonio", "Entel", False,
     ["Plataforma escolar en WordPress", "Servidor web Apache en aula de computación", "Router Wi-Fi docente"],
     ["wordpress", "servidor_web", "router_wifi"], 50.0, 6.0,
     "Colegio fiscal con laboratorio de informática y registro de notas local."),
    ("LPZ-UE-02", "Unidad Educativa Técnico Humanístico Sopocachi", "Unidad Educativa", "La Paz", "Cotahuma", "Tigo", True,
     ["Servidor de archivos SMB para material didáctico", "Acceso RDP para administración de aula", "Servidor web interno"],
     ["smb", "rdp", "servidor_web"], 75.0, 8.0,
     "Institución educativa con 25 computadoras en red y soporte técnico eventual."),
    ("LPZ-UE-03", "Unidad Educativa Valle de Mallasa", "Unidad Educativa", "La Paz", "Mallasa", "Entel", False,
     ["Router Wi-Fi de cobertura escolar", "Sitio web institucional en WordPress"],
     ["router_wifi", "wordpress"], 0.0, 3.5,
     "Escuela periurbana con presupuesto cero para licencias; depende de ajustes gratuitos."),
    ("LPZ-UE-04", "Instituto Tecnológico Comunal El Tejar", "Unidad Educativa", "La Paz", "Max Paredes", "AXS", True,
     ["Servidor web Apache para prácticas", "Acceso RDP a máquinas virtuales", "Carpetas SMB compartidas", "Router Wi-Fi de campus"],
     ["servidor_web", "rdp", "smb", "router_wifi"], 90.0, 10.0,
     "Centro de formación técnica con alta rotación de estudiantes en red."),
    ("LPZ-MY-01", "Textiles Artesanales Illimani SRL (MYPE)", "MYPE", "La Paz", "Centro", "Tigo", True,
     ["Tienda catálogo en WordPress", "Router Wi-Fi de oficina y taller"],
     ["wordpress", "router_wifi"], 40.0, 4.0,
     "Microempresa textil exportadora que gestiona pedidos por web, WhatsApp y pagos QR."),
    ("LPZ-MY-02", "Imprenta y Diseño Gráfico Prado (MYPE)", "MYPE", "La Paz", "Centro", "AXS", True,
     ["Servidor de archivos SMB con diseños de clientes", "Acceso RDP desde domicilio del diseñador", "Router Wi-Fi comercial"],
     ["smb", "rdp", "router_wifi"], 65.0, 5.5,
     "MYPE gráfica con cobros por QR y riesgo alto de pérdida de archivos por ransomware."),
    ("LPZ-MY-03", "Café y Tostaduría Altura Sur (MYPE)", "MYPE", "La Paz", "Sur", "Tigo", True,
     ["Router Wi-Fi para clientes y punto de venta", "Sitio WordPress con reservas", "Servidor web de menú digital"],
     ["router_wifi", "wordpress", "servidor_web"], 55.0, 5.0,
     "Negocio gastronómico con Wi-Fi compartido entre invitados, caja y cobros diarios por QR."),
    ("LPZ-MY-04", "Ferretería y Materiales Obrajes (MYPE)", "MYPE", "La Paz", "Sur", "Cotel", True,
     ["PC inventario con carpetas SMB", "Acceso RDP de contador externo"],
     ["smb", "rdp"], 30.0, 3.5,
     "Pequeña ferretería con facturación, cobro por QR e inventario en una PC de escritorio."),
    ("LPZ-MY-05", "Consultora Agrícola y Turística Hampaturi (MYPE)", "MYPE", "La Paz", "Hampaturi", "Entel LTE", True,
     ["Portal WordPress de turismo comunitario", "Servidor web Apache", "Router Wi-Fi satelital/LTE"],
     ["wordpress", "servidor_web", "router_wifi"], 80.0, 7.0,
     "MYPE rural-urbana con conectividad intermitente, reservas en línea y cobros por QR."),
    ("LPZ-MY-06", "Taller Textil y Comercializadora 16 de Julio (MYPE)", "MYPE", "El Alto", "Distrito 6", "Entel", True,
     ["Router Wi-Fi TP-Link de taller y ventas", "PC de pedidos con carpetas compartidas SMB", "Catálogo web en WordPress"],
     ["router_wifi", "smb", "wordpress"], 30.0, 4.0,
     "MYPE manufacturera y comercial en El Alto que opera ventas por redes sociales y pagos QR."),
]


def build_perfiles_lapaz() -> list[dict[str, Any]]:
    """Genera y persiste los 14 perfiles técnicos representativos de La Paz."""
    perfiles: list[dict[str, Any]] = []
    for row in _RAW_PERFILES:
        pid, nombre, tipo, mun, macro, isp, qr, activos, techs, usd, hrs, ctx = row
        perfiles.append(
            {
                "id": pid,
                "nombre": nombre,
                "tipo": tipo,
                "municipio": mun,
                "macrodistrito": macro,
                "isp_tipico": isp,
                "usa_pagos_qr": qr,
                "activos_digitales": activos,
                "tecnologias": techs,
                "presupuesto_disponible_usd": usd,
                "presupuesto_disponible_bob": round(float(usd) * TIPO_CAMBIO_BOB, 2),
                "horas_tecnicas_disponibles": hrs,
                "contexto_operativo": ctx,
            }
        )

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with PERFILES_PATH.open("w", encoding="utf-8") as f:
        json.dump(perfiles, f, ensure_ascii=False, indent=2)

    print(f"[OK] Generados {len(perfiles)} perfiles en {PERFILES_PATH}")
    return perfiles
