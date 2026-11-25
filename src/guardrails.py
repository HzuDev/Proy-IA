"""Fase 5: Guardrails deterministas de entrada y salida (alcance, anti-alucinación y transparencia)."""

from __future__ import annotations

import json
import re
from typing import Any

OFFENSIVE_PATTERNS = [
    r"\bexploit\w*\b",
    r"\bexplotar\b",
    r"\bhackear\b",
    r"\bhacking\b",
    r"\bpentest(?:ing)?\s+(?:no\s+autorizado|sin\s+permiso|externo)\b",
    r"\bfuerza\s+bruta\b",
    r"\bbrute\s*force\b",
    r"\breverse\s+shell\b",
    r"\bpayload\b",
    r"\bmetasploit\b",
    r"\bsqlmap\b",
    r"\bddos\b",
    r"\brobar\s+(?:contraseñas|datos|credenciales)\b",
    r"\binyecci[oó]n\s+sql\b.*\b(?:atacar|explotar|vulnerar)\b",
    r"\bsaltar\s+(?:autenticaci[oó]n|login|firewall)\b",
]

OFF_TOPIC_PATTERNS = [
    r"\breceta\s+de\b",
    r"\bhor[oó]scopo\b",
    r"\bpartido\s+de\s+f[uú]tbol\b",
    r"\bchiste\b",
    r"\bpoema\s+de\s+amor\b",
    r"\btraduce\s+esta\s+canci[oó]n\b",
]

CYBER_KEYWORDS = [
    "ciberseguridad",
    "seguridad",
    "vulnerabilidad",
    "cve",
    "riesgo",
    "mitigaci",
    "router",
    "mikrotik",
    "tp-link",
    "wifi",
    "wi-fi",
    "wordpress",
    "servidor",
    "smb",
    "rdp",
    "tráfico",
    "trafico",
    "red",
    "ataque",
    "diagnóstico",
    "diagnostico",
    "mype",
    "unidad educativa",
    "centro comunitario",
    "telecentro",
    "la paz",
    "el alto",
    "viacha",
    "presupuesto",
    "bolivianos",
    "proteger",
    "hardening",
    "respaldo",
    "incidente",
    "estadística",
    "estadistica",
    "perfil",
    "lpz-",
    "phishing",
    "quishing",
    "qr",
    "estafa",
    "suplantaci",
    "url",
    "enlace",
    "link",
    "http://",
    "https://",
    "ransomware",
    "malware",
    "agetic",
    "cgii",
    "csirt",
    "asfi",
    "att",
]

LA_PAZ_STATS_PATTERNS = [
    r"estad[ií]sticas?\s+(?:reales?\s+)?(?:de\s+)?incidentes",
    r"cu[aá]ntos\s+(?:ataques|incidentes|ciberataques)\s+(?:hubo|ocurrieron|existen)",
    r"por\s+(?:zona|barrio|macrodistrito)\s+(?:de|en)\s+la\s+paz",
    r"tasa\s+de\s+(?:ataques|incidentes)\s+en\s+(?:sopocachi|miraflores|centro|alto\s+lima|el\s+alto|la\s+paz|sur|obrajes|viacha)",
]

TRANSPARENCY_PHRASES = [
    "no existen estadísticas",
    "no se dispone",
    "no contamos con estadísticas",
    "no hay datos",
    "ausencia de",
    "no se registran estadísticas",
    "no posee estadísticas",
    "no incluye estadísticas",
    "sin estadísticas reales",
]


def pide_estadisticas_zona_lapaz(query: str) -> bool:
    q = query.lower()
    return any(re.search(pat, q) for pat in LA_PAZ_STATS_PATTERNS)


def validar_entrada(query: str) -> dict[str, Any]:
    """Input Guardrail: bloquea solicitudes ofensivas o ajenas a ciberseguridad defensiva."""
    q = query.strip().lower()
    if not q:
        return {
            "permitido": False,
            "categoria": "entrada_vacia",
            "motivo": "La consulta está vacía.",
            "pide_estadisticas_lapaz": False,
        }

    for pat in OFFENSIVE_PATTERNS:
        if re.search(pat, q):
            return {
                "permitido": False,
                "categoria": "solicitud_ofensiva",
                "motivo": (
                    "Solicitud bloqueada: este sistema únicamente realiza diagnóstico "
                    "preventivo y ciberseguridad defensiva; no genera exploits ni acciones ofensivas."
                ),
                "pide_estadisticas_lapaz": False,
            }

    for pat in OFF_TOPIC_PATTERNS:
        if re.search(pat, q):
            return {
                "permitido": False,
                "categoria": "fuera_de_alcance",
                "motivo": (
                    "Solicitud bloqueada: el tema está fuera del alcance de "
                    "ciberseguridad defensiva para entidades de La Paz."
                ),
                "pide_estadisticas_lapaz": False,
            }

    has_cyber_signal = any(kw in q for kw in CYBER_KEYWORDS)
    if not has_cyber_signal:
        return {
            "permitido": False,
            "categoria": "fuera_de_alcance",
            "motivo": (
                "Solicitud bloqueada: la consulta no se relaciona con diagnóstico "
                "preventivo de ciberseguridad ni activos digitales."
            ),
            "pide_estadisticas_lapaz": False,
        }

    return {
        "permitido": True,
        "categoria": "valido",
        "motivo": "Consulta válida dentro del alcance defensivo.",
        "pide_estadisticas_lapaz": pide_estadisticas_zona_lapaz(query),
    }


def _extract_authorized_cves(registro_tools: dict[str, Any]) -> set[str]:
    serialized = json.dumps(registro_tools, ensure_ascii=False)
    return set(re.findall(r"CVE-\d{4}-\d+", serialized, flags=re.IGNORECASE))


def _extract_authorized_numbers(registro_tools: dict[str, Any]) -> set[str]:
    """Extrae representaciones numéricas válidas presentes en las salidas de tools."""
    allowed: set[str] = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
            allowed.add(str(obj))
            allowed.add(f"{obj:.1f}")
            allowed.add(f"{obj:.2f}")
            allowed.add(f"{obj:.4f}")

    _walk(registro_tools)
    return allowed


def validar_salida(
    texto: str,
    registro_tools: dict[str, Any],
    pide_estadisticas_lapaz: bool = False,
) -> dict[str, Any]:
    """Output Guardrail: verifica trazabilidad literal de CVEs, cifras clave y transparencia."""
    errores: list[str] = []

    cves_en_texto = sorted(
        set(m.upper() for m in re.findall(r"CVE-\d{4}-\d+", texto, flags=re.IGNORECASE))
    )
    cves_autorizados = {c.upper() for c in _extract_authorized_cves(registro_tools)}
    cves_no_autorizados = [c for c in cves_en_texto if c not in cves_autorizados]

    if cves_no_autorizados:
        errores.append(
            f"CVEs no respaldados por herramientas: {', '.join(cves_no_autorizados)}"
        )

    # Verificar métricas clave si se mencionan explícitamente en el texto
    allowed_nums = _extract_authorized_numbers(registro_tools)
    metric_patterns = [
        (r"riesgo\s+reducido[^0-9]{0,20}(\d+(?:\.\d+)?)\s*%", "riesgo_reducido_pct"),
        (r"costo\s+total[^0-9]{0,20}(?:\$|bs\.?)?\s*(\d+(?:\.\d+)?)", "costo_total"),
        (r"horas\s+totales[^0-9]{0,20}(\d+(?:\.\d+)?)", "horas_totales"),
    ]
    for pat, label in metric_patterns:
        for match in re.finditer(pat, texto, flags=re.IGNORECASE):
            val = match.group(1)
            if val not in allowed_nums:
                errores.append(
                    f"Cifra '{val}' para {label} no coincide con la salida de tools."
                )

    if pide_estadisticas_lapaz:
        lower = texto.lower()
        declara_ausencia = any(phrase in lower for phrase in TRANSPARENCY_PHRASES)
        if not declara_ausencia:
            errores.append(
                "Transparencia La Paz: el usuario pidió estadísticas por zona/barrio y "
                "la respuesta no declaró explícitamente la ausencia de esos datos en data/."
            )

    return {
        "aprobado": len(errores) == 0,
        "errores": errores,
        "cves_encontrados": cves_en_texto,
        "cves_no_autorizados": cves_no_autorizados,
    }
