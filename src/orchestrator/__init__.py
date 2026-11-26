"""Paquete de orquestación multi-agente."""

from src.orchestrator.pipeline import ejecutar_diagnostico
from src.orchestrator.planner import cargar_perfil

__all__ = ["cargar_perfil", "ejecutar_diagnostico"]
