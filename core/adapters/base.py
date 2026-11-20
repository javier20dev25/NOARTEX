"""
NOARTEX — Adapter Framework
Contrato base y ciclo de vida uniforme para adaptadores de herramientas externas.
M2-A Specification.
"""
from __future__ import annotations

import abc
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core.contracts.models import (
    AvailabilityStatus,
    Capability,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskResult,
    TaskStatus,
)


class AdapterStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


@dataclass
class AdapterLimits:
    """Restricciones de recursos y ejecución para el adaptador."""
    timeout_seconds: int = 30
    max_output_bytes: int = 10 * 1024 * 1024  # 10MB
    allowed_target_roots: list[str] = field(default_factory=list)
    allow_network: bool = False
    allow_subprocesses: bool = False


@dataclass
class AdapterMetadata:
    """Metadatos declarativos y procedencia del adaptador."""
    adapter_id: str
    name: str
    version: str
    provenance: str
    license: str
    author: str
    description: str = ""
    limits: AdapterLimits = field(default_factory=AdapterLimits)


class AdapterInterface(abc.ABC):
    """
    Contrato común para cualquier adaptador de NOARTEX.
    Invariantes:
    - No puede auto-otorgarse permisos.
    - No puede saltarse la evaluación del Policy Engine.
    - No puede declarar que un fallo o ausencia de herramienta significa 'CLEAN'.
    - Invocaciones a ejecutables externos deben usar vectores de argumentos (sin shell=True).
    """

    def __init__(self, metadata: AdapterMetadata):
        self.metadata = metadata

    @abc.abstractmethod
    def describe_capabilities(self) -> list[Capability]:
        """Retorna las capacidades que expone este adaptador."""
        pass

    @abc.abstractmethod
    def health(self) -> dict[str, Any]:
        """
        Retorna el estado operativo del adaptador (AVAILABLE, UNAVAILABLE, DEGRADED, ERROR),
        sus dependencias y limitaciones activas.
        """
        pass

    @abc.abstractmethod
    def execute(
        self,
        request: TaskRequest,
        decision: PolicyDecision,
    ) -> TaskResult:
        """
        Ejecuta la operación gobernada bajo las restricciones emitidas por Policy.
        """
        pass

    def validate_target_path(self, target_path: str | Path) -> tuple[bool, str]:
        """
        Valida que una ruta objetivo exista y esté contenida dentro de las raíces autorizadas.
        Previene Path Traversal y lecturas fuera de alcance.
        """
        try:
            resolved = Path(target_path).resolve()
        except Exception as e:
            return False, f"Invalid target path: {e}"

        if not resolved.exists():
            return False, f"Target path does not exist: {resolved}"

        # Si hay raíces configuradas, validar contención
        roots = self.metadata.limits.allowed_target_roots
        if roots:
            allowed = False
            for r in roots:
                try:
                    root_resolved = Path(r).resolve()
                    if resolved == root_resolved or root_resolved in resolved.parents:
                        allowed = True
                        break
                except Exception:
                    continue
            if not allowed:
                return False, f"Path traversal blocked: target '{resolved}' is outside authorized roots: {roots}"

        return True, str(resolved)
