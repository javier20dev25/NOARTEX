"""
NOARTEX — Unified Observation Model (M3-D)
Modelo de eventos normalizado para fuentes heterogéneas (host, network, file, agent, web).
Garantiza los tres estados epistémicos fundamentales:
- NO_ACTIVITY_OBSERVED: La observación operó y no detectó actividad/cambios.
- OBSERVATION_UNAVAILABLE / DEGRADED: No se cuenta con visibilidad/capacidad o hubo fallo.
- SUSPICIOUS_ACTIVITY_OBSERVED: Se detectó actividad/anomalía con evidencia explícita.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ObservationDomain(str, Enum):
    HOST = "host"
    NETWORK = "network"
    FILE = "file"
    AGENT = "agent"
    WEB = "web"


class ObservationState(str, Enum):
    """
    Distinción epistémica obligatoria:
    - NO_ACTIVITY_OBSERVED: Sensor activo, alcance verificado, sin anomalías o cambios.
    - SUSPICIOUS_ACTIVITY_OBSERVED: Evento concreto registrado con evidencia.
    - OBSERVATION_UNAVAILABLE: Sensor no disponible o fuera de alcance.
    - DEGRADED: Observación parcial / limitada.
    """
    NO_ACTIVITY_OBSERVED = "NO_ACTIVITY_OBSERVED"
    SUSPICIOUS_ACTIVITY_OBSERVED = "SUSPICIOUS_ACTIVITY_OBSERVED"
    OBSERVATION_UNAVAILABLE = "OBSERVATION_UNAVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass
class ObservationEvent:
    """Evento normalizado de observación emitido por cualquier observer."""
    event_id: str = field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:12]}")
    domain: ObservationDomain = ObservationDomain.HOST
    event_type: str = "snapshot"
    state: ObservationState = ObservationState.NO_ACTIVITY_OBSERVED
    target_scope: str = "localhost"
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    coverage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: str = "HIGH"   # HIGH | MEDIUM | LOW | UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "domain": self.domain.value,
            "event_type": self.event_type,
            "state": self.state.value,
            "target_scope": self.target_scope,
            "collected_at": self.collected_at,
            "coverage": self.coverage,
            "limitations": self.limitations,
            "data": self.data,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
