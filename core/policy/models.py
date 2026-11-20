"""
NOARTEX — Policy Models & Enums (M5)
Contratos para permisos ABAC/RBAC deterministas:
- Niveles de riesgo R0 a R4
- Estados de postura de aprobación (MANUAL, AUTOMATIC, STRICT_HUMAN)
- Contratos de aprobación (ApprovalRequest, ApprovalGrant)
- Contratos de Kill Switch y Revocación
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ExecutionMode(str, Enum):
    """
    Modo de ejecución del Policy Engine:
    - MANUAL: Acciones R2+ requieren aprobación humana explícita.
    - AUTOMATIC: Acciones R2+ pre-autorizadas por política o reglas automáticas
      pueden auto-ejecutarse SIN intervención humana pero SIEMPRE bajo las
      restricciones estrictas del Policy Engine (el agente sigue sin auto-otorgarse permisos).
    - STRICT_HUMAN: Toda acción R2 o superior exige doble verificación humana.
    """
    MANUAL = "MANUAL"
    AUTOMATIC = "AUTOMATIC"
    STRICT_HUMAN = "STRICT_HUMAN"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class ApprovalGrant:
    """Aprobación explícita (humana o por regla automática de política)."""
    approval_id: str = field(default_factory=lambda: _new_id("appr"))
    task_id: str = ""
    operation: str = ""
    approver: str = "operator"
    approver_type: str = "human"  # human | automatic_policy
    scope: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)
    expires_at: Optional[str] = None
    status: ApprovalStatus = ApprovalStatus.GRANTED
    used: bool = False
    used_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "task_id": self.task_id,
            "operation": self.operation,
            "approver": self.approver,
            "approver_type": self.approver_type,
            "scope": self.scope,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "used": self.used,
            "used_at": self.used_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalGrant:
        return cls(
            approval_id=data.get("approval_id", _new_id("appr")),
            task_id=data.get("task_id", ""),
            operation=data.get("operation", ""),
            approver=data.get("approver", "operator"),
            approver_type=data.get("approver_type", "human"),
            scope=data.get("scope", {}),
            created_at=data.get("created_at", _now()),
            expires_at=data.get("expires_at"),
            status=ApprovalStatus(data.get("status", "GRANTED")),
            used=data.get("used", False),
            used_at=data.get("used_at"),
        )


@dataclass
class KillSwitchState:
    """Estado del interruptor de emergencia global o por dominio."""
    active: bool = False
    scope: str = "global"  # global | domain (e.g. "defense", "observer")
    activated_at: Optional[str] = None
    activated_by: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "scope": self.scope,
            "activated_at": self.activated_at,
            "activated_by": self.activated_by,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KillSwitchState:
        return cls(
            active=data.get("active", False),
            scope=data.get("scope", "global"),
            activated_at=data.get("activated_at"),
            activated_by=data.get("activated_by"),
            reason=data.get("reason"),
        )
