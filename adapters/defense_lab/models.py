"""
NOARTEX — Defense Lab Models (M6)
Modelos de datos para contención, validación post-acción y planes de rollback.
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


class ContainmentStatus(str, Enum):
    CONTAINED = "CONTAINED"
    NOT_CONTAINED = "NOT_CONTAINED"
    DEGRADED = "DEGRADED"
    ROLLED_BACK = "ROLLED_BACK"


class DefenseActionType(str, Enum):
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    REMEDIATE = "remediate"
    ROLLBACK = "rollback"


@dataclass
class RollbackPlan:
    """Plan determinista para revertir una acción defensiva."""
    plan_id: str = field(default_factory=lambda: _new_id("rb"))
    action_type: DefenseActionType = DefenseActionType.QUARANTINE
    target: str = ""
    original_state: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "original_state": self.original_state,
            "steps": self.steps,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RollbackPlan:
        return cls(
            plan_id=data.get("plan_id", _new_id("rb")),
            action_type=DefenseActionType(data.get("action_type", "quarantine")),
            target=data.get("target", ""),
            original_state=data.get("original_state", {}),
            steps=data.get("steps", []),
            created_at=data.get("created_at", _now()),
        )


@dataclass
class PostActionValidation:
    """Resultado de la verificación post-contención / post-remediación."""
    validation_id: str = field(default_factory=lambda: _new_id("val"))
    action_id: str = ""
    status: ContainmentStatus = ContainmentStatus.CONTAINED
    checks_performed: list[dict[str, Any]] = field(default_factory=list)
    adverse_effects_detected: bool = False
    evidence_collected: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "validation_id": self.validation_id,
            "action_id": self.action_id,
            "status": self.status.value,
            "checks_performed": self.checks_performed,
            "adverse_effects_detected": self.adverse_effects_detected,
            "evidence_collected": self.evidence_collected,
            "timestamp": self.timestamp,
        }
