"""
NOARTEX — Core Contracts
Tipos de datos y validación de esquemas para contratos inter-módulos.
Contract version: 1.0
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


# ---------------------------------------------------------------------------
# Enumeraciones
# ---------------------------------------------------------------------------

class DecisionKind(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_WITH_CONSTRAINTS = "ALLOW_WITH_CONSTRAINTS"
    UNAVAILABLE = "UNAVAILABLE"


class TaskStatus(str, Enum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    POLICY_EVAL = "POLICY_EVAL"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    DENIED = "DENIED"
    QUEUED = "QUEUED"
    DISPATCHED = "DISPATCHED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class RiskLevel(str, Enum):
    R0 = "R0"   # lectura segura
    R1 = "R1"   # recolección/análisis
    R2 = "R2"   # cambio reversible
    R3 = "R3"   # contención
    R4 = "R4"   # remediación/producción


class AgentType(str, Enum):
    CODEX = "codex"
    CLAUDE = "claude"
    OPENCODE = "opencode"
    ANTIGRAVITY = "antigravity"
    HUMAN = "human"
    SERVICE = "service"
    UNKNOWN = "unknown"


class AvailabilityStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Entidades
# ---------------------------------------------------------------------------

@dataclass
class ActorIdentity:
    agent_id: str
    agent_type: AgentType = AgentType.UNKNOWN
    instance: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "instance": self.instance,
        }


@dataclass
class Session:
    session_id: str = field(default_factory=lambda: _new_id("sess"))
    agent_id: str = ""
    agent_type: AgentType = AgentType.UNKNOWN
    created_at: str = field(default_factory=_now)
    expires_at: Optional[str] = None
    state: str = "ACTIVE"   # ACTIVE | CLOSED | EXPIRED
    capabilities_requested: list[str] = field(default_factory=list)
    ttl_seconds: int = 3600

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "state": self.state,
            "capabilities_requested": self.capabilities_requested,
            "ttl_seconds": self.ttl_seconds,
        }


@dataclass
class Capability:
    capability_id: str
    version: str
    domain: str
    operations: list[str]
    risk: RiskLevel
    description: str = ""
    availability: AvailabilityStatus = AvailabilityStatus.AVAILABLE
    requires: list[str] = field(default_factory=list)
    adapter_id: Optional[str] = None
    input_schema_ref: Optional[str] = None
    output_schema_ref: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "capability_id": self.capability_id,
            "version": self.version,
            "domain": self.domain,
            "operations": self.operations,
            "risk": self.risk.value,
            "description": self.description,
            "availability": self.availability.value,
            "requires": self.requires,
            "adapter_id": self.adapter_id,
            "input_schema_ref": self.input_schema_ref,
            "output_schema_ref": self.output_schema_ref,
        }


@dataclass
class TaskRequest:
    operation: str
    actor: ActorIdentity
    session_id: str
    task_id: str = field(default_factory=lambda: _new_id("task"))
    request_id: str = field(default_factory=lambda: _new_id("req"))
    contract_version: str = "1.0"
    target: Optional[dict] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "actor": self.actor.to_dict(),
            "operation": self.operation,
            "target": self.target,
            "parameters": self.parameters,
            "context": self.context,
            "requested_at": self.requested_at,
        }


@dataclass
class PolicyDecision:
    decision_id: str = field(default_factory=lambda: _new_id("dec"))
    task_id: str = ""
    decision: DecisionKind = DecisionKind.DENY
    reasons: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    approver: Optional[str] = None
    decided_at: str = field(default_factory=_now)
    expires_at: Optional[str] = None
    contract_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "decision_id": self.decision_id,
            "task_id": self.task_id,
            "decision": self.decision.value,
            "reasons": self.reasons,
            "constraints": self.constraints,
            "approver": self.approver,
            "decided_at": self.decided_at,
            "expires_at": self.expires_at,
        }


@dataclass
class TaskResult:
    task_id: str
    status: TaskStatus
    decision_ref: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: str = field(default_factory=_now)
    contract_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "task_id": self.task_id,
            "status": self.status.value,
            "decision_ref": self.decision_ref,
            "data": self.data,
            "evidence": self.evidence,
            "observations": self.observations,
            "limitations": self.limitations,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
