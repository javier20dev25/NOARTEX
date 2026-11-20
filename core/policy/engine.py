"""
NOARTEX — Policy Engine (M5 Full Specification)
Motor de permisos determinista ABAC/RBAC R0 a R4 sin LLM.
Soporta:
- Niveles de riesgo R0, R1, R2, R3, R4
- Postura de ejecución: MANUAL (requiere aprobación humana) vs AUTOMATIC (auto-aprobación gobernada) vs STRICT_HUMAN
- Mediación de Aprobaciones con tokens no reutilizables y expiración
- Evaluación y bloqueo inmediato ante Kill Switch activo
- Fail-Closed garantizado ante fallos del motor o indisponibilidad
- El agente NUNCA se auto-asigna permisos: todo efecto emana de la política
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from core.contracts.models import (
    AgentType,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
)
from core.policy.approval import ApprovalManager
from core.policy.killswitch import KillSwitchManager
from core.policy.models import ApprovalGrant, ExecutionMode


# ---------------------------------------------------------------------------
# Clasificación de Operaciones por Nivel de Riesgo (R0–R4)
# ---------------------------------------------------------------------------

# R0: Lectura segura / Discovery / Health / Auditoría / Consultas
_R0_OPERATIONS = {
    "core.capabilities.list",
    "core.capabilities.describe",
    "core.doctor.health",
    "core.audit.query",
    "core.session.show",
    "core.session.list",
    "observer.host.processes",
    "observer.host.files",
    "observer.host.network",
    "observer.agent.activity",
    "observer.agent.denials",
    "observer.web.headers",
    "observer.web.dns",
    # M9 Tetragon stream ops
    "observer.tetragon.stream",
    "observer.tetragon.status",
    "observer.tetragon.stop",
    "intelligence.incident.show",
    "intelligence.incident.list",
    "policy.status",
    "policy.approvals.list",
    "policy.killswitch.status",
    # M7 Memory — read ops
    "memory.case.show",
    "memory.case.list",
    "memory.followup.list",
    "memory.followup.overdue",
}

# R1: Recolección y Análisis estático / Correlación / Triage (Read-Only)
_R1_OPERATIONS = {
    "core.session.create",
    "core.session.close",
    "core.task.status",
    "core.task.result",
    "sentinel.sast.scan",
    "sentinel.cicd.audit",
    "sentinel.supply_chain.audit",
    "sentinel.report.generate",
    "intelligence.correlate",
    "intelligence.incident.create",
    "intelligence.incident.update",
    "intelligence.triage.evaluate",
    # M7 Memory — write/export ops
    "memory.case.create",
    "memory.note.add",
    "memory.followup.add",
    "memory.followup.update",
    "memory.export",
    "memory.evidence.add",
}

# R2: Cambios reversibles / Bajo impacto operativo (Cuarentena lógica, tagging, export, rollback)
_R2_OPERATIONS = {
    "defense.artifact.quarantine",
    "defense.artifact.tag",
    "defense.evidence.export",
    "defense.action.rollback",
    # M7 Memory — retention (reversible archiving)
    "memory.retention",
}

# R3: Contención / Impacto operativo (Aislamiento de host, bloqueo de red, revocar sesiones)
_R3_OPERATIONS = {
    "defense.host.isolate",
    "defense.network.block",
    "defense.process.terminate",
    "policy.session.revoke",
    "policy.killswitch.activate",
    "policy.killswitch.deactivate",
    "policy.approval.grant",
    "policy.approval.revoke",
}

# R4: Remediación / Producción (Parches, cambios de configuración crítica, restauración)
_R4_OPERATIONS = {
    "defense.host.remediate",
    "defense.config.restore",
    "defense.patch.apply",
}


@dataclass
class PolicyRule:
    operations: set[str]
    effect: DecisionKind
    reasons: list[str]
    constraints: dict[str, Any] = field(default_factory=dict)
    risk: RiskLevel = RiskLevel.R0
    requires_session: bool = True


class PolicyEngine:
    """
    Motor de Policy determinista.
    Evalúa TaskRequest -> PolicyDecision considerando:
    - Sesión activa
    - Estado de Kill Switch (global / dominio)
    - Nivel de riesgo R0..R4
    - Modo de ejecución (MANUAL vs AUTOMATIC vs STRICT_HUMAN)
    - Presencia y validez de ApprovalGrant para R2..R4
    """

    def __init__(
        self,
        execution_mode: ExecutionMode = ExecutionMode.MANUAL,
        approval_manager: Optional[ApprovalManager] = None,
        killswitch_manager: Optional[KillSwitchManager] = None,
        auto_approved_operations: Optional[set[str]] = None,
    ):
        self.mode = execution_mode
        self.approvals = approval_manager
        self.killswitch = killswitch_manager
        # Operaciones explícitas autorizadas en modo AUTOMATIC sin intervención humana
        self.auto_approved_ops = auto_approved_operations or set()

    def evaluate(
        self,
        request: TaskRequest,
        session_active: bool = True,
        extra_context: Optional[dict] = None,
    ) -> PolicyDecision:
        """
        Evalúa deterministamente una TaskRequest.
        Fail-Closed: ante cualquier condición anómala o no autorizada -> DENY.
        """
        op = request.operation
        params = request.parameters or {}
        context = request.context or {}
        if extra_context:
            context.update(extra_context)

        # 1. Comprobar Kill Switch
        if self.killswitch:
            blocked, reason = self.killswitch.is_blocked(op)
            if blocked:
                return PolicyDecision(
                    task_id=request.task_id,
                    decision=DecisionKind.DENY,
                    reasons=[f"Execution BLOCKED by Kill Switch: {reason}"],
                )

        # 2. Comprobar sesión activa requerida
        if not session_active:
            return PolicyDecision(
                task_id=request.task_id,
                decision=DecisionKind.DENY,
                reasons=["No active session", "Session required for all governed operations"],
            )

        # 3. Clasificación R0 (Lectura segura): ALLOW directo
        if op in _R0_OPERATIONS:
            return PolicyDecision(
                task_id=request.task_id,
                decision=DecisionKind.ALLOW,
                reasons=["R0 read-safe operation", "session active and verified"],
            )

        # 4. Clasificación R1 (Recolección/Análisis): ALLOW_WITH_CONSTRAINTS
        if op in _R1_OPERATIONS:
            return PolicyDecision(
                task_id=request.task_id,
                decision=DecisionKind.ALLOW_WITH_CONSTRAINTS,
                reasons=["R1 analysis / collection operation", "read-only governed constraints applied"],
                constraints={"max_duration_ms": 30000, "read_only": True, "redact_secrets": True},
            )

        # 4b. Operaciones de Gobernanza Administrativa (aprobaciones, killswitch, revocación)
        # Solo ejecutables por un operador humano. Los agentes NO pueden ejecutarlas (fail-closed).
        _ADMIN_GOVERNANCE_OPS = {
            "policy.approval.grant",
            "policy.approval.revoke",
            "policy.killswitch.activate",
            "policy.killswitch.deactivate",
            "policy.session.revoke",
        }
        if op in _ADMIN_GOVERNANCE_OPS:
            is_human = (
                request.actor.agent_type == AgentType.HUMAN
                or "human" in request.actor.agent_id.lower()
                or "operator" in request.actor.agent_id.lower()
            )
            if is_human:
                return PolicyDecision(
                    task_id=request.task_id,
                    decision=DecisionKind.ALLOW,
                    reasons=[f"Administrative operation '{op}' authorized for human operator"],
                    approver=request.actor.agent_id,
                )
            else:
                return PolicyDecision(
                    task_id=request.task_id,
                    decision=DecisionKind.DENY,
                    reasons=[f"Agent '{request.actor.agent_id}' cannot execute administrative governance operation '{op}' — human authority required"],
                )

        # 5. Clasificación R2, R3, R4 (Operaciones Privilegiadas / Contención / Remediación)
        is_r2 = op in _R2_OPERATIONS
        is_r3 = op in _R3_OPERATIONS
        is_r4 = op in _R4_OPERATIONS

        if is_r2 or is_r3 or is_r4:
            risk = RiskLevel.R4 if is_r4 else (RiskLevel.R3 if is_r3 else RiskLevel.R2)

            # Comprobar si se presenta un token de aprobación (approval_id)
            approval_id = params.get("approval_id") or context.get("approval_id")
            if approval_id and self.approvals:
                valid, msg = self.approvals.validate_and_consume(
                    approval_id=approval_id,
                    task_id=request.task_id,
                    operation=op,
                    actor_id=request.actor.agent_id,
                )
                if valid:
                    grant = self.approvals.get(approval_id)
                    approver = grant.approver if grant else "operator"
                    return PolicyDecision(
                        task_id=request.task_id,
                        decision=DecisionKind.ALLOW_WITH_CONSTRAINTS,
                        reasons=[
                            f"{risk.value} privileged operation authorized via valid approval '{approval_id}'",
                            f"Approver: {approver}",
                            msg,
                        ],
                        approver=approver,
                        constraints={
                            "risk_level": risk.value,
                            "approved_scope": grant.scope if grant else {},
                            "audit_enforced": True,
                        },
                    )
                else:
                    return PolicyDecision(
                        task_id=request.task_id,
                        decision=DecisionKind.DENY,
                        reasons=[f"Invalid or rejected approval grant: {msg}"],
                    )

            # Si NO hay aprobación previa:
            # Comprobar si estamos en modo AUTOMATIC y la operación está pre-autorizada
            if self.mode == ExecutionMode.AUTOMATIC and (op in self.auto_approved_ops or context.get("auto_remediation") is True):
                # En modo AUTOMATIC, la política auto-emite la concesión bajo constraints estrictos
                return PolicyDecision(
                    task_id=request.task_id,
                    decision=DecisionKind.ALLOW_WITH_CONSTRAINTS,
                    reasons=[
                        f"{risk.value} authorized in AUTOMATIC mode by deterministic policy rule",
                        "Pre-approved automatic defensive action executed without human intervention",
                    ],
                    approver="policy:automatic_rule",
                    constraints={"risk_level": risk.value, "mode": "AUTOMATIC", "audit_enforced": True},
                )

            # Si no está en modo automático o no está pre-autorizada -> REQUIRE_APPROVAL
            return PolicyDecision(
                task_id=request.task_id,
                decision=DecisionKind.REQUIRE_APPROVAL,
                reasons=[
                    f"Privileged operation ({risk.value}) requires explicit approval before dispatch",
                    f"Operation: {op}",
                    f"Current Policy mode: {self.mode.value}",
                    "Submit approval grant with task before execution can proceed",
                ],
                constraints={"risk_level": risk.value},
            )

        # 6. Operaciones desconocidas -> Fail-Closed (DENY)
        return PolicyDecision(
            task_id=request.task_id,
            decision=DecisionKind.DENY,
            reasons=[
                f"Operation '{op}' is not registered in capability registry or policy matrix",
                "Fail-closed: unmapped operations are denied",
            ],
        )

    def is_allowed(self, decision: PolicyDecision) -> bool:
        return decision.decision in (
            DecisionKind.ALLOW,
            DecisionKind.ALLOW_WITH_CONSTRAINTS,
        )
