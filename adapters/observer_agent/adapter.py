"""
NOARTEX — Agent Activity Observer Adapter (M3-C)
Monitorea la actividad de los agentes conectados a NOARTEX:
- Herramientas y operaciones invocadas
- Tareas denegadas por el Policy Engine
- Errores repetitivos y anomalías
- Patrones de comportamiento sospechosos
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from core.adapters.base import (
    AdapterInterface,
    AdapterLimits,
    AdapterMetadata,
    AdapterStatus,
)
from core.audit.store import AuditLog
from core.contracts.models import (
    AvailabilityStatus,
    Capability,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskResult,
    TaskStatus,
)
from core.observer.models import (
    ObservationDomain,
    ObservationEvent,
    ObservationState,
)


class AgentObserverAdapter(AdapterInterface):
    DEFAULT_METADATA = AdapterMetadata(
        adapter_id="adapter.observer.agent",
        name="Agent Activity Observer",
        version="1.0.0",
        provenance="noartex core audit intelligence",
        license="MIT",
        author="NOARTEX Core Team",
        description="Observes agent task history, denied invocations, and anomalous tool usage patterns",
        limits=AdapterLimits(
            timeout_seconds=10,
            max_output_bytes=5 * 1024 * 1024,
            allowed_target_roots=[],
            allow_network=False,
            allow_subprocesses=False,
        ),
    )

    def __init__(self, audit_log: AuditLog, metadata: Optional[AdapterMetadata] = None):
        super().__init__(metadata or self.DEFAULT_METADATA)
        self.audit = audit_log

    def describe_capabilities(self) -> list[Capability]:
        return [
            Capability(
                capability_id="observer.agent.activity",
                version="1.0.0",
                domain="observer",
                operations=["summary", "inspect"],
                risk=RiskLevel.R0,
                description="Summarize agent task activity, tool calls, and denied operations",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="observer.agent.denials",
                version="1.0.0",
                domain="observer",
                operations=["list"],
                risk=RiskLevel.R0,
                description="Detect repeated denied operations or potential policy bypass attempts",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
        ]

    def health(self) -> dict[str, Any]:
        return {
            "adapter_id": self.metadata.adapter_id,
            "status": AdapterStatus.AVAILABLE.value,
            "version": self.metadata.version,
            "limitations": [],
        }

    def execute(self, request: TaskRequest, decision: PolicyDecision) -> TaskResult:
        started = datetime.now(timezone.utc).isoformat()
        op = request.operation
        params = request.parameters or {}

        target_agent = params.get("agent_id")
        limit = params.get("limit", 100)

        records = self.audit.query(actor_id=target_agent, limit=limit)

        if op == "observer.agent.activity":
            total_tasks = sum(1 for r in records if r.get("event_type") == "TASK_REQUESTED")
            denials = [r for r in records if r.get("event_type") in ("TASK_DENIED", "APPROVAL_DENIED")]
            completed = sum(1 for r in records if r.get("event_type") == "TASK_COMPLETED")

            state = (
                ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED
                if len(denials) >= 3
                else ObservationState.NO_ACTIVITY_OBSERVED
            )

            obs_event = ObservationEvent(
                domain=ObservationDomain.AGENT,
                event_type="agent_activity_summary",
                state=state,
                target_scope=target_agent or "all_agents",
                coverage={"records_evaluated": len(records)},
                data={
                    "total_requested": total_tasks,
                    "total_completed": completed,
                    "total_denied": len(denials),
                    "target_agent": target_agent,
                },
                evidence=[{"type": "audit_denials", "count": len(denials)}],
                confidence="HIGH",
            )

            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data={"observation": obs_event.to_dict()},
                evidence=obs_event.evidence,
                observations=[
                    f"Agent activity analyzed: {total_tasks} requested, {len(denials)} denied."
                ],
                started_at=started,
            )

        elif op == "observer.agent.denials":
            denials = [
                r for r in records if r.get("event_type") in ("TASK_DENIED", "APPROVAL_DENIED")
            ]
            state = (
                ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED
                if denials
                else ObservationState.NO_ACTIVITY_OBSERVED
            )

            obs_event = ObservationEvent(
                domain=ObservationDomain.AGENT,
                event_type="agent_denials_list",
                state=state,
                target_scope=target_agent or "all_agents",
                coverage={"evaluated_records": len(records)},
                data={"denials": denials, "denial_count": len(denials)},
                evidence=[{"type": "denied_events", "sample": denials[:10]}],
                confidence="HIGH",
            )

            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data={"observation": obs_event.to_dict()},
                evidence=obs_event.evidence,
                observations=[f"Found {len(denials)} policy denial events"],
                started_at=started,
            )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.DENIED,
            decision_ref=decision.decision_id,
            observations=[f"Unsupported agent observer operation: '{op}'"],
            started_at=started,
        )
