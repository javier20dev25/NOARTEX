"""
NOARTEX — Discovery / Capability Registry
Catálogo de capacidades disponibles en el core y adaptadores registrados.
M1 + M2 Specification.
"""
from __future__ import annotations

import shutil
from typing import TYPE_CHECKING, Optional

from core.contracts.models import AvailabilityStatus, Capability, RiskLevel

if TYPE_CHECKING:
    from core.adapters.base import AdapterInterface


# ---------------------------------------------------------------------------
# Capacidades built-in del core M1
# ---------------------------------------------------------------------------
_BUILTIN_CAPABILITIES: list[Capability] = [
    Capability(
        capability_id="core.capabilities.list",
        version="1.0.0",
        domain="discovery",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List all registered capabilities with their metadata",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.capabilities.describe",
        version="1.0.0",
        domain="discovery",
        operations=["describe"],
        risk=RiskLevel.R0,
        description="Describe a specific capability by id",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.doctor.health",
        version="1.0.0",
        domain="health",
        operations=["health"],
        risk=RiskLevel.R0,
        description="Check health of NOARTEX core components and registered adapters",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.session.create",
        version="1.0.0",
        domain="session",
        operations=["create"],
        risk=RiskLevel.R1,
        description="Create a new agent session",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.session.list",
        version="1.0.0",
        domain="session",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List active sessions",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.session.show",
        version="1.0.0",
        domain="session",
        operations=["show"],
        risk=RiskLevel.R0,
        description="Show details of a specific session",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.session.close",
        version="1.0.0",
        domain="session",
        operations=["close"],
        risk=RiskLevel.R1,
        description="Close an active session",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.task.status",
        version="1.0.0",
        domain="task",
        operations=["status"],
        risk=RiskLevel.R1,
        description="Query the status of a submitted task",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.task.result",
        version="1.0.0",
        domain="task",
        operations=["result"],
        risk=RiskLevel.R1,
        description="Retrieve the result of a completed task",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="core.audit.query",
        version="1.0.0",
        domain="audit_memory",
        operations=["query"],
        risk=RiskLevel.R0,
        description="Query the append-only audit log by task, session, or actor",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.correlate",
        version="1.0.0",
        domain="intelligence",
        operations=["correlate"],
        risk=RiskLevel.R1,
        description="Correlate multi-source observations, findings, and audit signals into unified timeline",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.incident.create",
        version="1.0.0",
        domain="intelligence",
        operations=["create"],
        risk=RiskLevel.R1,
        description="Create and initialize a security incident with hypotheses and metadata",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.incident.update",
        version="1.0.0",
        domain="intelligence",
        operations=["update"],
        risk=RiskLevel.R1,
        description="Update incident state, hypotheses, tags, or owner",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.incident.show",
        version="1.0.0",
        domain="intelligence",
        operations=["show"],
        risk=RiskLevel.R0,
        description="Retrieve full incident record, timeline, evidence, and verdicts",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.incident.list",
        version="1.0.0",
        domain="intelligence",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List registered security incidents filtered by state or severity",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="intelligence.triage.evaluate",
        version="1.0.0",
        domain="intelligence",
        operations=["evaluate"],
        risk=RiskLevel.R1,
        description="Evaluate incident or signals deterministically to produce a schema-compliant triage verdict",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.status",
        version="1.0.0",
        domain="policy",
        operations=["status"],
        risk=RiskLevel.R0,
        description="Query current Policy Engine mode, rules, and kill switch status",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.approval.grant",
        version="1.0.0",
        domain="policy",
        operations=["grant"],
        risk=RiskLevel.R3,
        description="Grant explicit approval token for a privileged task",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.approval.revoke",
        version="1.0.0",
        domain="policy",
        operations=["revoke"],
        risk=RiskLevel.R3,
        description="Revoke an active approval grant",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.approvals.list",
        version="1.0.0",
        domain="policy",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List granted or pending approval tokens",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.killswitch.activate",
        version="1.0.0",
        domain="policy",
        operations=["activate"],
        risk=RiskLevel.R3,
        description="Activate emergency kill switch globally or per domain",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.killswitch.deactivate",
        version="1.0.0",
        domain="policy",
        operations=["deactivate"],
        risk=RiskLevel.R3,
        description="Deactivate emergency kill switch for a specified scope",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="policy.session.revoke",
        version="1.0.0",
        domain="policy",
        operations=["revoke"],
        risk=RiskLevel.R3,
        description="Revoke an active agent session immediately",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    # M7 — Memory Layer
    Capability(
        capability_id="memory.case.create",
        version="1.0.0",
        domain="memory",
        operations=["create"],
        risk=RiskLevel.R1,
        description="Create a new enrichable case with metadata and tags",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.case.show",
        version="1.0.0",
        domain="memory",
        operations=["show"],
        risk=RiskLevel.R0,
        description="Retrieve full case record by case_id",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.case.list",
        version="1.0.0",
        domain="memory",
        operations=["list"],
        risk=RiskLevel.R0,
        description="Query and list cases filtered by actor, severity, tag, or state",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.note.add",
        version="1.0.0",
        domain="memory",
        operations=["add"],
        risk=RiskLevel.R1,
        description="Add a human or agent note to a case",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.followup.add",
        version="1.0.0",
        domain="memory",
        operations=["add"],
        risk=RiskLevel.R1,
        description="Add a follow-up task associated to a case",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.followup.update",
        version="1.0.0",
        domain="memory",
        operations=["update"],
        risk=RiskLevel.R1,
        description="Update the state of a follow-up (OPEN/IN_PROGRESS/CLOSED)",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.followup.list",
        version="1.0.0",
        domain="memory",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List follow-ups for a case or list overdue follow-ups",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.export",
        version="1.0.0",
        domain="memory",
        operations=["export"],
        risk=RiskLevel.R1,
        description="Export a full case bundle with integrity hash",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.retention",
        version="1.0.0",
        domain="memory",
        operations=["apply"],
        risk=RiskLevel.R2,
        description="Apply retention policy: archive expired cases, preserve audit notes",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.evidence.add",
        version="1.0.0",
        domain="memory",
        operations=["add"],
        risk=RiskLevel.R1,
        description="Attach evidence item with integrity hash to a case",
        availability=AvailabilityStatus.AVAILABLE,
    ),
    Capability(
        capability_id="memory.followup.overdue",
        version="1.0.0",
        domain="memory",
        operations=["list"],
        risk=RiskLevel.R0,
        description="List all overdue follow-ups across all cases",
        availability=AvailabilityStatus.AVAILABLE,
    ),
]


class CapabilityRegistry:
    """
    Registry de capacidades NOARTEX.
    Soporta registro estático de capacidades del core y registro dinámico de adaptadores.
    """

    def __init__(self):
        self._capabilities: dict[str, Capability] = {
            cap.capability_id: cap for cap in _BUILTIN_CAPABILITIES
        }
        self._adapters: dict[str, AdapterInterface] = {}
        self._operation_to_adapter: dict[str, AdapterInterface] = {}
        self._adapter_notes: list[str] = []

    def register_adapter(self, adapter: AdapterInterface) -> None:
        """
        Registra un adaptador, descubre sus capacidades y las agrega al catálogo.
        """
        aid = adapter.metadata.adapter_id
        self._adapters[aid] = adapter
        caps = adapter.describe_capabilities()
        for cap in caps:
            self._capabilities[cap.capability_id] = cap
            # Mapear capability_id como operación
            self._operation_to_adapter[cap.capability_id] = adapter
            for op in cap.operations:
                full_op = f"{cap.capability_id}.{op}"
                self._operation_to_adapter[full_op] = adapter

    def get_adapter_for_operation(self, operation: str) -> Optional[AdapterInterface]:
        """Resuelve qué adaptador atiende una operación dada."""
        return self._operation_to_adapter.get(operation)

    def get_adapter(self, adapter_id: str) -> Optional[AdapterInterface]:
        return self._adapters.get(adapter_id)

    def list_adapters(self) -> list[AdapterInterface]:
        return list(self._adapters.values())

    def list(
        self,
        domain: Optional[str] = None,
        include_unavailable: bool = True,
    ) -> list[Capability]:
        caps = list(self._capabilities.values())
        if domain:
            caps = [c for c in caps if c.domain == domain]
        if not include_unavailable:
            caps = [c for c in caps if c.availability == AvailabilityStatus.AVAILABLE]
        return caps

    def get(self, capability_id: str) -> Optional[Capability]:
        return self._capabilities.get(capability_id)

    def register(self, capability: Capability) -> None:
        """Registra una capacidad manual."""
        self._capabilities[capability.capability_id] = capability

    def health(self) -> dict:
        """
        Health check del registry y de cada adaptador registrado.
        """
        available = sum(
            1 for c in self._capabilities.values()
            if c.availability == AvailabilityStatus.AVAILABLE
        )
        total = len(self._capabilities)

        components = {
            "core": {"status": "ok", "version": "1.0.0-m1"},
            "policy_engine": {"status": "ok", "mode": "deterministic"},
            "audit_log": {"status": "ok", "mode": "jsonl_append_only"},
            "session_manager": {"status": "ok"},
            "capability_registry": {
                "status": "ok",
                "total": total,
                "available": available,
            },
        }

        # Consultar salud de adaptadores registrados
        adapter_limitations = []
        if self._adapters:
            for aid, adp in self._adapters.items():
                h = adp.health()
                components[aid] = h
                adapter_limitations.extend(h.get("limitations", []))
        else:
            # Fallback legacy check
            sentinel_status = self._check_sentinel()
            components["sentinel_adapter"] = sentinel_status
            if sentinel_status["status"] == "not_installed":
                adapter_limitations.append("sentinel-runtime adapter not installed — using core only")

        overall = "ok" if all(
            str(c.get("status", "")).lower() in ("ok", "available", "not_installed", "unavailable")
            for c in components.values()
        ) else "degraded"

        return {
            "overall": overall,
            "components": components,
            "limitations": self._adapter_notes + adapter_limitations,
        }

    @staticmethod
    def _check_sentinel() -> dict:
        """Verifica si Sentinel CLI está presente."""
        if shutil.which("sentinel") or shutil.which("sentinel.cmd"):
            return {"status": "available", "note": "sentinel CLI found in PATH"}
        return {
            "status": "not_installed",
            "note": "sentinel not in PATH — core operates without it (by design)",
        }
