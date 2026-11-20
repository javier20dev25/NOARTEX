"""
NOARTEX — Orchestrator
Núcleo de enrutamiento: recibe tareas, invoca Policy, despacha y audita.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from core.audit.store import AuditLog
from core.contracts.models import (
    ActorIdentity,
    AgentType,
    DecisionKind,
    PolicyDecision,
    TaskRequest,
    TaskResult,
    TaskStatus,
)
from core.discovery.registry import CapabilityRegistry
from core.intelligence import (
    EventCorrelator,
    EvidenceItem,
    Incident,
    IncidentState,
    IncidentStore,
    Severity,
    TimelineEvent,
    TriageEngine,
)
from core.memory import CaseManager, NotableSource, FollowUpState
from core.policy.engine import PolicyEngine
from core.session.manager import SessionManager


class Orchestrator:
    """
    Punto central de control de NOARTEX.
    El agente nunca accede directamente a capacidades privilegiadas;
    toda invocación pasa por aquí.
    """

    def __init__(
        self,
        audit_log: AuditLog,
        session_manager: SessionManager,
        registry: CapabilityRegistry,
        policy_engine: PolicyEngine,
        incident_store: Optional[IncidentStore] = None,
    ):
        self.audit = audit_log
        self.sessions = session_manager
        self.registry = registry
        self.policy = policy_engine
        data_dir = getattr(session_manager, "_dir", None) or getattr(session_manager, "data_dir", None)
        if not data_dir:
            from pathlib import Path
            data_dir = Path.home() / ".noartex"
        self.incidents = incident_store or IncidentStore(data_dir)
        self.correlator = EventCorrelator()
        self.triage = TriageEngine()
        # Almacén en memoria de tareas (M1; M7+ usa Memory/Case store)
        self._tasks: dict[str, dict] = {}
        # M7: CaseManager
        self.case_manager = CaseManager(data_dir)

    # ------------------------------------------------------------------
    # Sesiones
    # ------------------------------------------------------------------

    def session_create(
        self,
        agent_id: str,
        agent_type: str = "unknown",
        ttl_seconds: int = 3600,
    ) -> dict:
        sess = self.sessions.create(agent_id, agent_type, ttl_seconds)
        self.audit.append(
            "SESSION_CREATED",
            actor_id=agent_id,
            session_id=sess.session_id,
            data={"agent_type": agent_type, "ttl_seconds": ttl_seconds},
        )
        return sess.to_dict()

    def session_show(self, session_id: str) -> Optional[dict]:
        sess = self.sessions.get(session_id)
        return sess.to_dict() if sess else None

    def session_list(self, agent_id: Optional[str] = None) -> list[dict]:
        return [s.to_dict() for s in self.sessions.list_sessions(agent_id)]

    def session_close(self, session_id: str, actor_id: str = "operator") -> bool:
        ok = self.sessions.close(session_id)
        if ok:
            self.audit.append(
                "SESSION_CLOSED",
                actor_id=actor_id,
                session_id=session_id,
            )
        return ok

    # ------------------------------------------------------------------
    # Tareas
    # ------------------------------------------------------------------

    def task_submit(
        self,
        operation: str,
        actor: ActorIdentity,
        session_id: str,
        parameters: Optional[dict] = None,
        target: Optional[dict] = None,
        context: Optional[dict] = None,
    ) -> dict:
        """
        Flujo completo: RECEIVED → POLICY_EVAL → dispatch/deny → COMPLETED/DENIED
        """
        req = TaskRequest(
            operation=operation,
            actor=actor,
            session_id=session_id,
            parameters=parameters or {},
            target=target,
            context=context or {},
        )

        # 1. RECEIVED
        self.audit.append(
            "TASK_REQUESTED",
            actor_id=actor.agent_id,
            session_id=session_id,
            task_id=req.task_id,
            data={"operation": operation, "request_id": req.request_id},
        )

        # 2. POLICY_EVAL
        session_active = self.sessions.is_active(session_id)
        decision = self.policy.evaluate(req, session_active=session_active)

        self.audit.append(
            "POLICY_EVALUATED",
            actor_id=actor.agent_id,
            session_id=session_id,
            task_id=req.task_id,
            decision_id=decision.decision_id,
            data={
                "decision": decision.decision.value,
                "reasons": decision.reasons,
                "constraints": decision.constraints,
            },
        )

        # 3. Dispatch o deny
        if self.policy.is_allowed(decision):
            result = self._dispatch(req, decision)
        elif decision.decision == DecisionKind.REQUIRE_APPROVAL:
            result = TaskResult(
                task_id=req.task_id,
                status=TaskStatus.PENDING_APPROVAL,
                decision_ref=decision.decision_id,
                observations=["Task requires explicit approval before execution"],
                limitations=["Approval flow not yet implemented in M1"],
            )
            self.audit.append(
                "APPROVAL_REQUESTED",
                actor_id=actor.agent_id,
                session_id=session_id,
                task_id=req.task_id,
                decision_id=decision.decision_id,
            )
        else:
            # DENY
            result = TaskResult(
                task_id=req.task_id,
                status=TaskStatus.DENIED,
                decision_ref=decision.decision_id,
                observations=decision.reasons,
                limitations=[],
            )
            self.audit.append(
                "TASK_DENIED",
                actor_id=actor.agent_id,
                session_id=session_id,
                task_id=req.task_id,
                decision_id=decision.decision_id,
                data={"reasons": decision.reasons},
            )

        # 4. Guardar en memoria
        self._tasks[req.task_id] = {
            "request": req.to_dict(),
            "decision": decision.to_dict(),
            "result": result.to_dict(),
        }
        return result.to_dict()

    def task_status(self, task_id: str) -> Optional[dict]:
        entry = self._tasks.get(task_id)
        if not entry:
            return None
        return {"task_id": task_id, "status": entry["result"]["status"]}

    def task_result(self, task_id: str) -> Optional[dict]:
        entry = self._tasks.get(task_id)
        return entry["result"] if entry else None

    # ------------------------------------------------------------------
    # Dispatch interno (core read-only M1)
    # ------------------------------------------------------------------

    def _dispatch(self, req: TaskRequest, decision: PolicyDecision) -> TaskResult:
        """
        Ejecuta operaciones core de M1 (read-only, sin adapters externos).
        """
        started = datetime.now(timezone.utc).isoformat()
        op = req.operation
        data: dict[str, Any] = {}
        observations: list[str] = []
        limitations: list[str] = []

        try:
            if op in ("core.capabilities.list", "core.capabilities.describe"):
                query = req.parameters.get("query", {})
                domain = query.get("domain") if isinstance(query, dict) else None
                caps = self.registry.list(domain=domain)
                data = {"capabilities": [c.to_dict() for c in caps]}
                observations.append(f"Listed {len(caps)} capabilities")

            elif op == "core.doctor.health":
                data = self.registry.health()

            elif op == "core.audit.query":
                p = req.parameters
                records = self.audit.query(
                    task_id=p.get("task_id"),
                    session_id=p.get("session_id"),
                    actor_id=p.get("actor_id"),
                    event_type=p.get("event_type"),
                    limit=p.get("limit", 50),
                )
                data = {"records": records, "count": len(records)}

            elif op == "core.session.list":
                agent_id = req.parameters.get("agent_id")
                data = {"sessions": self.session_list(agent_id)}

            elif op == "core.session.show":
                sid = req.parameters.get("session_id", req.session_id)
                sess = self.session_show(sid)
                data = {"session": sess} if sess else {}
                if not sess:
                    observations.append("Session not found")

            elif op == "core.task.status":
                tid = req.parameters.get("task_id", "")
                status = self.task_status(tid)
                data = status or {"error": "task not found"}

            elif op == "core.task.result":
                tid = req.parameters.get("task_id", "")
                result = self.task_result(tid)
                data = result or {"error": "task not found"}

            elif op == "intelligence.correlate":
                p = req.parameters
                corr = self.correlator.correlate(
                    observations=p.get("observations"),
                    findings=p.get("findings"),
                    audit_records=p.get("audit_records"),
                    context=p.get("context"),
                )
                data = {
                    "evidence": [e.to_dict() for e in corr["evidence"]],
                    "timeline": [t.to_dict() for t in corr["timeline"]],
                    "uncertainty": corr["uncertainty"],
                    "summary": corr["summary"],
                }
                if p.get("create_incident"):
                    inc = self.incidents.create(
                        title=p.get("incident_title", "Correlated Incident"),
                        severity=Severity(p.get("severity", "MEDIUM")),
                        owner=req.actor.agent_id,
                        hypotheses=p.get("hypotheses", []),
                        tags=p.get("tags", []),
                    )
                    for ev in corr["evidence"]:
                        inc.evidence.append(ev)
                    for tl in corr["timeline"]:
                        inc.timeline.append(tl)
                    inc.uncertainty = corr["uncertainty"]
                    self.incidents._persist()
                    data["incident"] = inc.to_dict()
                observations.append(
                    f"Correlated {corr['summary']['total_evidence']} evidence items into {corr['summary']['total_timeline_events']} timeline events"
                )

            elif op == "intelligence.incident.create":
                p = req.parameters
                inc = self.incidents.create(
                    title=p.get("title", "Untitled Incident"),
                    severity=Severity(p.get("severity", "MEDIUM")),
                    owner=p.get("owner", req.actor.agent_id),
                    hypotheses=p.get("hypotheses", []),
                    tags=p.get("tags", []),
                )
                data = {"incident": inc.to_dict()}
                observations.append(f"Created incident '{inc.incident_id}' with severity {inc.severity.value}")

            elif op == "intelligence.incident.update":
                p = req.parameters
                iid = p.get("incident_id", "")
                st = IncidentState(p["state"]) if "state" in p else None
                sev = Severity(p["severity"]) if "severity" in p else None
                inc = self.incidents.update(
                    incident_id=iid,
                    state=st,
                    severity=sev,
                    hypotheses=p.get("hypotheses"),
                    tags=p.get("tags"),
                    owner=p.get("owner"),
                )
                if p.get("note"):
                    self.incidents.add_note(iid, author=req.actor.agent_id, note=p["note"])
                data = {"incident": inc.to_dict() if inc else None}
                if not inc:
                    observations.append(f"Incident '{iid}' not found")

            elif op == "intelligence.incident.show":
                p = req.parameters
                iid = p.get("incident_id", "")
                inc = self.incidents.get(iid)
                data = {"incident": inc.to_dict() if inc else None}
                if not inc:
                    observations.append(f"Incident '{iid}' not found")

            elif op == "intelligence.incident.list":
                p = req.parameters
                incs = self.incidents.list_incidents(
                    state=p.get("state"),
                    severity=p.get("severity"),
                    limit=p.get("limit", 50),
                )
                data = {"incidents": [i.to_dict() for i in incs], "count": len(incs)}
                observations.append(f"Listed {len(incs)} incidents")

            elif op == "intelligence.triage.evaluate":
                p = req.parameters
                iid = p.get("incident_id")
                inc = self.incidents.get(iid) if iid else None
                if not inc:
                    # Crear incidente provisional a partir de los datos recibidos
                    corr = self.correlator.correlate(
                        observations=p.get("observations"),
                        findings=p.get("findings"),
                        audit_records=p.get("audit_records"),
                    )
                    inc = Incident(
                        incident_id=iid or f"inc_temp_{req.task_id[:8]}",
                        title=p.get("title", "Ad-hoc Triage Evaluation"),
                        severity=Severity(p.get("severity", "MEDIUM")),
                        tags=p.get("tags", []),
                        evidence=corr["evidence"],
                        timeline=corr["timeline"],
                        uncertainty=corr["uncertainty"],
                    )
                verdict = self.triage.evaluate(inc, fp_rules=p.get("fp_rules"))
                if iid and self.incidents.get(iid):
                    self.incidents.save_verdict(verdict)
                data = {"verdict": verdict.to_dict()}
                observations.append(
                    f"Triage evaluated: verdict={verdict.classification.value}, confidence={verdict.confidence.value}"
                )

            # --- M5: Policy, Aprobaciones y Kill Switch ---
            elif op == "policy.status":
                data = {
                    "mode": self.policy.mode.value,
                    "killswitch_active": any(s.active for s in (self.policy.killswitch._switches.values() if self.policy.killswitch else [])),
                    "auto_approved_operations": list(self.policy.auto_approved_ops),
                }

            elif op == "policy.approval.grant":
                p = req.parameters
                if not self.policy.approvals:
                    observations.append("No approval manager configured in policy engine")
                    data = {"error": "no approval manager"}
                else:
                    g = self.policy.approvals.grant(
                        task_id=p.get("task_id", ""),
                        operation=p.get("target_operation", ""),
                        approver=p.get("approver", req.actor.agent_id),
                        approver_type=p.get("approver_type", "human"),
                        scope=p.get("scope", {}),
                        ttl_seconds=p.get("ttl_seconds", 600),
                    )
                    data = {"approval": g.to_dict()}
                    observations.append(f"Granted approval '{g.approval_id}' for task '{g.task_id}' (TTL={p.get('ttl_seconds', 600)}s)")

            elif op == "policy.approval.revoke":
                p = req.parameters
                aid = p.get("approval_id", "")
                ok = self.policy.approvals.revoke(aid, revoker=req.actor.agent_id) if self.policy.approvals else False
                data = {"revoked": ok, "approval_id": aid}
                observations.append(f"Revoked approval '{aid}': {ok}")

            elif op == "policy.approvals.list":
                p = req.parameters
                tid = p.get("task_id")
                grants = self.policy.approvals.list_grants(task_id=tid) if self.policy.approvals else []
                data = {"approvals": [g.to_dict() for g in grants], "count": len(grants)}

            elif op == "policy.killswitch.activate":
                p = req.parameters
                scope = p.get("scope", "global")
                reason = p.get("reason", "Emergency intervention")
                if self.policy.killswitch:
                    st = self.policy.killswitch.activate(scope=scope, activated_by=req.actor.agent_id, reason=reason)
                    data = {"killswitch": st.to_dict()}
                    observations.append(f"Kill switch ACTIVATED for scope '{scope}'")
                else:
                    data = {"error": "no killswitch manager"}

            elif op == "policy.killswitch.deactivate":
                p = req.parameters
                scope = p.get("scope", "global")
                ok = self.policy.killswitch.deactivate(scope=scope) if self.policy.killswitch else False
                data = {"deactivated": ok, "scope": scope}
                observations.append(f"Kill switch DEACTIVATED for scope '{scope}': {ok}")

            elif op == "policy.session.revoke":
                p = req.parameters
                sid = p.get("session_id", "")
                closed = self.session_close(sid, actor_id=req.actor.agent_id)
                data = {"revoked": closed, "session_id": sid}
                observations.append(f"Session '{sid}' revoked: {closed}")

            # --- M7: Memory / Case Manager ---
            elif op == "memory.case.create":
                p = req.parameters
                case = self.case_manager.create_case(
                    title=p.get("title", "Untitled"),
                    description=p.get("description", ""),
                    severity=p.get("severity", "medium"),
                    actor=p.get("actor", req.actor.agent_id),
                    tags=p.get("tags", []),
                    incident_ref=p.get("incident_ref"),
                    created_at=p.get("created_at"),
                )
                data = {"case": case.to_dict()}
                observations.append(f"Created case '{case.case_id}'")

            elif op == "memory.case.show":
                p = req.parameters
                case = self.case_manager.get_case(p.get("case_id", ""))
                data = {"case": case.to_dict() if case else None}
                if not case:
                    observations.append("Case not found")

            elif op == "memory.case.list":
                p = req.parameters
                result_q = self.case_manager.query(
                    actor=p.get("actor"),
                    severity=p.get("severity"),
                    tag=p.get("tag"),
                    state=p.get("state"),
                    include_archived=p.get("include_archived", False),
                    limit=p.get("limit", 50),
                    offset=p.get("offset", 0),
                )
                data = result_q
                observations.append(f"Query returned {result_q['total']} total cases")

            elif op == "memory.note.add":
                p = req.parameters
                note = self.case_manager.add_note(
                    case_id=p.get("case_id", ""),
                    source=NotableSource(p.get("source", "agent")),
                    author=p.get("author", req.actor.agent_id),
                    content=p.get("content", ""),
                )
                data = {"note": note.to_dict()}
                observations.append(f"Added note '{note.note_id}' to case '{note.case_id}'")

            elif op == "memory.evidence.add":
                p = req.parameters
                ev = self.case_manager.add_evidence(
                    case_id=p.get("case_id", ""),
                    title=p.get("title", ""),
                    source=p.get("source", ""),
                    content=p.get("content", ""),
                    collected_at=p.get("collected_at"),
                )
                data = {"evidence": ev.to_dict()}
                observations.append(f"Added evidence '{ev.evidence_id}' to case '{ev.case_id}'")

            elif op == "memory.followup.add":
                p = req.parameters
                fu = self.case_manager.add_followup(
                    case_id=p.get("case_id", ""),
                    title=p.get("title", ""),
                    assignee=p.get("assignee"),
                    due_at=p.get("due_at"),
                )
                data = {"followup": fu.to_dict()}
                observations.append(f"Added follow-up '{fu.followup_id}' to case '{fu.case_id}'")

            elif op == "memory.followup.update":
                p = req.parameters
                fu = self.case_manager.update_followup_state(
                    followup_id=p.get("followup_id", ""),
                    new_state=FollowUpState(p.get("state", "OPEN")),
                )
                data = {"followup": fu.to_dict()}
                observations.append(f"Updated follow-up '{fu.followup_id}' to state '{fu.state.value}'")

            elif op == "memory.followup.list":
                p = req.parameters
                case_id = p.get("case_id", "")
                fus = self.case_manager.list_followups(case_id)
                data = {"followups": [f.to_dict() for f in fus], "count": len(fus)}
                observations.append(f"Listed {len(fus)} follow-ups for case '{case_id}'")

            elif op == "memory.followup.overdue":
                fus = self.case_manager.list_overdue_followups()
                data = {"followups": [f.to_dict() for f in fus], "count": len(fus)}
                observations.append(f"Found {len(fus)} overdue follow-ups")

            elif op == "memory.export":
                p = req.parameters
                export = self.case_manager.export_case(p.get("case_id", ""))
                data = {"export": export}
                observations.append(f"Exported case '{p.get('case_id')}' with hash {export.get('export_hash', '')[:16]}...")

            elif op == "memory.retention":
                p = req.parameters
                result_ret = self.case_manager.apply_retention(max_age_days=p.get("max_age_days", 90))
                data = result_ret
                observations.append(
                    f"Retention applied: {result_ret['archived']} archived, "
                    f"{result_ret['preserved_audit_entries']} audit entries preserved"
                )

            else:
                # Comprobar si hay un adaptador registrado para esta operación
                adapter = self.registry.get_adapter_for_operation(op)
                if adapter is not None:
                    adapter_result = adapter.execute(req, decision)
                    # Registrar evento de auditoría correspondiente al estado del adaptador
                    event = "TASK_COMPLETED" if adapter_result.status in (
                        TaskStatus.SUCCEEDED, TaskStatus.DEGRADED
                    ) else "TASK_FAILED"
                    self.audit.append(
                        event,
                        actor_id=req.actor.agent_id,
                        session_id=req.session_id,
                        task_id=req.task_id,
                        decision_id=decision.decision_id,
                        data={
                            "status": adapter_result.status.value,
                            "operation": op,
                            "adapter_id": adapter.metadata.adapter_id,
                        },
                    )
                    return adapter_result

                observations.append(f"Operation '{op}' allowed but no handler registered")
                limitations.append("Handler not yet implemented — register an adapter")
                data = {"status": "UNAVAILABLE", "operation": op}

        except Exception as exc:
            self.audit.append("SYSTEM_ERROR", task_id=req.task_id, data={"error": str(exc)})
            return TaskResult(
                task_id=req.task_id,
                status=TaskStatus.FAILED,
                decision_ref=decision.decision_id,
                observations=[f"Internal error: {exc}"],
                started_at=started,
            )

        result = TaskResult(
            task_id=req.task_id,
            status=TaskStatus.SUCCEEDED,
            decision_ref=decision.decision_id,
            data=data,
            observations=observations,
            limitations=limitations,
            started_at=started,
        )
        self.audit.append(
            "TASK_COMPLETED",
            actor_id=req.actor.agent_id,
            session_id=req.session_id,
            task_id=req.task_id,
            decision_id=decision.decision_id,
            data={"status": "SUCCEEDED", "operation": op},
        )
        return result
