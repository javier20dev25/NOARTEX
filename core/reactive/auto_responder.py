"""
NOARTEX — Auto Responder
Autonomous governed response coordinator: triggers correlation, triage, and containment.
Operates strictly under PolicyEngine fail-closed invariants and ExecutionMode.AUTOMATIC.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from core.contracts.models import (
    ActorIdentity,
    AgentType,
    DecisionKind,
    PolicyDecision,
    TaskRequest,
    TaskResult,
    TaskStatus,
)
from core.intelligence import (
    EventCorrelator,
    Incident,
    IncidentState,
    IncidentStore,
    Severity,
    TriageEngine,
    TriageVerdict,
    VerdictClassification,
)
from core.policy.engine import PolicyEngine
from core.policy.models import ExecutionMode
from core.reactive.event_bus import EventPriority, EventType, ReactiveEvent, ReactiveEventBus


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ResponseChainLink:
    step: str
    event_id: str
    action_taken: str
    latency_ms: float
    timestamp: str = field(default_factory=_now)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "event_id": self.event_id,
            "action_taken": self.action_taken,
            "latency_ms": round(self.latency_ms, 3),
            "timestamp": self.timestamp,
            "details": self.details,
        }


class AutoResponder:
    """
    Subscribes to EventBus events and orchestrates the automatic response pipeline:
    Telemetry -> Auto-Correlation -> Deterministic Triage -> Policy Gating -> Containment Action.
    """

    def __init__(
        self,
        event_bus: ReactiveEventBus,
        correlator: EventCorrelator,
        triage_engine: TriageEngine,
        policy_engine: PolicyEngine,
        incident_store: Optional[IncidentStore] = None,
        containment_executor: Optional[Callable[[TaskRequest, PolicyDecision], TaskResult]] = None,
        correlation_threshold: int = 1,
    ):
        self.bus = event_bus
        self.correlator = correlator
        self.triage = triage_engine
        self.policy = policy_engine
        self.incidents = incident_store
        self.containment_executor = containment_executor
        self.correlation_threshold = correlation_threshold

        self._observations_buffer: list[dict[str, Any]] = []
        self._findings_buffer: list[dict[str, Any]] = []
        self._audit_buffer: list[dict[str, Any]] = []
        self._response_chain: list[ResponseChainLink] = []
        self._lock = threading.RLock()

        # Wire subscribers
        self.bus.subscribe(EventType.TELEMETRY_EVENT, self._on_telemetry_event)
        self.bus.subscribe(EventType.OBSERVATION_EVENT, self._on_observation_event)
        self.bus.subscribe(EventType.CORRELATION_TRIGGER, self._on_correlation_trigger)
        self.bus.subscribe(EventType.TRIAGE_TRIGGER, self._on_triage_trigger)
        self.bus.subscribe(EventType.CONTAINMENT_TRIGGER, self._on_containment_trigger)

    def _on_telemetry_event(self, event: ReactiveEvent) -> None:
        t0 = time.perf_counter()
        with self._lock:
            self._observations_buffer.append(event.payload)
            buf_len = len(self._observations_buffer)

        # Trigger immediately on CRITICAL events or when threshold is reached
        if event.priority == EventPriority.CRITICAL or buf_len >= self.correlation_threshold:
            self._trigger_correlation(t0)

    def _on_observation_event(self, event: ReactiveEvent) -> None:
        t0 = time.perf_counter()
        with self._lock:
            self._observations_buffer.append(event.payload)
        self._trigger_correlation(t0)

    def _trigger_correlation(self, origin_t0: float) -> None:
        t_start = time.perf_counter()
        with self._lock:
            obs = list(self._observations_buffer)
            findings = list(self._findings_buffer)
            audit = list(self._audit_buffer)

        corr = self.correlator.correlate(
            observations=obs,
            findings=findings,
            audit_records=audit,
        )
        t_corr = (time.perf_counter() - t_start) * 1000.0

        link = ResponseChainLink(
            step="CORRELATION",
            event_id=f"corr_{int(time.time()*1000)}",
            action_taken=f"Correlated {corr['summary']['total_evidence']} evidence items into {corr['summary']['total_timeline_events']} events",
            latency_ms=t_corr,
            details={"evidence_count": len(corr["evidence"]), "timeline_count": len(corr["timeline"])},
        )
        with self._lock:
            self._response_chain.append(link)

        # Publish trigger for next stage
        self.bus.publish(
            ReactiveEvent(
                event_type=EventType.CORRELATION_TRIGGER,
                payload={"correlation": corr, "origin_t0": origin_t0},
                priority=EventPriority.HIGH,
                source="auto_responder",
            )
        )

    def _on_correlation_trigger(self, event: ReactiveEvent) -> None:
        t_start = time.perf_counter()
        corr = event.payload.get("correlation", {})
        origin_t0 = event.payload.get("origin_t0", t_start)

        evidence = corr.get("evidence", [])
        if not evidence:
            return

        # Build incident structure for triage evaluation
        inc = Incident(
            incident_id=f"inc_auto_{int(time.time()*1000)}",
            title="Real-Time Automated Threat Correlation",
            severity=Severity.HIGH,
            evidence=evidence,
            timeline=corr.get("timeline", []),
            uncertainty=corr.get("uncertainty", {}),
        )
        verdict = self.triage.evaluate(inc)
        t_triage = (time.perf_counter() - t_start) * 1000.0

        link = ResponseChainLink(
            step="TRIAGE",
            event_id=event.event_id,
            action_taken=f"Triage verdict evaluated: {verdict.classification.value} (confidence={verdict.confidence.value})",
            latency_ms=t_triage,
            details={"verdict": verdict.classification.value, "confidence": verdict.confidence.value},
        )
        with self._lock:
            self._response_chain.append(link)

        # Publish Triage Trigger
        self.bus.publish(
            ReactiveEvent(
                event_type=EventType.TRIAGE_TRIGGER,
                payload={"verdict": verdict.to_dict(), "incident_id": inc.incident_id, "origin_t0": origin_t0},
                priority=EventPriority.CRITICAL if verdict.classification in (VerdictClassification.CONFIRMED, VerdictClassification.PARTIAL) else EventPriority.MEDIUM,
                source="auto_responder",
            )
        )

    def _on_triage_trigger(self, event: ReactiveEvent) -> None:
        t_start = time.perf_counter()
        verdict_data = event.payload.get("verdict", {})
        origin_t0 = event.payload.get("origin_t0", t_start)
        classification = verdict_data.get("classification")

        if classification not in ("CONFIRMED", "PARTIAL"):
            return

        # Prepare containment request
        actor = ActorIdentity(agent_id="auto_responder_daemon", agent_type=AgentType.SERVICE)
        req = TaskRequest(
            operation="defense.artifact.quarantine",
            actor=actor,
            session_id="sess_reactive_daemon",
            parameters={"target_path": "quarantine_candidate", "reason": f"Automated response to {classification} threat"},
            context={"auto_remediation": True},
        )

        # Policy evaluation under governed mode
        decision = self.policy.evaluate(req, session_active=True)
        t_policy = (time.perf_counter() - t_start) * 1000.0

        link = ResponseChainLink(
            step="POLICY_EVALUATION",
            event_id=event.event_id,
            action_taken=f"Policy decision: {decision.decision.value} (mode={self.policy.mode.value})",
            latency_ms=t_policy,
            details={"decision": decision.decision.value, "reasons": decision.reasons},
        )
        with self._lock:
            self._response_chain.append(link)

        if self.policy.is_allowed(decision):
            self.bus.publish(
                ReactiveEvent(
                    event_type=EventType.CONTAINMENT_TRIGGER,
                    payload={"request": req.to_dict(), "decision": decision.to_dict(), "origin_t0": origin_t0},
                    priority=EventPriority.CRITICAL,
                    source="auto_responder",
                )
            )

    def _on_containment_trigger(self, event: ReactiveEvent) -> None:
        t_start = time.perf_counter()
        req_dict = event.payload.get("request", {})
        dec_dict = event.payload.get("decision", {})
        origin_t0 = event.payload.get("origin_t0", t_start)

        req = TaskRequest(
            operation=req_dict.get("operation", "defense.artifact.quarantine"),
            actor=ActorIdentity(agent_id=req_dict.get("actor", {}).get("agent_id", "auto_responder")),
            session_id=req_dict.get("session_id", "sess_reactive"),
            parameters=req_dict.get("parameters", {}),
            task_id=req_dict.get("task_id", "task_auto_containment"),
        )
        dec = PolicyDecision(
            task_id=req.task_id,
            decision=DecisionKind(dec_dict.get("decision", "ALLOW_WITH_CONSTRAINTS")),
        )

        action_summary = "Containment action executed"
        if self.containment_executor:
            res = self.containment_executor(req, dec)
            action_summary = f"Containment executed: status={res.status.value}"

        t_containment = (time.perf_counter() - t_start) * 1000.0
        total_pipeline_ms = (time.perf_counter() - origin_t0) * 1000.0

        link = ResponseChainLink(
            step="CONTAINMENT_DISPATCH",
            event_id=event.event_id,
            action_taken=action_summary,
            latency_ms=t_containment,
            details={"total_pipeline_latency_ms": round(total_pipeline_ms, 3)},
        )
        with self._lock:
            self._response_chain.append(link)

    def get_response_chain(self) -> list[dict[str, Any]]:
        with self._lock:
            return [l.to_dict() for l in self._response_chain]

    def reset_buffers(self) -> None:
        with self._lock:
            self._observations_buffer.clear()
            self._findings_buffer.clear()
            self._audit_buffer.clear()
            self._response_chain.clear()
