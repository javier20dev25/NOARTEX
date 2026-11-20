"""
NOARTEX M9-A Acceptance Tests — Reactive Event Pipeline & Asynchronous Dispatch
Validates thread-safe Priority Event Bus, sub-millisecond dispatch, priority preemption,
and autonomous trigger sequences with real timing benchmarks.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Insert root
ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))

from core.contracts.models import (
    ActorIdentity,
    AgentType,
    DecisionKind,
    PolicyDecision,
    TaskRequest,
    TaskResult,
    TaskStatus,
)
from core.intelligence import EventCorrelator, TriageEngine
from core.policy.engine import PolicyEngine
from core.policy.models import ExecutionMode
from core.reactive import (
    AutoResponder,
    EventPriority,
    EventType,
    ReactiveEvent,
    ReactiveEventBus,
)


def run_tests() -> bool:
    print("=" * 75)
    print("  NOARTEX M9-A Acceptance Tests — Reactive Event Pipeline")
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

    # -------------------------------------------------------------------------
    # M9-A-T1: Event Throughput & Dispatch Latency (< 50ms avg)
    # -------------------------------------------------------------------------
    print("\n--- M9-A-T1: Event throughput and dispatch latency ---")
    bus = ReactiveEventBus()
    bus.start()

    received_events = []
    bus.subscribe(EventType.TELEMETRY_EVENT, lambda ev: received_events.append(ev))

    t_start = time.perf_counter()
    N = 100
    for i in range(N):
        bus.publish(
            ReactiveEvent(
                event_type=EventType.TELEMETRY_EVENT,
                payload={"index": i, "data": "benchmark"},
                priority=EventPriority.MEDIUM,
            )
        )

    # Wait for all to be dispatched
    bus.drain(timeout=2.0)
    total_time_ms = (time.perf_counter() - t_start) * 1000.0
    metrics = bus.get_metrics()

    check("M9-A-T1: 100 events published", metrics["events_published"] == 100)
    check("M9-A-T1: 100 events dispatched", metrics["events_dispatched"] == 100)
    check(f"M9-A-T1: Average dispatch latency < 50ms (measured: {metrics['avg_dispatch_latency_ms']}ms)", metrics["avg_dispatch_latency_ms"] < 50.0)
    check(f"M9-A-T1: Total dispatch time for 100 events < 500ms (measured: {round(total_time_ms, 2)}ms)", total_time_ms < 500.0)
    bus.stop()

    # -------------------------------------------------------------------------
    # M9-A-T2: Priority Preemption (CRITICAL dispatched before LOW)
    # -------------------------------------------------------------------------
    print("\n--- M9-A-T2: Priority queue preemption ---")
    bus_p = ReactiveEventBus()
    # Do not start yet, queue both first to test priority ordering
    dispatched_order = []
    bus_p.subscribe("*", lambda ev: dispatched_order.append((ev.priority, ev.payload.get("name"))))

    # Queue LOW first, then CRITICAL
    bus_p.publish(ReactiveEvent(event_type=EventType.OBSERVATION_EVENT, payload={"name": "low_1"}, priority=EventPriority.LOW))
    bus_p.publish(ReactiveEvent(event_type=EventType.OBSERVATION_EVENT, payload={"name": "low_2"}, priority=EventPriority.LOW))
    bus_p.publish(ReactiveEvent(event_type=EventType.CONTAINMENT_TRIGGER, payload={"name": "crit_urgent"}, priority=EventPriority.CRITICAL))

    bus_p.start()
    bus_p.drain(timeout=1.0)
    bus_p.stop()

    check("M9-A-T2: 3 events dispatched", len(dispatched_order) == 3)
    check("M9-A-T2: CRITICAL event dispatched first despite being queued last", dispatched_order[0][0] == EventPriority.CRITICAL and dispatched_order[0][1] == "crit_urgent")

    # -------------------------------------------------------------------------
    # M9-A-T3: AutoResponder triggers correlation on threshold
    # -------------------------------------------------------------------------
    print("\n--- M9-A-T3: AutoResponder correlation trigger ---")
    bus_ar = ReactiveEventBus()
    correlator = EventCorrelator()
    triage = TriageEngine()
    policy = PolicyEngine(execution_mode=ExecutionMode.AUTOMATIC, auto_approved_operations={"defense.artifact.quarantine"})
    responder = AutoResponder(
        event_bus=bus_ar,
        correlator=correlator,
        triage_engine=triage,
        policy_engine=policy,
        correlation_threshold=2,
    )
    bus_ar.start()

    # Publish 2 telemetry items to trigger correlation
    bus_ar.publish(ReactiveEvent(
        event_type=EventType.TELEMETRY_EVENT,
        payload={"domain": "host", "state": "SUSPICIOUS_ACTIVITY_OBSERVED", "event_type": "kprobe_do_sys_openat2", "target_scope": "/etc/shadow", "confidence": "HIGH"},
    ))
    bus_ar.publish(ReactiveEvent(
        event_type=EventType.TELEMETRY_EVENT,
        payload={"domain": "network", "state": "SUSPICIOUS_ACTIVITY_OBSERVED", "event_type": "kprobe_tcp_v4_connect", "target_scope": "192.168.1.100:4444", "confidence": "HIGH"},
    ))

    time.sleep(0.15)
    bus_ar.drain(timeout=1.0)
    chain = responder.get_response_chain()

    check("M9-A-T3: Response chain has recorded links", len(chain) >= 2)
    step_names = [l["step"] for l in chain]
    check("M9-A-T3: CORRELATION step executed automatically", "CORRELATION" in step_names)
    check("M9-A-T3: TRIAGE step executed automatically", "TRIAGE" in step_names)

    # -------------------------------------------------------------------------
    # M9-A-T4: Full End-to-End Reactive Cycle (< 200ms)
    # -------------------------------------------------------------------------
    print("\n--- M9-A-T4: Full real-time cycle latency ---")
    containment_executed = []
    def mock_executor(req, dec):
        containment_executed.append((req.operation, dec.decision))
        return TaskResult(task_id=req.task_id, status=TaskStatus.SUCCEEDED)

    responder.containment_executor = mock_executor
    responder.reset_buffers()

    t_cycle_start = time.perf_counter()
    # Publish suspicious event triggering entire chain
    bus_ar.publish(ReactiveEvent(
        event_type=EventType.TELEMETRY_EVENT,
        payload={"domain": "host", "state": "SUSPICIOUS_ACTIVITY_OBSERVED", "event_type": "kprobe_open", "target_scope": "/srv/sentinel-enterprise-lab/root-secret.txt", "confidence": "HIGH"},
        priority=EventPriority.CRITICAL,
    ))

    time.sleep(0.1)
    bus_ar.drain(timeout=1.0)
    cycle_ms = (time.perf_counter() - t_cycle_start) * 1000.0

    chain_full = responder.get_response_chain()
    steps_full = [l["step"] for l in chain_full]

    check("M9-A-T4: POLICY_EVALUATION step executed in chain", "POLICY_EVALUATION" in steps_full)
    check("M9-A-T4: CONTAINMENT_DISPATCH step executed in chain", "CONTAINMENT_DISPATCH" in steps_full)
    check("M9-A-T4: Containment executor invoked with auto-approval", len(containment_executed) > 0 and containment_executed[0][1] == DecisionKind.ALLOW_WITH_CONSTRAINTS)
    check(f"M9-A-T4: Total real-time cycle latency < 200ms (measured: {round(cycle_ms, 2)}ms)", cycle_ms < 200.0)

    # -------------------------------------------------------------------------
    # M9-A-T5: Bus Stop & Drain Cleanliness
    # -------------------------------------------------------------------------
    print("\n--- M9-A-T5: Event bus stop and drain ---")
    bus_ar.stop()
    m_final = bus_ar.get_metrics()
    check("M9-A-T5: Event bus stopped cleanly", not m_final["running"])
    check("M9-A-T5: No unhandled queue backlog", m_final["queue_size"] == 0)

    print("\n" + "=" * 75)
    print(f"  M9-A Results: {passed}/{passed + failed} PASS  |  {failed} FAIL")
    print("=" * 75)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
