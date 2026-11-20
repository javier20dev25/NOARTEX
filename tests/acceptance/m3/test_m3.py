#!/usr/bin/env python3
"""
NOARTEX M3 Acceptance & Negative Tests
Pruebas ejecutables M3-A (Host), M3-B (Web), M3-C (Agent), M3-D (Unified Model)
según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md

Verifica:
  - Host observer: processes, files, network (snapshots reales)
  - Web observer: DNS lookup, HTTP headers, degradación honesta
  - Agent observer: activity summary, denials
  - Modelo unificado: ObservationEvent, tres estados epistémicos
  - Degradación honesta: fallo ≠ estado seguro
  - Pruebas negativas: path denial, error → DEGRADED/UNAVAILABLE
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent.parent
NOARTEX_SCRIPT = str(ROOT / "noartex.py")

sys.path.insert(0, str(ROOT))

from core.adapters.base import AdapterInterface, AdapterLimits, AdapterMetadata, AdapterStatus
from core.contracts.models import (
    ActorIdentity,
    AgentType,
    AvailabilityStatus,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskResult,
    TaskStatus,
)
from core.observer.models import ObservationDomain, ObservationEvent, ObservationState
from adapters.observer_host.adapter import HostObserverAdapter
from adapters.observer_agent.adapter import AgentObserverAdapter
from adapters.observer_web.adapter import WebObserverAdapter
from core.audit.store import AuditLog

results: list[dict] = []
TEST_DATA_DIR = str(ROOT / "data" / "test_m3")


def run(args: list[str], extra_env: Optional[dict] = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["NOARTEX_DATA_DIR"] = TEST_DATA_DIR
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, NOARTEX_SCRIPT] + args,
        capture_output=True, text=True, env=env,
        cwd=str(ROOT),
    )
    return proc.returncode, proc.stdout, proc.stderr


def assert_ok(test_id: str, description: str, cond: bool, detail: str = "") -> bool:
    results.append({
        "id": test_id,
        "status": "PASS" if cond else "FAIL",
        "description": description,
        "detail": detail,
    })
    icon = "✅" if cond else "❌"
    print(f"  {icon} {test_id}: {description}")
    if not cond and detail:
        for line in detail[:600].split("\n"):
            print(f"       {line}")
    return cond


# ---------------------------------------------------------------------------
# Helper: make a mock PolicyDecision for direct adapter testing
# ---------------------------------------------------------------------------
def _allow_decision(task_id: str = "test_task") -> PolicyDecision:
    return PolicyDecision(task_id=task_id, decision=DecisionKind.ALLOW)


# ---------------------------------------------------------------------------
# M3-A: Host Observer
# ---------------------------------------------------------------------------

def test_m3a1_host_process_snapshot():
    """M3-A1: Process snapshot returns structured data with PID, PPID, name."""
    adapter = HostObserverAdapter()
    req = TaskRequest(
        operation="observer.host.processes",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    processes = obs.get("data", {}).get("processes", [])

    cond = (
        result.status in (TaskStatus.SUCCEEDED, TaskStatus.DEGRADED)
        and obs.get("domain") == "host"
        and obs.get("event_type") == "process_snapshot"
        and len(processes) > 0
        and all("pid" in p and "ppid" in p and "name" in p for p in processes[:5])
        and obs.get("collected_at") is not None
        and obs.get("coverage") is not None
        and isinstance(obs.get("limitations"), list)
    )
    assert_ok(
        "M3-A1",
        "Host process snapshot returns structured PID/PPID/name data with provenance",
        cond,
        f"status={result.status.value}, processes={len(processes)}, domain={obs.get('domain')}",
    )


def test_m3a2_host_file_integrity():
    """M3-A2: File integrity snapshot returns SHA256 hashes and metadata."""
    adapter = HostObserverAdapter()
    # Point to a known small directory
    target = str(ROOT / "core" / "observer")
    req = TaskRequest(
        operation="observer.host.files",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"target_path": target, "max_files": 10},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    files = obs.get("data", {}).get("files", [])

    cond = (
        result.status == TaskStatus.SUCCEEDED
        and obs.get("domain") == "file"
        and obs.get("event_type") == "file_snapshot"
        and len(files) > 0
        and all(
            "sha256" in f and "size" in f and "mtime" in f and "path" in f
            for f in files
        )
        and all(len(f["sha256"]) == 64 for f in files if f["sha256"] != "OMITTED_EXCEEDS_5MB")
        and obs.get("collected_at") is not None
        and obs.get("coverage", {}).get("scanned_files", 0) > 0
    )
    assert_ok(
        "M3-A2",
        "File integrity snapshot returns SHA256 hashes, size, mtime with coverage",
        cond,
        f"files={len(files)}, sample={files[0] if files else 'none'}",
    )


def test_m3a3_host_network_snapshot():
    """M3-A3: Network socket snapshot returns listeners with port/PID."""
    adapter = HostObserverAdapter()
    req = TaskRequest(
        operation="observer.host.network",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    listeners = obs.get("data", {}).get("listeners", [])

    cond = (
        result.status in (TaskStatus.SUCCEEDED, TaskStatus.DEGRADED)
        and obs.get("domain") == "network"
        and obs.get("event_type") == "socket_snapshot"
        and obs.get("collected_at") is not None
        and isinstance(obs.get("limitations"), list)
        and obs.get("coverage") is not None
    )
    # On Windows we expect actual listeners; accept DEGRADED if no listeners but never crash
    if listeners:
        cond = cond and all(
            "local_port" in l and "owning_pid" in l
            for l in listeners[:5]
        )
    assert_ok(
        "M3-A3",
        "Network socket snapshot returns listeners with port/PID or honest DEGRADED",
        cond,
        f"status={result.status.value}, listeners={len(listeners)}",
    )


# ---------------------------------------------------------------------------
# M3-B: Web Observer
# ---------------------------------------------------------------------------

def test_m3b1_web_dns_lookup():
    """M3-B1: DNS lookup resolves a known host."""
    adapter = WebObserverAdapter()
    req = TaskRequest(
        operation="observer.web.dns",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"host": "localhost"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    ips = obs.get("data", {}).get("resolved_ips", [])

    cond = (
        result.status == TaskStatus.SUCCEEDED
        and obs.get("domain") == "web"
        and obs.get("event_type") == "dns_lookup"
        and len(ips) > 0
        and "127.0.0.1" in ips
        and obs.get("collected_at") is not None
    )
    assert_ok(
        "M3-B1",
        "DNS lookup resolves localhost to 127.0.0.1 with structured observation",
        cond,
        f"ips={ips}, domain={obs.get('domain')}",
    )


def test_m3b2_web_dns_unreachable():
    """M3-B2: DNS with unreachable host returns DEGRADED, never crash or false CLEAN."""
    adapter = WebObserverAdapter()
    req = TaskRequest(
        operation="observer.web.dns",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"host": "this-host-will-never-exist-noartex-test.invalid"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})

    cond = (
        result.status == TaskStatus.DEGRADED
        and obs.get("state") in ("DEGRADED", "OBSERVATION_UNAVAILABLE")
        and obs.get("state") != "NO_ACTIVITY_OBSERVED"
        and len(obs.get("limitations", [])) > 0
    )
    assert_ok(
        "M3-B2",
        "Unreachable DNS returns DEGRADED with limitations, never false safe state",
        cond,
        f"status={result.status.value}, state={obs.get('state')}, limitations={obs.get('limitations')}",
    )


def test_m3b3_web_headers_invalid_url():
    """M3-B3: HTTP headers with invalid URL → DENIED (not crash)."""
    adapter = WebObserverAdapter()
    req = TaskRequest(
        operation="observer.web.headers",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"url": "ftp://not-http-protocol.example.com"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    cond = (
        result.status == TaskStatus.DENIED
        and any("http" in o.lower() for o in result.observations)
    )
    assert_ok(
        "M3-B3",
        "HTTP headers with non-HTTP URL returns DENIED (protocol validation)",
        cond,
        f"status={result.status.value}, obs={result.observations}",
    )


def test_m3b4_web_headers_unreachable():
    """M3-B4: HTTP headers with unreachable endpoint → DEGRADED, never clean."""
    adapter = WebObserverAdapter()
    req = TaskRequest(
        operation="observer.web.headers",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"url": "http://192.0.2.1:1"},  # TEST-NET, should fail fast
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})

    cond = (
        result.status == TaskStatus.DEGRADED
        and obs.get("state") in ("DEGRADED", "OBSERVATION_UNAVAILABLE")
        and obs.get("state") != "NO_ACTIVITY_OBSERVED"
    )
    assert_ok(
        "M3-B4",
        "HTTP to unreachable endpoint → DEGRADED with honest state, never false safe",
        cond,
        f"status={result.status.value}, state={obs.get('state')}",
    )


# ---------------------------------------------------------------------------
# M3-C: Agent Observer
# ---------------------------------------------------------------------------

def test_m3c1_agent_activity_summary():
    """M3-C1: Agent activity summary returns task/denial counts from audit log."""
    # Create a temporary audit log and seed it with events
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m3_")
    audit_path = Path(tmp_dir) / "audit.jsonl"
    audit = AuditLog(audit_path)
    # Seed: 3 task requests, 1 completed, 1 denied
    audit.append("TASK_REQUESTED", actor_id="agent:alpha", task_id="t1")
    audit.append("TASK_COMPLETED", actor_id="agent:alpha", task_id="t1")
    audit.append("TASK_REQUESTED", actor_id="agent:alpha", task_id="t2")
    audit.append("TASK_DENIED", actor_id="agent:alpha", task_id="t2")
    audit.append("TASK_REQUESTED", actor_id="agent:alpha", task_id="t3")
    audit.append("TASK_COMPLETED", actor_id="agent:alpha", task_id="t3")

    adapter = AgentObserverAdapter(audit_log=audit)
    req = TaskRequest(
        operation="observer.agent.activity",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"agent_id": "agent:alpha"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    data = obs.get("data", {})

    cond = (
        result.status == TaskStatus.SUCCEEDED
        and obs.get("domain") == "agent"
        and obs.get("event_type") == "agent_activity_summary"
        and data.get("total_requested") == 3
        and data.get("total_denied") == 1
        and data.get("total_completed") == 2
        and obs.get("collected_at") is not None
        and obs.get("confidence") in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
        and obs.get("coverage", {}).get("records_evaluated", 0) > 0
    )
    # Cleanup
    shutil.rmtree(tmp_dir, ignore_errors=True)
    assert_ok(
        "M3-C1",
        "Agent activity summary reports correct task/denial/completion counts",
        cond,
        f"requested={data.get('total_requested')}, denied={data.get('total_denied')}, completed={data.get('total_completed')}",
    )


def test_m3c2_agent_denials_list():
    """M3-C2: Agent denials list captures policy denials with evidence."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m3_")
    audit_path = Path(tmp_dir) / "audit.jsonl"
    audit = AuditLog(audit_path)
    # Seed: multiple denials
    audit.append("TASK_DENIED", actor_id="agent:beta", task_id="t10",
                 data={"reasons": ["unauthorized operation"]})
    audit.append("TASK_DENIED", actor_id="agent:beta", task_id="t11",
                 data={"reasons": ["blocked path"]})
    audit.append("TASK_COMPLETED", actor_id="agent:beta", task_id="t12")

    adapter = AgentObserverAdapter(audit_log=audit)
    req = TaskRequest(
        operation="observer.agent.denials",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"agent_id": "agent:beta"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    obs = result.data.get("observation", {})
    denial_count = obs.get("data", {}).get("denial_count", 0)

    cond = (
        result.status == TaskStatus.SUCCEEDED
        and obs.get("domain") == "agent"
        and obs.get("event_type") == "agent_denials_list"
        and denial_count == 2
        and obs.get("state") == "SUSPICIOUS_ACTIVITY_OBSERVED"  # denials present → suspicious
        and obs.get("collected_at") is not None
        and len(obs.get("evidence", [])) > 0
    )
    shutil.rmtree(tmp_dir, ignore_errors=True)
    assert_ok(
        "M3-C2",
        "Agent denials list captures 2 denials and reports SUSPICIOUS_ACTIVITY_OBSERVED",
        cond,
        f"denial_count={denial_count}, state={obs.get('state')}",
    )


# ---------------------------------------------------------------------------
# M3-D: Unified Observation Model
# ---------------------------------------------------------------------------

def test_m3d1_observation_event_structure():
    """M3-D1: All observations conform to ObservationEvent schema with required fields."""
    # Run all 3 observer types and verify the observation dict structure
    required_fields = {"event_id", "domain", "event_type", "state", "target_scope",
                       "collected_at", "coverage", "limitations", "data", "evidence", "confidence"}

    failures = []

    # Host processes
    adapter_h = HostObserverAdapter()
    req_h = TaskRequest(operation="observer.host.processes",
                        actor=ActorIdentity(agent_id="test:m3"),
                        session_id="sess_m3_test")
    res_h = adapter_h.execute(req_h, _allow_decision(req_h.task_id))
    obs_h = res_h.data.get("observation", {})
    missing_h = required_fields - set(obs_h.keys())
    if missing_h:
        failures.append(f"host.processes missing: {missing_h}")

    # Web DNS
    adapter_w = WebObserverAdapter()
    req_w = TaskRequest(operation="observer.web.dns",
                        actor=ActorIdentity(agent_id="test:m3"),
                        session_id="sess_m3_test",
                        parameters={"host": "localhost"})
    res_w = adapter_w.execute(req_w, _allow_decision(req_w.task_id))
    obs_w = res_w.data.get("observation", {})
    missing_w = required_fields - set(obs_w.keys())
    if missing_w:
        failures.append(f"web.dns missing: {missing_w}")

    # Agent activity (empty audit)
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m3_")
    audit = AuditLog(Path(tmp_dir) / "audit.jsonl")
    adapter_a = AgentObserverAdapter(audit_log=audit)
    req_a = TaskRequest(operation="observer.agent.activity",
                        actor=ActorIdentity(agent_id="test:m3"),
                        session_id="sess_m3_test")
    res_a = adapter_a.execute(req_a, _allow_decision(req_a.task_id))
    obs_a = res_a.data.get("observation", {})
    missing_a = required_fields - set(obs_a.keys())
    if missing_a:
        failures.append(f"agent.activity missing: {missing_a}")
    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = len(failures) == 0
    assert_ok(
        "M3-D1",
        "All observer outputs conform to ObservationEvent schema (12 required fields)",
        cond,
        "; ".join(failures) if failures else "All 3 observations have all required fields",
    )


def test_m3d2_epistemic_states_coverage():
    """M3-D2: The three epistemic states are exercised across test results."""
    # Collect all observation states from other test results:
    # NO_ACTIVITY_OBSERVED: host processes (normal) or web dns (success)
    # DEGRADED: unreachable web target
    # SUSPICIOUS_ACTIVITY_OBSERVED: agent denials with denial events

    valid_states = {s.value for s in ObservationState}

    # 1. NO_ACTIVITY_OBSERVED from successful DNS
    adapter_w = WebObserverAdapter()
    req1 = TaskRequest(operation="observer.web.dns",
                       actor=ActorIdentity(agent_id="test:m3"),
                       session_id="sess_m3_test",
                       parameters={"host": "localhost"})
    res1 = adapter_w.execute(req1, _allow_decision(req1.task_id))
    state1 = res1.data.get("observation", {}).get("state")

    # 2. DEGRADED from failed DNS
    req2 = TaskRequest(operation="observer.web.dns",
                       actor=ActorIdentity(agent_id="test:m3"),
                       session_id="sess_m3_test",
                       parameters={"host": "this-host-does-not-exist.invalid"})
    res2 = adapter_w.execute(req2, _allow_decision(req2.task_id))
    state2 = res2.data.get("observation", {}).get("state")

    # 3. SUSPICIOUS from agent denials
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m3_")
    audit = AuditLog(Path(tmp_dir) / "audit.jsonl")
    audit.append("TASK_DENIED", actor_id="agent:x", task_id="t99")
    adapter_a = AgentObserverAdapter(audit_log=audit)
    req3 = TaskRequest(operation="observer.agent.denials",
                       actor=ActorIdentity(agent_id="test:m3"),
                       session_id="sess_m3_test")
    res3 = adapter_a.execute(req3, _allow_decision(req3.task_id))
    state3 = res3.data.get("observation", {}).get("state")
    shutil.rmtree(tmp_dir, ignore_errors=True)

    observed_states = {state1, state2, state3}

    cond = (
        state1 == "NO_ACTIVITY_OBSERVED"
        and state2 in ("DEGRADED", "OBSERVATION_UNAVAILABLE")
        and state3 == "SUSPICIOUS_ACTIVITY_OBSERVED"
        and observed_states.issubset(valid_states)
    )
    assert_ok(
        "M3-D2",
        "Three epistemic states exercised: NO_ACTIVITY, DEGRADED, SUSPICIOUS",
        cond,
        f"states observed: {state1}, {state2}, {state3}",
    )


def test_m3d3_observation_provenance_fields():
    """M3-D3: Every observation includes coverage, limitations, confidence, collected_at."""
    adapter = HostObserverAdapter()
    req = TaskRequest(
        operation="observer.host.files",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"target_path": str(ROOT / "core" / "observer"), "max_files": 5},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)
    obs = result.data.get("observation", {})

    cond = (
        isinstance(obs.get("coverage"), dict)
        and isinstance(obs.get("limitations"), list)
        and obs.get("confidence") in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
        and obs.get("collected_at") is not None
        and len(obs.get("collected_at", "")) > 10  # ISO timestamp
    )
    assert_ok(
        "M3-D3",
        "Observation includes coverage dict, limitations list, confidence, and ISO collected_at",
        cond,
        f"coverage={obs.get('coverage')}, confidence={obs.get('confidence')}, collected_at={obs.get('collected_at')}",
    )


# ---------------------------------------------------------------------------
# M3-NEG: Negative Tests
# ---------------------------------------------------------------------------

def test_m3_neg1_file_observer_unauthorized_path():
    """M3-NEG1: File observer with path outside authorized roots → DENIED."""
    restricted_meta = AdapterMetadata(
        adapter_id="adapter.observer.host.restricted",
        name="Restricted Host Observer",
        version="1.0.0",
        provenance="test",
        license="MIT",
        author="Tester",
        limits=AdapterLimits(allowed_target_roots=[str(ROOT / "tests")]),
    )
    adapter = HostObserverAdapter(metadata=restricted_meta)
    req = TaskRequest(
        operation="observer.host.files",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"target_path": "C:\\Windows"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    cond = (
        result.status == TaskStatus.DENIED
        and any("outside authorized roots" in o.lower() for o in result.observations)
    )
    assert_ok(
        "M3-NEG1",
        "File observer with unauthorized path returns DENIED (path traversal blocked)",
        cond,
        f"status={result.status.value}, obs={result.observations}",
    )


def test_m3_neg2_file_observer_nonexistent_path():
    """M3-NEG2: File observer with non-existent path → DENIED (validation)."""
    adapter = HostObserverAdapter()
    req = TaskRequest(
        operation="observer.host.files",
        actor=ActorIdentity(agent_id="test:m3"),
        session_id="sess_m3_test",
        parameters={"target_path": "C:\\this_path_absolutely_does_not_exist_m3_42"},
    )
    dec = _allow_decision(req.task_id)
    result = adapter.execute(req, dec)

    cond = (
        result.status == TaskStatus.DENIED
        and any("does not exist" in o.lower() or "rejected" in o.lower() for o in result.observations)
    )
    assert_ok(
        "M3-NEG2",
        "File observer with non-existent path returns DENIED (not crash, not clean)",
        cond,
        f"status={result.status.value}, obs={result.observations}",
    )


# ---------------------------------------------------------------------------
# M3-E2E: End-to-End via CLI
# ---------------------------------------------------------------------------

def test_m3_e2e_cli_observer():
    """M3-E2E: Observer executes end-to-end via CLI with session, policy, audit trail."""
    _, out, _ = run(["session", "create", "--agent", "test:m3e2e", "--format", "json"])
    sid = json.loads(out)["session_id"]

    # Submit observer.host.processes via CLI
    code, out2, err2 = run([
        "task", "submit",
        "--session", sid,
        "--operation", "observer.host.processes",
    ])
    res = json.loads(out2)

    cond_exec = (
        res.get("status") in ("SUCCEEDED", "DEGRADED")
        and "observation" in res.get("data", {})
        and res.get("decision_ref") is not None
    )

    # Verify audit trail
    tid = res.get("task_id", "")
    _, out3, _ = run(["audit", "query", "--task", tid])
    audit_data = json.loads(out3)
    records = audit_data.get("records", [])
    event_types = {r["event_type"] for r in records}

    cond_audit = (
        "TASK_REQUESTED" in event_types
        and "POLICY_EVALUATED" in event_types
        and "TASK_COMPLETED" in event_types
    )

    cond = cond_exec and cond_audit
    assert_ok(
        "M3-E2E",
        "Observer executes E2E via CLI: session → policy → execution → audit trail",
        cond,
        f"exec_ok={cond_exec}, audit_ok={cond_audit}, events={event_types}",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*70}")
    print("  NOARTEX M3 Acceptance & Negative Tests")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*70}\n")

    tests = [
        # M3-A: Host Observer
        test_m3a1_host_process_snapshot,
        test_m3a2_host_file_integrity,
        test_m3a3_host_network_snapshot,
        # M3-B: Web Observer
        test_m3b1_web_dns_lookup,
        test_m3b2_web_dns_unreachable,
        test_m3b3_web_headers_invalid_url,
        test_m3b4_web_headers_unreachable,
        # M3-C: Agent Observer
        test_m3c1_agent_activity_summary,
        test_m3c2_agent_denials_list,
        # M3-D: Unified Model
        test_m3d1_observation_event_structure,
        test_m3d2_epistemic_states_coverage,
        test_m3d3_observation_provenance_fields,
        # M3-NEG: Negative Tests
        test_m3_neg1_file_observer_unauthorized_path,
        test_m3_neg2_file_observer_nonexistent_path,
        # M3-E2E: End-to-End
        test_m3_e2e_cli_observer,
    ]

    for t in tests:
        try:
            t()
        except Exception as exc:
            assert_ok(t.__name__, f"Exception in {t.__name__}", False, str(exc)[:600])

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)

    print(f"\n{'='*70}")
    print(f"  Results: {passed}/{total} PASS  |  {failed} FAIL")
    print(f"{'='*70}\n")

    if failed > 0:
        print("⚠️  M3 has FAILURES — review above")
        sys.exit(1)
    else:
        print("🎉  M3 CLOSED — All observer, model, and negative tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
