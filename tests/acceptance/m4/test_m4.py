#!/usr/bin/env python3
"""
NOARTEX M4 Acceptance Tests — Intelligence & Incident Management
Pruebas ejecutables M4-T1 a M4-T5 según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md

Verifica:
  - M4-T1: Ingesta de conjunto de eventos/evidencias y correlación en timeline
  - M4-T2: Manejo de evidencia insuficiente o contradictoria (UNKNOWN / PARTIAL) con brechas explícitas
  - M4-T3: Diferenciación de False Positive conocido (trazable, no eliminación silenciosa)
  - M4-T4: Validación estricta de esquema JSON Schema de TriageVerdict
  - M4-T5: Consulta de incidente con historial completo (hipótesis, notas, veredictos)
  - M4-E2E: Flujo E2E vía CLI y gobernanza en Audit Log
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

import jsonschema

ROOT = Path(__file__).resolve().parent.parent.parent.parent
NOARTEX_SCRIPT = str(ROOT / "noartex.py")

sys.path.insert(0, str(ROOT))

from core.contracts.models import ActorIdentity, AgentType, DecisionKind, PolicyDecision, TaskRequest, TaskStatus
from core.intelligence import (
    ConfidenceLevel,
    EvidenceItem,
    EventCorrelator,
    Incident,
    IncidentState,
    IncidentStore,
    Severity,
    TimelineEvent,
    TriageEngine,
    TriageVerdict,
    VerdictClassification,
)
from core.observer.models import ObservationDomain, ObservationEvent, ObservationState

results: list[dict] = []
TEST_DATA_DIR = str(ROOT / "data" / "test_m4")


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
# M4-T1: Correlation and Timeline
# ---------------------------------------------------------------------------

def test_m4t1_correlation_and_timeline():
    """M4-T1: Ingesta de conjunto de eventos/evidencias y correlación en timeline e incidente."""
    correlator = EventCorrelator()

    # Fixture de observaciones heterogéneas
    obs_host = {
        "event_id": "obs_host_101",
        "domain": "host",
        "event_type": "process_snapshot",
        "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value,
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:00:10Z",
        "confidence": "HIGH",
        "data": {"pid": 4040, "name": "powershell.exe", "cmdline": "powershell -enc malicious_base64"},
    }
    obs_net = {
        "event_id": "obs_net_102",
        "domain": "network",
        "event_type": "socket_snapshot",
        "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value,
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:00:15Z",
        "confidence": "HIGH",
        "data": {"local_port": 4444, "owning_pid": 4040, "state": "LISTEN"},
    }
    finding_sast = {
        "id": "find_sast_201",
        "rule_id": "sentinel.sast.suspicious_process_spawn",
        "severity": "HIGH",
        "detected_at": "2026-11-19T20:00:05Z",
        "message": "Potential reverse shell spawn detected in deployment script",
    }
    audit_event = {
        "event_type": "TASK_DENIED",
        "actor_id": "agent:malicious_probe",
        "timestamp": "2026-11-19T20:00:20Z",
        "task_id": "task_denied_301",
        "data": {"reasons": ["Attempted defense.host.remediate without authorization"]},
    }

    result = correlator.correlate(
        observations=[obs_host, obs_net],
        findings=[finding_sast],
        audit_records=[audit_event],
    )

    timeline = result.get("timeline", [])
    evidence = result.get("evidence", [])
    summary = result.get("summary", {})

    # Verificaciones:
    # 1. Timeline ordenado cronológicamente (05s -> 10s -> 15s -> 20s)
    timestamps = [t.timestamp for t in timeline]
    is_chronological = timestamps == sorted(timestamps)

    # 2. Toda evidencia está referenciada y preservada
    evidence_ids = {e.evidence_id for e in evidence}
    timeline_refs = {t.evidence_ref for t in timeline if t.evidence_ref}

    cond = (
        len(evidence) == 4
        and len(timeline) == 4
        and is_chronological
        and timeline_refs.issubset(evidence_ids)
        and summary.get("total_evidence") == 4
        and summary.get("total_timeline_events") == 4
    )
    assert_ok(
        "M4-T1",
        "Ingests multi-source fixture and builds chronologically ordered timeline with evidence refs",
        cond,
        f"evidence_count={len(evidence)}, timeline_count={len(timeline)}, is_chrono={is_chronological}",
    )


# ---------------------------------------------------------------------------
# M4-T2: Insufficient or Contradictory Evidence Handling
# ---------------------------------------------------------------------------

def test_m4t2_insufficient_or_contradictory_evidence():
    """M4-T2: Casos con evidencia contradictoria o insuficiente emiten UNKNOWN o PARTIAL con razones."""
    correlator = EventCorrelator()
    triage = TriageEngine()

    # Caso A: Señales contradictorias (mismo target reportado como SUSPICIOUS y NO_ACTIVITY)
    obs_susp = {
        "event_id": "obs_s1",
        "domain": "host",
        "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value,
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:10:00Z",
    }
    obs_clean = {
        "event_id": "obs_c1",
        "domain": "host",
        "state": ObservationState.NO_ACTIVITY_OBSERVED.value,
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:10:05Z",
    }
    corr_a = correlator.correlate(observations=[obs_susp, obs_clean])
    inc_a = Incident(
        incident_id="inc_contra_1",
        title="Contradictory Signals Test",
        evidence=corr_a["evidence"],
        timeline=corr_a["timeline"],
        uncertainty=corr_a["uncertainty"],
    )
    verdict_a = triage.evaluate(inc_a)

    cond_a = (
        verdict_a.classification == VerdictClassification.UNKNOWN
        and len(verdict_a.uncertainty["contradictions"]) > 0
        and "contradictory" in verdict_a.summary.lower()
    )

    # Caso B: Cobertura degradada / sensores caídos (insuficiente visibilidad)
    obs_deg1 = {
        "event_id": "obs_d1",
        "domain": "host",
        "state": ObservationState.OBSERVATION_UNAVAILABLE.value,
        "limitations": ["PowerShell CIM connection refused"],
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:11:00Z",
    }
    obs_deg2 = {
        "event_id": "obs_d2",
        "domain": "network",
        "state": ObservationState.DEGRADED.value,
        "limitations": ["Network socket collector timeout"],
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:11:05Z",
    }
    corr_b = correlator.correlate(observations=[obs_deg1, obs_deg2])
    inc_b = Incident(
        incident_id="inc_degraded_2",
        title="Degraded Sensors Test",
        evidence=corr_b["evidence"],
        timeline=corr_b["timeline"],
        uncertainty=corr_b["uncertainty"],
    )
    verdict_b = triage.evaluate(inc_b)

    cond_b = (
        verdict_b.classification == VerdictClassification.UNKNOWN
        and len(verdict_b.uncertainty["coverage_gaps"]) > 0
        and len(verdict_b.uncertainty["epistemic_limitations"]) > 0
    )

    # Caso C: Señal sospechosa pero con brechas de cobertura (visibilidad parcial)
    obs_partial_susp = {
        "event_id": "obs_p1",
        "domain": "host",
        "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value,
        "target_scope": "localhost",
        "collected_at": "2026-11-19T20:12:00Z",
    }
    obs_partial_deg = {
        "event_id": "obs_p2",
        "domain": "web",
        "state": ObservationState.DEGRADED.value,
        "limitations": ["DNS gateway unreachable"],
        "target_scope": "api.domain.test",
        "collected_at": "2026-11-19T20:12:05Z",
    }
    corr_c = correlator.correlate(observations=[obs_partial_susp, obs_partial_deg])
    inc_c = Incident(
        incident_id="inc_partial_3",
        title="Partial Coverage Test",
        evidence=corr_c["evidence"],
        timeline=corr_c["timeline"],
        uncertainty=corr_c["uncertainty"],
    )
    verdict_c = triage.evaluate(inc_c)

    cond_c = (
        verdict_c.classification == VerdictClassification.PARTIAL
        and len(verdict_c.uncertainty["coverage_gaps"]) > 0
    )

    cond = cond_a and cond_b and cond_c
    assert_ok(
        "M4-T2",
        "Contradictory and insufficient evidence cases classified as UNKNOWN/PARTIAL with explicit gaps",
        cond,
        f"contra_verdict={verdict_a.classification.value}, degraded_verdict={verdict_b.classification.value}, partial_verdict={verdict_c.classification.value}",
    )


# ---------------------------------------------------------------------------
# M4-T3: Known False Positive Traceability
# ---------------------------------------------------------------------------

def test_m4t3_known_false_positive_traceable():
    """M4-T3: Diferenciación de False Positive conocido con justificación y evidencia preservada."""
    triage = TriageEngine()

    ev_fp = EvidenceItem(
        evidence_id="ev_fp_001",
        source_type="sast_finding",
        source_ref="rule_eval_test_exec",
        content={
            "is_false_positive": True,
            "fp_rule_id": "FP_MOCK_TEST_HARNESS",
            "fp_justification": "Test execution of benign mock script in tests/ directory.",
            "original_finding": "Eval called in test runner",
        },
        collected_at="2026-11-19T20:20:00Z",
    )
    tl_fp = TimelineEvent(
        timestamp="2026-11-19T20:20:00Z",
        event_type="security_finding",
        description="Eval called in test runner",
        evidence_ref="ev_fp_001",
    )

    inc = Incident(
        incident_id="inc_fp_test_10",
        title="Test Runner Eval Invocation",
        tags=["known_false_positive"],
        evidence=[ev_fp],
        timeline=[tl_fp],
    )

    verdict = triage.evaluate(inc)

    # Invariante M4-T3:
    # 1. Clasificado como FALSE_POSITIVE
    # 2. false_positive_rationale presente con rule_id, justification, original_finding
    # 3. La evidencia NO se eliminó silenciosamente: ev_fp_001 sigue en evidence_refs y timeline
    cond = (
        verdict.classification == VerdictClassification.FALSE_POSITIVE
        and verdict.false_positive_rationale is not None
        and bool(verdict.false_positive_rationale.get("rule_id"))
        and bool(verdict.false_positive_rationale.get("justification"))
        and "ev_fp_001" in verdict.evidence_refs
        and len(verdict.timeline) > 0
    )
    assert_ok(
        "M4-T3",
        "Known False Positive classified as FALSE_POSITIVE with rationale and preserved evidence",
        cond,
        f"classification={verdict.classification.value}, fp_rationale={verdict.false_positive_rationale}, evidence_preserved={'ev_fp_001' in verdict.evidence_refs}",
    )


# ---------------------------------------------------------------------------
# M4-T4: Triage Verdict JSON Schema Validation
# ---------------------------------------------------------------------------

def test_m4t4_schema_validation():
    """M4-T4: Validación estricta del esquema JSON Schema para TriageVerdict."""
    schema_file = ROOT / "schemas" / "triage_verdict.json"
    with open(schema_file, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # 1. Instancia válida
    valid_verdict = TriageVerdict(
        verdict_id="vrd_123456789abc",
        incident_id="inc_abcdef123456",
        classification=VerdictClassification.CONFIRMED,
        severity=Severity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        summary="Confirmed threat with multiple corroborating signals",
        evidence_refs=["ev_1", "ev_2"],
        timeline=[
            {"timestamp": "2026-11-19T20:30:00Z", "event_type": "finding", "description": "Alert detected"}
        ],
        uncertainty={
            "coverage_gaps": [],
            "contradictions": [],
            "epistemic_limitations": [],
        },
        recommended_actions=[
            {"action": "isolate_host", "risk_level": "R3", "description": "Isolate affected host"}
        ],
    )
    # Debe validar sin excepción
    valid_dict = valid_verdict.to_dict()
    jsonschema.validate(instance=valid_dict, schema=schema)

    # 2. Instancia inválida (debe fallar la validación con jsonschema.ValidationError)
    invalid_dict = valid_dict.copy()
    invalid_dict["classification"] = "INVALID_VERDICT_STATE"
    validation_failed = False
    try:
        jsonschema.validate(instance=invalid_dict, schema=schema)
    except jsonschema.ValidationError:
        validation_failed = True

    cond = validation_failed
    assert_ok(
        "M4-T4",
        "TriageVerdict validates strictly against schemas/triage_verdict.json (passes valid, rejects invalid)",
        cond,
        "Schema successfully validated valid verdict and rejected invalid classification enum",
    )


# ---------------------------------------------------------------------------
# M4-T5: Incident Query and History
# ---------------------------------------------------------------------------

def test_m4t5_incident_query_history():
    """M4-T5: Consulta de incidente con recuperación completa de hipótesis, notas, evidencia y veredicto."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m4_inc_")
    store = IncidentStore(tmp_dir)

    # Crear incidente
    inc = store.create(
        title="Supply Chain Anomaly Investigation",
        severity=Severity.HIGH,
        owner="operator:alice",
        hypotheses=["Hypothesis 1: Malicious dependency injected into build pipeline"],
        tags=["supply_chain", "npm"],
    )
    iid = inc.incident_id

    # Agregar nota operativa
    store.add_note(iid, author="agent:triage", note="Checked lockfile and found untracked postinstall script.")

    # Agregar evidencia
    ev = EvidenceItem(
        evidence_id="ev_sc_001",
        source_type="supply_chain_audit",
        source_ref="pkg_evil_util",
        content={"package": "evil-util", "version": "1.0.0", "threat": "DATA_EXFILTRATION"},
    )
    store.add_evidence(iid, ev)

    # Guardar veredicto
    verdict = TriageVerdict(
        verdict_id="vrd_777888999aaa",
        incident_id=iid,
        classification=VerdictClassification.CONFIRMED,
        severity=Severity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        summary="Confirmed malicious package evil-util in dependency tree.",
        evidence_refs=["ev_sc_001"],
    )
    store.save_verdict(verdict)

    # Recuperar desde un nuevo store (probando persistencia en disco)
    store2 = IncidentStore(tmp_dir)
    recovered = store2.get(iid)

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        recovered is not None
        and recovered.incident_id == iid
        and len(recovered.hypotheses) == 1
        and len(recovered.notes) == 1
        and len(recovered.evidence) == 1
        and recovered.evidence[0].evidence_id == "ev_sc_001"
        and recovered.latest_verdict is not None
        and recovered.latest_verdict.classification == VerdictClassification.CONFIRMED
        and len(recovered.timeline) >= 4  # created, note_added, evidence_attached, verdict_issued
    )
    assert_ok(
        "M4-T5",
        "Incident query faithfully recovers hypotheses, notes, evidence, timeline, and triage verdict",
        cond,
        f"recovered_notes={len(recovered.notes) if recovered else 0}, recovered_timeline={len(recovered.timeline) if recovered else 0}",
    )


# ---------------------------------------------------------------------------
# M4-E2E: End-to-End Workflow via CLI & Policy Governance
# ---------------------------------------------------------------------------

def test_m4_e2e_cli_flow():
    """M4-E2E: Flujo completo de inteligencia vía CLI con sesiones, Policy y Audit Log."""
    # 1. Crear sesión de agente
    _, out_s, _ = run(["session", "create", "--agent", "agent:analyst", "--type", "codex", "--format", "json"])
    sid = json.loads(out_s)["session_id"]

    # 2. Crear incidente vía task submit
    code_c, out_c, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "intelligence.incident.create",
        "--params", json.dumps({"title": "E2E Investigation Case", "severity": "HIGH"}),
    ])
    res_c = json.loads(out_c)
    iid = res_c["data"]["incident"]["incident_id"]

    # 3. Evaluar triage vía task submit
    code_t, out_t, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "intelligence.triage.evaluate",
        "--params", json.dumps({"incident_id": iid}),
    ])
    res_t = json.loads(out_t)
    verdict = res_t["data"]["verdict"]

    # 4. Verificar consulta de auditoría
    task_id = res_t["task_id"]
    _, out_a, _ = run(["audit", "query", "--task", task_id])
    audit_data = json.loads(out_a)
    records = audit_data.get("records", [])
    event_types = {r["event_type"] for r in records}

    cond = (
        res_c["status"] == "SUCCEEDED"
        and res_t["status"] == "SUCCEEDED"
        and verdict["incident_id"] == iid
        and "TASK_REQUESTED" in event_types
        and "POLICY_EVALUATED" in event_types
        and "TASK_COMPLETED" in event_types
    )
    assert_ok(
        "M4-E2E",
        "Full Intelligence workflow executes E2E via CLI with session, policy, and audit trail",
        cond,
        f"create_status={res_c.get('status')}, triage_status={res_t.get('status')}, audit_events={event_types}",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*70}")
    print("  NOARTEX M4 Acceptance Tests (Intelligence & Incident Management)")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*70}\n")

    tests = [
        test_m4t1_correlation_and_timeline,
        test_m4t2_insufficient_or_contradictory_evidence,
        test_m4t3_known_false_positive_traceable,
        test_m4t4_schema_validation,
        test_m4t5_incident_query_history,
        test_m4_e2e_cli_flow,
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
        print("⚠️  M4 has FAILURES — review above")
        sys.exit(1)
    else:
        print("🎉  M4 CLOSED — All correlation, incident, triage, and schema tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
