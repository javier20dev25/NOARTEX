#!/usr/bin/env python3
"""
NOARTEX M5 Acceptance Tests — Permissions, Approvals, Revocation, Kill Switch & Autonomous Mode
Pruebas ejecutables M5-T1 a M5-T7 según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md
y el requerimiento específico del usuario:
- M5-T1: Matriz de Policy R0–R4 determinista (100% de decisiones esperadas coinciden)
- M5-T2: Flujo Human-in-the-Loop (R3 genera PENDING_APPROVAL, aprobación válida habilita ejecución, audit completo)
- M5-T3: Aprobación inválida (expirada por TTL o fuera de alcance) -> DENIED
- M5-T4: Revocación (revocación de sesión o de aprobación activa -> nuevas acciones denegadas)
- M5-T5: Kill switch de emergencia (global y por dominio -> bloqueo inmediato fail-closed)
- M5-T6: Fail-safe ante caída/indisponibilidad de componentes críticos
- M5-T7: MODO AUTOMÁTICO SIN PERMISOS DEL AGENTE:
  En modo AUTOMATIC, la política del sistema puede auto-aprobar acciones pre-autorizadas
  sin intervención humana, mientras que el agente sigue sin poder auto-otorgarse permisos
  ni saltarse las reglas de la política (fail-closed garantizado para lo no autorizado).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent.parent
NOARTEX_SCRIPT = str(ROOT / "noartex.py")

sys.path.insert(0, str(ROOT))

from core.contracts.models import (
    ActorIdentity,
    AgentType,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskStatus,
)
from core.policy import (
    ApprovalGrant,
    ApprovalManager,
    ApprovalStatus,
    ExecutionMode,
    KillSwitchManager,
    KillSwitchState,
    PolicyEngine,
)

results: list[dict] = []
TEST_DATA_DIR = str(ROOT / "data" / "test_m5")


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
# M5-T1: Full Policy Matrix R0 to R4
# ---------------------------------------------------------------------------

def test_m5t1_policy_matrix_r0_to_r4():
    """M5-T1: Matriz completa de Policy: R0..R4 determinista (100% de decisiones esperadas coinciden)."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_matrix_")
    approvals = ApprovalManager(tmp_dir)
    killswitch = KillSwitchManager(tmp_dir)
    engine = PolicyEngine(execution_mode=ExecutionMode.MANUAL, approval_manager=approvals, killswitch_manager=killswitch)

    actor = ActorIdentity(agent_id="agent:tester")

    # Fixture de pruebas: (operación, decisión esperada, justificación)
    matrix = [
        # R0: Lectura segura -> ALLOW
        ("core.capabilities.list", DecisionKind.ALLOW),
        ("observer.host.processes", DecisionKind.ALLOW),
        ("intelligence.incident.show", DecisionKind.ALLOW),
        # R1: Análisis y recolección -> ALLOW_WITH_CONSTRAINTS
        ("sentinel.sast.scan", DecisionKind.ALLOW_WITH_CONSTRAINTS),
        ("intelligence.correlate", DecisionKind.ALLOW_WITH_CONSTRAINTS),
        ("core.task.status", DecisionKind.ALLOW_WITH_CONSTRAINTS),
        # R2: Cambios reversibles sin aprobación previa en modo MANUAL -> REQUIRE_APPROVAL
        ("defense.artifact.quarantine", DecisionKind.REQUIRE_APPROVAL),
        # R3: Contención / impacto operativo sin aprobación previa en modo MANUAL -> REQUIRE_APPROVAL
        ("defense.host.isolate", DecisionKind.REQUIRE_APPROVAL),
        ("defense.network.block", DecisionKind.REQUIRE_APPROVAL),
        # R4: Remediación crítica sin aprobación previa -> REQUIRE_APPROVAL
        ("defense.host.remediate", DecisionKind.REQUIRE_APPROVAL),
        ("defense.patch.apply", DecisionKind.REQUIRE_APPROVAL),
        # Operación desconocida / no mapeada -> DENY (fail-closed)
        ("unknown.malicious.exploit", DecisionKind.DENY),
    ]

    mismatches = []
    for op, expected_decision in matrix:
        req = TaskRequest(operation=op, actor=actor, session_id="sess_valid")
        dec = engine.evaluate(req, session_active=True)
        if dec.decision != expected_decision:
            mismatches.append(f"{op}: expected {expected_decision.value}, got {dec.decision.value}")

    # Verificar también que sin sesión activa -> DENY para todo
    req_nosess = TaskRequest(operation="core.capabilities.list", actor=actor, session_id="sess_expired")
    dec_nosess = engine.evaluate(req_nosess, session_active=False)
    if dec_nosess.decision != DecisionKind.DENY:
        mismatches.append(f"No session check failed: got {dec_nosess.decision.value}")

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = len(mismatches) == 0
    assert_ok(
        "M5-T1",
        "Deterministic Policy Matrix R0-R4 achieves 100% expected decisions (ALLOW, CONSTRAINTS, REQUIRE_APPROVAL, DENY)",
        cond,
        "; ".join(mismatches) if mismatches else "All matrix evaluations matched perfectly",
    )


# ---------------------------------------------------------------------------
# M5-T2: Human-in-the-Loop Approval Flow
# ---------------------------------------------------------------------------

def test_m5t2_human_in_the_loop_approval_flow():
    """M5-T2: Tarea privilegiada R3 genera REQUIRE_APPROVAL; tras aprobación humana explícita, se autoriza."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_hitl_")
    approvals = ApprovalManager(tmp_dir)
    engine = PolicyEngine(execution_mode=ExecutionMode.MANUAL, approval_manager=approvals)

    actor = ActorIdentity(agent_id="agent:operator")
    req = TaskRequest(
        operation="defense.host.isolate",
        actor=actor,
        session_id="sess_valid",
        parameters={"target_host": "server-01.internal"},
    )

    # 1. Invocación inicial sin token de aprobación -> REQUIRE_APPROVAL
    dec1 = engine.evaluate(req, session_active=True)
    step1_ok = dec1.decision == DecisionKind.REQUIRE_APPROVAL

    # 2. Operador humano revisa y emite token de aprobación explícito
    grant = approvals.grant(
        task_id=req.task_id,
        operation="defense.host.isolate",
        approver="human:admin_security",
        approver_type="human",
        scope={"target_host": "server-01.internal"},
        ttl_seconds=300,
    )

    # 3. Re-dispatch con token de aprobación en parameters
    req.parameters["approval_id"] = grant.approval_id
    dec2 = engine.evaluate(req, session_active=True)
    step2_ok = (
        dec2.decision == DecisionKind.ALLOW_WITH_CONSTRAINTS
        and dec2.approver == "human:admin_security"
    )

    # 4. Intento de re-uso del mismo token (replay attack prevention: token consumido)
    req_replay = TaskRequest(
        operation="defense.host.isolate",
        actor=actor,
        session_id="sess_valid",
        parameters={"approval_id": grant.approval_id},
    )
    dec3 = engine.evaluate(req_replay, session_active=True)
    step3_ok = dec3.decision == DecisionKind.DENY and "already been used" in dec3.reasons[0].lower()

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = step1_ok and step2_ok and step3_ok
    assert_ok(
        "M5-T2",
        "Human-in-the-loop approval: PENDING -> GRANTED -> ONE-TIME CONSUMPTION (replay prevented)",
        cond,
        f"step1_require_appr={step1_ok}, step2_allowed={step2_ok}, step3_replay_denied={step3_ok}",
    )


# ---------------------------------------------------------------------------
# M5-T3: Expired or Out-of-Scope Approvals Rejected
# ---------------------------------------------------------------------------

def test_m5t3_expired_or_out_of_scope_approval_rejected():
    """M5-T3: Aprobación expirada por TTL o usada para una operación distinta -> DENIED."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_exp_")
    approvals = ApprovalManager(tmp_dir)
    engine = PolicyEngine(execution_mode=ExecutionMode.MANUAL, approval_manager=approvals)

    actor = ActorIdentity(agent_id="agent:tester")

    # A) Aprobación con TTL negativo / expirada
    grant_exp = approvals.grant(
        task_id="task_target",
        operation="defense.network.block",
        approver="human:admin",
        ttl_seconds=-10,  # ya expirada
    )
    req_exp = TaskRequest(
        operation="defense.network.block",
        actor=actor,
        session_id="sess_valid",
        task_id="task_target",
        parameters={"approval_id": grant_exp.approval_id},
    )
    dec_exp = engine.evaluate(req_exp, session_active=True)
    cond_exp = dec_exp.decision == DecisionKind.DENY and "expired" in dec_exp.reasons[0].lower()

    # B) Aprobación emitida para una operación pero usada para otra (scope violation)
    grant_scope = approvals.grant(
        task_id="task_scoped",
        operation="defense.artifact.quarantine",
        approver="human:admin",
        ttl_seconds=300,
    )
    req_scope = TaskRequest(
        operation="defense.host.isolate",  # operacion distinta!
        actor=actor,
        session_id="sess_valid",
        task_id="task_scoped",
        parameters={"approval_id": grant_scope.approval_id},
    )
    dec_scope = engine.evaluate(req_scope, session_active=True)
    cond_scope = dec_scope.decision == DecisionKind.DENY and "scoped to operation" in dec_scope.reasons[0].lower()

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = cond_exp and cond_scope
    assert_ok(
        "M5-T3",
        "Expired and out-of-scope approvals strictly return DENIED",
        cond,
        f"expired_rejected={cond_exp}, scope_violation_rejected={cond_scope}",
    )


# ---------------------------------------------------------------------------
# M5-T4: Revocation (Session & Approvals)
# ---------------------------------------------------------------------------

def test_m5t4_revocation_session_and_approvals():
    """M5-T4: Revocación activa de sesiones o aprobaciones bloquea de inmediato nuevas acciones."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_rev_")
    approvals = ApprovalManager(tmp_dir)
    engine = PolicyEngine(execution_mode=ExecutionMode.MANUAL, approval_manager=approvals)

    # 1. Revocación de Aprobación
    grant = approvals.grant(
        task_id="task_to_revoke",
        operation="defense.host.isolate",
        approver="human:admin",
        ttl_seconds=600,
    )
    # Revocar la aprobación antes de que el agente la use
    revoked_ok = approvals.revoke(grant.approval_id, revoker="security_lead")

    req = TaskRequest(
        operation="defense.host.isolate",
        actor=ActorIdentity(agent_id="agent:tester"),
        session_id="sess_valid",
        task_id="task_to_revoke",
        parameters={"approval_id": grant.approval_id},
    )
    dec = engine.evaluate(req, session_active=True)

    cond_appr_revoked = (
        revoked_ok
        and dec.decision == DecisionKind.DENY
        and "revoked" in dec.reasons[0].lower()
    )

    # 2. Revocación de Sesión
    req_sess = TaskRequest(operation="core.capabilities.list", actor=ActorIdentity(agent_id="agent:tester"), session_id="sess_revoked")
    dec_sess = engine.evaluate(req_sess, session_active=False)  # sesión revocada
    cond_sess_revoked = dec_sess.decision == DecisionKind.DENY

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = cond_appr_revoked and cond_sess_revoked
    assert_ok(
        "M5-T4",
        "Revocation of approvals and sessions immediately takes effect and denies further tasks",
        cond,
        f"approval_revocation_ok={cond_appr_revoked}, session_revocation_ok={cond_sess_revoked}",
    )


# ---------------------------------------------------------------------------
# M5-T5: Emergency Kill Switch
# ---------------------------------------------------------------------------

def test_m5t5_emergency_kill_switch():
    """M5-T5: Kill switch de emergencia global o por dominio bloquea de inmediato (fail-closed)."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_kill_")
    killswitch = KillSwitchManager(tmp_dir)
    engine = PolicyEngine(killswitch_manager=killswitch)

    actor = ActorIdentity(agent_id="agent:tester")

    # 1. Estado normal (sin kill switch): R0 permitido
    req1 = TaskRequest(operation="observer.host.processes", actor=actor, session_id="sess_valid")
    dec1 = engine.evaluate(req1, session_active=True)
    cond1 = dec1.decision == DecisionKind.ALLOW

    # 2. Activar Kill Switch Global
    st = killswitch.activate(scope="global", activated_by="incident_commander", reason="Containment drill")
    dec2 = engine.evaluate(req1, session_active=True)
    cond2 = dec2.decision == DecisionKind.DENY and "global kill switch" in dec2.reasons[0].lower()

    # 3. Desactivar Global y Activar solo para dominio 'defense'
    killswitch.deactivate(scope="global")
    killswitch.activate(scope="defense", activated_by="lead_sec", reason="Locking down defense tools")

    # R0 observer sigue permitido:
    dec_obs = engine.evaluate(req1, session_active=True)
    cond_obs_allowed = dec_obs.decision == DecisionKind.ALLOW

    # Operación de dominio 'defense' bloqueada:
    req_def = TaskRequest(operation="defense.host.isolate", actor=actor, session_id="sess_valid")
    dec_def = engine.evaluate(req_def, session_active=True)
    cond_def_blocked = dec_def.decision == DecisionKind.DENY and "domain kill switch" in dec_def.reasons[0].lower()

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = cond1 and cond2 and cond_obs_allowed and cond_def_blocked
    assert_ok(
        "M5-T5",
        "Kill switch activates globally and per-domain, immediately enforcing fail-closed block",
        cond,
        f"normal_ok={cond1}, global_blocked={cond2}, domain_scoped_block={cond_def_blocked}",
    )


# ---------------------------------------------------------------------------
# M5-T6: Fail-Safe on Engine / Store Disruption
# ---------------------------------------------------------------------------

def test_m5t6_failsafe_disruption():
    """M5-T6: Ante fallo o indisponibilidad de subsistemas de política -> DENY por defecto (fail-closed)."""
    # Motor de política sin approval manager intentando validar un R3 que dice tener approval
    engine_orphan = PolicyEngine(approval_manager=None)
    req = TaskRequest(
        operation="defense.host.isolate",
        actor=ActorIdentity(agent_id="agent:tester"),
        session_id="sess_valid",
        parameters={"approval_id": "appr_fake_123"},
    )
    dec = engine_orphan.evaluate(req, session_active=True)

    # Invariante: Nunca permite la acción si el validador no está disponible
    cond = dec.decision in (DecisionKind.REQUIRE_APPROVAL, DecisionKind.DENY)
    assert_ok(
        "M5-T6",
        "Fail-safe: Disruption or missing subsystem falls back safely to REQUIRE_APPROVAL/DENY (never bypass)",
        cond,
        f"decision={dec.decision.value}, reasons={dec.reasons}",
    )


# ---------------------------------------------------------------------------
# M5-T7: Autonomous Mode ("Sin Permisos del Agente")
# ---------------------------------------------------------------------------

def test_m5t7_autonomous_mode_governed_without_agent_permissions():
    """
    M5-T7: MODO AUTOMÁTICO SIN PERMISOS DEL AGENTE (Requerimiento Clave del Usuario).
    El sistema puede auto-aprobar acciones pre-autorizadas en modo AUTOMATIC
    sin intervención humana, pero el agente NO tiene permisos propios ni puede
    auto-aprobarse nada fuera de las reglas del Policy Engine.
    """
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m5_auto_")
    approvals = ApprovalManager(tmp_dir)

    # Configurar el Policy Engine en modo AUTOMATIC con un conjunto estricto de operaciones pre-autorizadas
    pre_approved_ops = {"defense.artifact.quarantine", "defense.artifact.tag"}
    engine_auto = PolicyEngine(
        execution_mode=ExecutionMode.AUTOMATIC,
        approval_manager=approvals,
        auto_approved_operations=pre_approved_ops,
    )

    actor = ActorIdentity(agent_id="agent:autonomous_defender")

    # Caso A: Operación pre-autorizada en política -> ALLOW_WITH_CONSTRAINTS emitida por el sistema
    req_pre = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=actor,
        session_id="sess_valid",
        parameters={"artifact_hash": "sha256_dummy_malware"},
    )
    dec_pre = engine_auto.evaluate(req_pre, session_active=True)
    cond_a = (
        dec_pre.decision == DecisionKind.ALLOW_WITH_CONSTRAINTS
        and dec_pre.approver == "policy:automatic_rule"
        and "AUTOMATIC mode" in dec_pre.reasons[0]
    )

    # Caso B: Operación NO pre-autorizada (ej. aislamiento drástico de red o remediación)
    # El agente NO puede auto-aprobarse esto. Sigue requiriendo aprobación humana explícita.
    req_not_pre = TaskRequest(
        operation="defense.host.remediate",
        actor=actor,
        session_id="sess_valid",
    )
    dec_not_pre = engine_auto.evaluate(req_not_pre, session_active=True)
    cond_b = dec_not_pre.decision == DecisionKind.REQUIRE_APPROVAL

    # Caso C: Agente intenta inyectar su propio token o engañar al Policy Engine ("auto-otorgarse permisos")
    req_spoof = TaskRequest(
        operation="defense.host.isolate",
        actor=actor,
        session_id="sess_valid",
        parameters={"approval_id": "appr_agent_invented_self_grant"},
    )
    dec_spoof = engine_auto.evaluate(req_spoof, session_active=True)
    cond_c = dec_spoof.decision == DecisionKind.DENY and "not found" in dec_spoof.reasons[0].lower()

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = cond_a and cond_b and cond_c
    assert_ok(
        "M5-T7",
        "Autonomous Mode operates without human click for pre-approved policy, while agent NEVER self-approves (fail-closed)",
        cond,
        f"auto_approved_ok={cond_a}, unapproved_requires_human={cond_b}, agent_self_grant_blocked={cond_c}",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*75}")
    print("  NOARTEX M5 Acceptance Tests (Permissions, Approvals, Kill Switch & Auto Mode)")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*75}\n")

    tests = [
        test_m5t1_policy_matrix_r0_to_r4,
        test_m5t2_human_in_the_loop_approval_flow,
        test_m5t3_expired_or_out_of_scope_approval_rejected,
        test_m5t4_revocation_session_and_approvals,
        test_m5t5_emergency_kill_switch,
        test_m5t6_failsafe_disruption,
        test_m5t7_autonomous_mode_governed_without_agent_permissions,
    ]

    for t in tests:
        try:
            t()
        except Exception as exc:
            assert_ok(t.__name__, f"Exception in {t.__name__}", False, str(exc)[:600])

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)

    print(f"\n{'='*75}")
    print(f"  Results: {passed}/{total} PASS  |  {failed} FAIL")
    print(f"{'='*75}\n")

    if failed > 0:
        print("⚠️  M5 has FAILURES — review above")
        sys.exit(1)
    else:
        print("🎉  M5 CLOSED — All permissions, approvals, kill switch, and autonomous mode tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
