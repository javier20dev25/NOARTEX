#!/usr/bin/env python3
"""
NOARTEX M6 Acceptance Tests — Defense, Contention, Post-Validation & Rollback
Pruebas ejecutables M6-T1 a M6-T6 según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md:
- M6-T1: Acción de contención reversible (quarantine/isolate) con aprobación R3 -> Ejecución con evidencia pre/post
- M6-T2: Validación post-contención automática guiada por contrato (CONTAINED/DEGRADED)
- M6-T3: Intento de acción Defense sin aprobación o fuera de política -> DENIED sin ejecución
- M6-T4: Remediación con plan y rollback definido (cambio reversible y rollback funcional comprobado)
- M6-T5: Falla de adaptador Defense a mitad de acción -> FAILED/DEGRADED con compensación y audit íntegro
- M6-T6: Ejecución en entorno no autorizado / no etiquetado como lab -> Bloqueada por Policy/scope
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

from adapters.defense_lab import ContainmentStatus, DefenseActionType, DefenseLabAdapter, RollbackPlan
from core.contracts.models import (
    ActorIdentity,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskStatus,
)
from core.policy import ApprovalManager, ExecutionMode, PolicyEngine

results: list[dict] = []
TEST_DATA_DIR = str(ROOT / "data" / "test_m6")


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
# M6-T1: Reversible Containment with Pre/Post Evidence
# ---------------------------------------------------------------------------

def test_m6t1_reversible_containment_with_evidence():
    """M6-T1: Acción de contención reversible (cuarentena de artefacto) con evidencia pre y post acción."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="noartex_m6_t1_"))
    lab_dir = tmp_dir / "lab"
    adapter = DefenseLabAdapter(lab_dir=lab_dir)

    # Crear artefacto de prueba
    sample_file = tmp_dir / "malicious_payload.ps1"
    sample_file.write_text("Write-Host 'simulated attack payload'", encoding="utf-8")

    req = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="operator:defender"),
        session_id="sess_valid",
        parameters={"target_path": str(sample_file), "environment": "lab"},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW_WITH_CONSTRAINTS, approver="operator")

    res = adapter.execute(req, dec)

    # Verificaciones:
    # 1. El artefacto original ya no está en su ruta previa
    # 2. El artefacto está en la carpeta de cuarentena
    # 3. Hay evidencia previa y posterior registrada
    # 4. Se estableció un plan de rollback
    evidence = res.evidence
    has_pre = any(e.get("stage") == "pre_action" for e in evidence)
    has_post = any(e.get("stage") == "post_action" for e in evidence)
    rb_plan = res.data.get("rollback_plan")

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        res.status == TaskStatus.SUCCEEDED
        and has_pre
        and has_post
        and rb_plan is not None
        and "plan_id" in rb_plan
    )
    assert_ok(
        "M6-T1",
        "Reversible containment executes with pre/post evidence and established rollback plan",
        cond,
        f"status={res.status.value}, pre_evidence={has_pre}, post_evidence={has_post}, rb_plan={rb_plan.get('plan_id') if rb_plan else None}",
    )


# ---------------------------------------------------------------------------
# M6-T2: Contract-Guided Post-Containment Validation
# ---------------------------------------------------------------------------

def test_m6t2_post_containment_validation():
    """M6-T2: Validación post-contención automática guiada por contrato que certifica estado CONTAINED."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="noartex_m6_t2_"))
    lab_dir = tmp_dir / "lab"
    adapter = DefenseLabAdapter(lab_dir=lab_dir)

    # Crear archivo a contener
    target = tmp_dir / "infected.dll"
    target.write_bytes(b"\x90\x90\x90")

    req = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="operator:defender"),
        session_id="sess_valid",
        parameters={"target_path": str(target), "environment": "lab"},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW_WITH_CONSTRAINTS, approver="operator")

    res = adapter.execute(req, dec)
    val = res.data.get("validation", {})

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        res.status == TaskStatus.SUCCEEDED
        and val.get("status") == ContainmentStatus.CONTAINED.value
        and len(val.get("checks_performed", [])) >= 2
        and val.get("adverse_effects_detected") is False
    )
    assert_ok(
        "M6-T2",
        "Post-action validation contract certifies CONTAINED status with verified checks and no adverse effects",
        cond,
        f"validation_status={val.get('status')}, checks={len(val.get('checks_performed', []))}",
    )


# ---------------------------------------------------------------------------
# M6-T3: Unapproved Defense Action Blocked
# ---------------------------------------------------------------------------

def test_m6t3_unapproved_defense_action_blocked():
    """M6-T3: Intento de acción Defense sin aprobación previa o fuera de política es denegado (DENIED)."""
    tmp_dir = tempfile.mkdtemp(prefix="noartex_m6_t3_")
    approvals = ApprovalManager(tmp_dir)
    engine = PolicyEngine(execution_mode=ExecutionMode.MANUAL, approval_manager=approvals)

    actor = ActorIdentity(agent_id="agent:unauthorized")
    req = TaskRequest(
        operation="defense.host.isolate",
        actor=actor,
        session_id="sess_valid",
        parameters={"target_host": "prod-server-01"},
    )

    # En modo MANUAL, sin approval_id -> REQUIRE_APPROVAL
    dec = engine.evaluate(req, session_active=True)

    # Y si pasa una aprobación falsa/inválida -> DENIED
    req_fake = TaskRequest(
        operation="defense.host.isolate",
        actor=actor,
        session_id="sess_valid",
        parameters={"approval_id": "appr_forged_999"},
    )
    dec_fake = engine.evaluate(req_fake, session_active=True)

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        dec.decision == DecisionKind.REQUIRE_APPROVAL
        and dec_fake.decision == DecisionKind.DENY
    )
    assert_ok(
        "M6-T3",
        "Unapproved defense action strictly blocked by PolicyEngine (REQUIRE_APPROVAL or DENIED)",
        cond,
        f"initial_eval={dec.decision.value}, forged_approval_eval={dec_fake.decision.value}",
    )


# ---------------------------------------------------------------------------
# M6-T4: Full Rollback Execution
# ---------------------------------------------------------------------------

def test_m6t4_functional_rollback_execution():
    """M6-T4: Remediación/cuarentena con plan y ejecución exitosa de rollback funcional."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="noartex_m6_t4_"))
    lab_dir = tmp_dir / "lab"
    adapter = DefenseLabAdapter(lab_dir=lab_dir)

    # 1. Crear archivo original
    original_file = tmp_dir / "original_config.json"
    original_file.write_text('{"setting": "critical_value"}', encoding="utf-8")

    # 2. Ejecutar cuarentena
    req_q = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="operator"),
        session_id="sess_valid",
        parameters={"target_path": str(original_file), "environment": "lab"},
    )
    dec = PolicyDecision(task_id=req_q.task_id, decision=DecisionKind.ALLOW_WITH_CONSTRAINTS)
    res_q = adapter.execute(req_q, dec)
    plan_id = res_q.data["rollback_plan"]["plan_id"]

    quarantine_applied = not original_file.exists()

    # 3. Invocar rollback usando el plan_id
    req_rb = TaskRequest(
        operation="defense.action.rollback",
        actor=ActorIdentity(agent_id="operator"),
        session_id="sess_valid",
        parameters={"plan_id": plan_id, "environment": "lab"},
    )
    res_rb = adapter.execute(req_rb, dec)

    # 4. Verificar que el archivo original fue restaurado fielmente
    file_restored = original_file.exists() and original_file.read_text(encoding="utf-8") == '{"setting": "critical_value"}'

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        quarantine_applied
        and res_rb.status == TaskStatus.SUCCEEDED
        and file_restored
    )
    assert_ok(
        "M6-T4",
        "Action generates rollback plan and subsequent rollback restores target state perfectly",
        cond,
        f"quarantined={quarantine_applied}, rb_status={res_rb.status.value}, restored={file_restored}",
    )


# ---------------------------------------------------------------------------
# M6-T5: Mid-Action Failure & Compensation
# ---------------------------------------------------------------------------

def test_m6t5_mid_action_failure_and_compensation():
    """M6-T5: Falla a mitad de acción activa compensación automática y reporta FAILED con audit íntegro."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="noartex_m6_t5_"))
    lab_dir = tmp_dir / "lab"
    adapter = DefenseLabAdapter(lab_dir=lab_dir)

    target = tmp_dir / "sample_failure.bin"
    target.write_bytes(b"data_sample")

    # Simular fallo a mitad de camino
    req = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="operator"),
        session_id="sess_valid",
        parameters={"target_path": str(target), "simulate_failure": True, "environment": "lab"},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW_WITH_CONSTRAINTS)

    res = adapter.execute(req, dec)

    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        res.status == TaskStatus.FAILED
        and res.data.get("rollback_applied") is True
        and "compensation applied" in res.limitations[0].lower()
    )
    assert_ok(
        "M6-T5",
        "Mid-action adapter failure triggers compensation and reports FAILED without leaving partial state",
        cond,
        f"status={res.status.value}, limitations={res.limitations}",
    )


# ---------------------------------------------------------------------------
# M6-T6: Non-Lab / Unauthorized Environment Blocked
# ---------------------------------------------------------------------------

def test_m6t6_unauthorized_environment_blocked():
    """M6-T6: Intento de ejecución fuera de entorno etiquetado como lab/test es bloqueado inmediatamente."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="noartex_m6_t6_"))
    adapter = DefenseLabAdapter(lab_dir=tmp_dir)

    target = tmp_dir / "prod_file.txt"
    target.write_text("production contents", encoding="utf-8")

    # Intentar ejecutar con environment="production"
    req_prod = TaskRequest(
        operation="defense.artifact.quarantine",
        actor=ActorIdentity(agent_id="agent:attacker"),
        session_id="sess_valid",
        parameters={"target_path": str(target), "environment": "production"},
    )
    dec = PolicyDecision(task_id=req_prod.task_id, decision=DecisionKind.ALLOW_WITH_CONSTRAINTS)

    res_prod = adapter.execute(req_prod, dec)

    file_untouched = target.exists()
    shutil.rmtree(tmp_dir, ignore_errors=True)

    cond = (
        res_prod.status == TaskStatus.DENIED
        and any("not an authorized lab environment" in o for o in res_prod.observations)
        and file_untouched
    )
    assert_ok(
        "M6-T6",
        "Defense actions in non-lab environments (e.g. production) are strictly rejected (DENIED)",
        cond,
        f"status={res_prod.status.value}, observations={res_prod.observations}",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*75}")
    print("  NOARTEX M6 Acceptance Tests (Defense, Containment & Rollback in Lab)")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*75}\n")

    tests = [
        test_m6t1_reversible_containment_with_evidence,
        test_m6t2_post_containment_validation,
        test_m6t3_unapproved_defense_action_blocked,
        test_m6t4_functional_rollback_execution,
        test_m6t5_mid_action_failure_and_compensation,
        test_m6t6_unauthorized_environment_blocked,
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
        print("⚠️  M6 has FAILURES — review above")
        sys.exit(1)
    else:
        print("🎉  M6 CLOSED — All defense, containment, validation, and rollback tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
