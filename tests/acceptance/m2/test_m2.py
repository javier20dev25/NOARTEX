#!/usr/bin/env python3
"""
NOARTEX M2 Acceptance & Negative Tests
Pruebas ejecutables M2-A, M2-B, M2-C según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md
Verifica:
  - Framework común de adaptadores (AdapterInterface)
  - Descubrimiento e integración de Sentinel CLI
  - Fallos controlados, degradación honesta y pruebas negativas (M2-C)
  - Prevención de Path Traversal y rechazo de sintaxis insegura
  - Trazabilidad y gobernanza de Policy Engine
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent.parent
NOARTEX_SCRIPT = str(ROOT / "noartex.py")

sys.path.insert(0, str(ROOT))

from core.adapters.base import AdapterInterface, AdapterLimits, AdapterMetadata, AdapterStatus
from adapters.sentinel_cli.adapter import SentinelCLIAdapter
from core.contracts.models import (
    ActorIdentity,
    AgentType,
    DecisionKind,
    PolicyDecision,
    TaskRequest,
    TaskStatus,
)

results: list[dict] = []
TEST_DATA_DIR = str(ROOT / "data" / "test_m2")


def run(args: list[str], extra_env: Optional[dict] = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["NOARTEX_DATA_DIR"] = TEST_DATA_DIR
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, NOARTEX_SCRIPT] + args,
        capture_output=True, text=True, env=env,
        cwd=str(ROOT)
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
        for line in detail[:400].split("\n"):
            print(f"       {line}")
    return cond


# ---------------------------------------------------------------------------
# M2-A: Adapter Framework
# ---------------------------------------------------------------------------

def test_m2_framework_contract():
    """M2-A1: SentinelCLIAdapter hereda de AdapterInterface y cumple los métodos requeridos."""
    adapter = SentinelCLIAdapter()
    cond = (
        isinstance(adapter, AdapterInterface)
        and hasattr(adapter, "describe_capabilities")
        and hasattr(adapter, "health")
        and hasattr(adapter, "execute")
        and adapter.metadata.adapter_id == "adapter.sentinel.cli"
    )
    assert_ok("M2-A1", "SentinelCLIAdapter implements AdapterInterface contract", cond)


def test_m2_framework_metadata():
    """M2-A2: Metadatos declarativos obligatorios (licencia, autor, procedencia, límites)."""
    meta = SentinelCLIAdapter.DEFAULT_METADATA
    cond = (
        bool(meta.adapter_id)
        and bool(meta.version)
        and bool(meta.provenance)
        and bool(meta.license)
        and meta.limits.timeout_seconds > 0
    )
    assert_ok("M2-A2", "Adapter metadata declares provenance, license, and execution limits", cond)


# ---------------------------------------------------------------------------
# M2-B: Sentinel CLI Discovery & Execution
# ---------------------------------------------------------------------------

def test_m2_discovery_capabilities():
    """M2-B1: noartex capabilities expone capacidades de Sentinel CLI."""
    code, out, _ = run(["capabilities", "--format", "json"])
    data = json.loads(out)
    cap_ids = {c["capability_id"] for c in data.get("capabilities", [])}
    expected = {
        "sentinel.sast.scan",
        "sentinel.cicd.audit",
        "sentinel.supply_chain.audit",
        "sentinel.report.generate",
    }
    cond = expected.issubset(cap_ids)
    assert_ok("M2-B1", "Discovery includes all 4 Sentinel CLI capabilities", cond, f"found: {cap_ids}")


def test_m2_sast_scan_execution():
    """M2-B2: Ejecución exitosa de sentinel.sast.scan bajo sesión autorizada."""
    _, out, _ = run(["session", "create", "--agent", "test:sast", "--format", "json"])
    sid = json.loads(out)["session_id"]

    target = str(ROOT / "core" / "contracts")
    code2, out2, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "sentinel.sast.scan",
        "--params", json.dumps({"target_path": target}),
    ])
    res = json.loads(out2)
    cond = (
        res.get("status") == "SUCCEEDED"
        and "findings_count" in res.get("data", {})
        and len(res.get("evidence", [])) > 0
        and res.get("decision_ref") is not None
    )
    assert_ok("M2-B2", "sentinel.sast.scan executes and returns structured findings", cond, str(res)[:300])


# ---------------------------------------------------------------------------
# M2-C: Negative Testing, Failure Handling & Honest Degradation
# ---------------------------------------------------------------------------

def test_m2_neg_missing_binary():
    """M2-C1: Binario no instalado -> UNAVAILABLE, NUNCA 'CLEAN' ni crash."""
    mock_adapter = SentinelCLIAdapter(binary_path=str(ROOT / "nonexistent" / "sentinel_missing_binary"))
    req = TaskRequest(
        operation="sentinel.sast.scan",
        actor=ActorIdentity(agent_id="test"),
        session_id="sess_mock",
        parameters={"target_path": str(ROOT)},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW)
    res = mock_adapter.execute(req, dec)

    cond = (
        res.status == TaskStatus.UNAVAILABLE
        and "not installed" in res.observations[0].lower()
        and "cannot assert security state" in res.limitations[0].lower()
    )
    assert_ok("M2-C1", "Missing binary returns UNAVAILABLE without asserting clean", cond, str(res)[:300])


def test_m2_neg_nonexistent_target_path():
    """M2-C2: Ruta objetivo inexistente -> DENIED (validación estricta de ruta)."""
    adapter = SentinelCLIAdapter()
    req = TaskRequest(
        operation="sentinel.sast.scan",
        actor=ActorIdentity(agent_id="test"),
        session_id="sess_mock",
        parameters={"target_path": str(ROOT / "nonexistent_dir_12345")},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW)
    res = adapter.execute(req, dec)

    cond = (
        res.status == TaskStatus.DENIED
        and "validation failed" in res.observations[0].lower()
    )
    assert_ok("M2-C2", "Non-existent target path returns DENIED", cond, str(res)[:300])


def test_m2_neg_path_traversal_blocked():
    """M2-C3: Intento de Path Traversal fuera de raíces autorizadas -> Bloqueado."""
    # Configurar adaptador con límite de raíz estricto solo a tests/
    restricted_limits = AdapterLimits(allowed_target_roots=[str(ROOT / "tests")])
    restricted_meta = AdapterMetadata(
        adapter_id="adapter.sentinel.restricted",
        name="Restricted Sentinel",
        version="1.0.0",
        provenance="internal",
        license="MIT",
        author="Tester",
        limits=restricted_limits,
    )
    adapter = SentinelCLIAdapter(metadata=restricted_meta)

    # Intentar escanear un directorio fuera de la raíz autorizada (tests/)
    req = TaskRequest(
        operation="sentinel.sast.scan",
        actor=ActorIdentity(agent_id="test"),
        session_id="sess_mock",
        parameters={"target_path": str(ROOT / "core")},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW)
    res = adapter.execute(req, dec)

    cond = (
        res.status == TaskStatus.DENIED
        and "outside authorized roots" in res.observations[0].lower()
    )
    assert_ok("M2-C3", "Path traversal outside authorized root returns DENIED", cond, str(res)[:300])


def test_m2_neg_malicious_package_name():
    """M2-C4: Inyección en nombre de paquete en supply_chain.audit -> Rechazado."""
    adapter = SentinelCLIAdapter()
    req = TaskRequest(
        operation="sentinel.supply_chain.audit",
        actor=ActorIdentity(agent_id="test"),
        session_id="sess_mock",
        parameters={"package": "malicious; rm -rf / && calc.exe"},
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW)
    res = adapter.execute(req, dec)

    cond = (
        res.status == TaskStatus.DENIED
        and "invalid package name syntax" in res.observations[0].lower()
    )
    assert_ok("M2-C4", "Malicious package syntax injection attempt returns DENIED", cond, str(res)[:300])


def test_m2_neg_unauthorized_operation():
    """M2-C5: Operación no soportada por el adaptador -> DENIED."""
    adapter = SentinelCLIAdapter()
    req = TaskRequest(
        operation="sentinel.unknown.exploit",
        actor=ActorIdentity(agent_id="test"),
        session_id="sess_mock",
    )
    dec = PolicyDecision(task_id=req.task_id, decision=DecisionKind.ALLOW)
    res = adapter.execute(req, dec)

    cond = (
        res.status == TaskStatus.DENIED
        and "not supported" in res.observations[0].lower()
    )
    assert_ok("M2-C5", "Unsupported adapter operation returns DENIED", cond, str(res)[:300])


def test_m2_audit_trail_integrity():
    """M2-C6: Toda tarea de adaptador genera traza completa en Audit Log."""
    _, out, _ = run(["session", "create", "--agent", "test:audit", "--format", "json"])
    sid = json.loads(out)["session_id"]
    target = str(ROOT / "core" / "contracts")

    _, out2, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "sentinel.sast.scan",
        "--params", json.dumps({"target_path": target}),
    ])
    tid = json.loads(out2)["task_id"]

    _, out3, _ = run(["audit", "query", "--task", tid])
    audit_data = json.loads(out3)
    records = audit_data.get("records", [])
    event_types = {r["event_type"] for r in records}

    cond = (
        "TASK_REQUESTED" in event_types
        and "POLICY_EVALUATED" in event_types
        and "TASK_COMPLETED" in event_types
        and any(r.get("data", {}).get("adapter_id") == "adapter.sentinel.cli" for r in records)
    )
    assert_ok("M2-C6", "Full audit trail links request, policy evaluation, and adapter execution", cond, str(records)[:300])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*60}")
    print("  NOARTEX M2 Acceptance & Negative Tests")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*60}\n")

    tests = [
        test_m2_framework_contract,
        test_m2_framework_metadata,
        test_m2_discovery_capabilities,
        test_m2_sast_scan_execution,
        test_m2_neg_missing_binary,
        test_m2_neg_nonexistent_target_path,
        test_m2_neg_path_traversal_blocked,
        test_m2_neg_malicious_package_name,
        test_m2_neg_unauthorized_operation,
        test_m2_audit_trail_integrity,
    ]

    for t in tests:
        try:
            t()
        except Exception as exc:
            assert_ok(t.__name__, f"Exception in {t.__name__}", False, str(exc))

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)

    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} PASS  |  {failed} FAIL")
    print(f"{'='*60}\n")

    if failed > 0:
        sys.exit(1)
    else:
        print("🎉  M2 CLOSED — All adapter contract, execution & negative tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
