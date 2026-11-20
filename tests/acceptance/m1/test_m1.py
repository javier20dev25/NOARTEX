#!/usr/bin/env python3
"""
NOARTEX M1 Acceptance Tests
Pruebas ejecutables M1-T1 .. M1-T10 según NOARTEX_PRODUCT_ARCHITECTURE_AND_ACCEPTANCE_SPEC_001.md
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

PASS_MARK = "✅ PASS"
FAIL_MARK = "❌ FAIL"
results: list[dict] = []

TEST_DATA_DIR = str(ROOT / "data" / "test_acceptance")


def run(args: list[str], extra_env: Optional[dict] = None) -> tuple[int, str, str]:
    """Runs: python noartex.py <args>"""
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
# Tests
# ---------------------------------------------------------------------------

def test_m1_t1():
    """M1-T1: noartex --help → code 0, lista comandos core"""
    code, out, err = run(["--help"])
    cond = (
        code == 0
        and "doctor" in out
        and "capabilities" in out
        and "session" in out
        and "task" in out
        and "audit" in out
    )
    assert_ok("M1-T1", "CLI --help exits 0 and lists core commands",
               cond, f"code={code}\n{out[:300]}")


def test_m1_t2():
    """M1-T2: noartex doctor --format json → valid JSON, no fatal errors"""
    code, out, err = run(["doctor", "--format", "json"])
    if code != 0:
        assert_ok("M1-T2", "doctor --format json returns valid JSON", False,
                  f"code={code} err={err[:200]}")
        return
    try:
        data = json.loads(out)
        cond = (
            "overall" in data
            and "components" in data
            and data["overall"] in ("ok", "degraded")
            and "core" in data["components"]
        )
        assert_ok("M1-T2", "doctor --format json → valid JSON with components",
                  cond, str(data)[:300])
    except json.JSONDecodeError as e:
        assert_ok("M1-T2", "doctor --format json → valid JSON", False, str(e))


def test_m1_t3():
    """M1-T3: noartex capabilities --format json → lista con capability_id/risk/availability"""
    code, out, err = run(["capabilities", "--format", "json"])
    if code != 0:
        assert_ok("M1-T3", "capabilities --format json returns valid JSON", False,
                  f"code={code} err={err[:200]}")
        return
    try:
        data = json.loads(out)
        caps = data.get("capabilities", [])
        cond = (
            len(caps) > 0
            and all("capability_id" in c for c in caps)
            and all("risk" in c for c in caps)
            and all("availability" in c for c in caps)
        )
        assert_ok("M1-T3", f"capabilities → {len(caps)} capabilities with required fields",
                  cond, f"first: {caps[0] if caps else 'none'}")
    except json.JSONDecodeError as e:
        assert_ok("M1-T3", "capabilities --format json → valid JSON", False, str(e))


def test_m1_t4():
    """M1-T4: session create + session show"""
    code, out, err = run(["session", "create", "--agent", "opencode:local", "--format", "json"])
    if code != 0:
        assert_ok("M1-T4", "session create returns valid session", False,
                  f"code={code} err={err[:200]}")
        return
    try:
        sess = json.loads(out)
        sid = sess.get("session_id", "")
        cond = bool(sid) and "agent_id" in sess and sess.get("state") == "ACTIVE"
        assert_ok("M1-T4a", "session create → session_id + state=ACTIVE", cond, str(sess))

        # show
        code2, out2, err2 = run(["session", "show", sid])
        try:
            sess2 = json.loads(out2)
            assert_ok("M1-T4b", "session show retrieves created session",
                       sess2.get("session_id") == sid)
        except Exception:
            assert_ok("M1-T4b", "session show retrieves created session", False, out2[:200])
    except json.JSONDecodeError as e:
        assert_ok("M1-T4", "session create JSON", False, str(e))


def test_m1_t5():
    """M1-T5: task submit (R0 operation) → SUCCEEDED"""
    _, out, _ = run(["session", "create", "--agent", "test:agent", "--format", "json"])
    sess = json.loads(out)
    sid = sess["session_id"]

    code2, out2, err2 = run([
        "task", "submit",
        "--session", sid,
        "--operation", "core.capabilities.list",
    ])
    if code2 != 0:
        assert_ok("M1-T5", "task submit R0 → SUCCEEDED", False,
                  f"code={code2} err={err2[:200]}")
        return
    try:
        result = json.loads(out2)
        cond = (
            "task_id" in result
            and result.get("status") == "SUCCEEDED"
            and "decision_ref" in result
        )
        assert_ok("M1-T5", "task submit R0 → status=SUCCEEDED + task_id + decision_ref",
                  cond, str(result)[:300])
    except json.JSONDecodeError as e:
        assert_ok("M1-T5", "task submit R0 JSON", False, str(e))


def test_m1_t6():
    """M1-T6: audit query --task → TASK_REQUESTED + POLICY_EVALUATED + TASK_COMPLETED"""
    _, out, _ = run(["session", "create", "--agent", "audit:test", "--format", "json"])
    sess = json.loads(out)
    sid = sess["session_id"]
    _, out2, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "core.doctor.health",
    ])
    result = json.loads(out2)
    tid = result.get("task_id", "")

    code3, out3, err3 = run(["audit", "query", "--task", tid])
    if code3 != 0:
        assert_ok("M1-T6", "audit query --task returns records", False, err3[:200])
        return
    try:
        data = json.loads(out3)
        records = data.get("records", [])
        event_types = {r["event_type"] for r in records}
        cond = (
            "TASK_REQUESTED" in event_types
            and "POLICY_EVALUATED" in event_types
            and "TASK_COMPLETED" in event_types
        )
        assert_ok("M1-T6", "audit → TASK_REQUESTED+POLICY_EVALUATED+TASK_COMPLETED present",
                  cond, f"events={event_types}")
    except json.JSONDecodeError as e:
        assert_ok("M1-T6", "audit query JSON", False, str(e))


def test_m1_t7():
    """M1-T7: task submit de operación privilegiada sin aprobación → DENIED o PENDING_APPROVAL (no ejecución)"""
    _, out, _ = run(["session", "create", "--agent", "deny:test", "--format", "json"])
    sess = json.loads(out)
    sid = sess["session_id"]
    _, out2, _ = run([
        "task", "submit",
        "--session", sid,
        "--operation", "defense.host.isolate",
    ])
    try:
        result = json.loads(out2)
        cond = result.get("status") in ("DENIED", "UNAVAILABLE", "PENDING_APPROVAL")
        assert_ok("M1-T7", "privileged operation without approval → DENIED/PENDING_APPROVAL (no execution)",
                  cond, f"status={result.get('status')}")
    except json.JSONDecodeError as e:
        assert_ok("M1-T7", "denied operation JSON", False, str(e))


def test_m1_t8():
    """M1-T8: sin Sentinel → doctor reporta limitación, core sigue operativo"""
    code, out, _ = run(["doctor", "--format", "json"])
    try:
        data = json.loads(out)
        sentinel = (
            data.get("components", {}).get("adapter.sentinel.cli")
            or data.get("components", {}).get("sentinel_adapter", {})
        )
        overall_ok = data.get("overall") in ("ok", "degraded")
        cond = overall_ok and str(sentinel.get("status", "")).lower() in ("not_installed", "available", "unavailable")
        assert_ok("M1-T8", "without Sentinel → core OK, absence reported not fatal",
                  cond, f"overall={data.get('overall')} sentinel={sentinel}")
    except json.JSONDecodeError as e:
        assert_ok("M1-T8", "without Sentinel JSON", False, str(e))


def test_m1_t9():
    """M1-T9: skill portable existe y referencia comandos noartex"""
    skill_path = ROOT / "skills" / "canonical" / "SKILL.md"
    cond = skill_path.exists()
    if cond:
        content = skill_path.read_text(encoding="utf-8")
        cond = (
            "noartex capabilities" in content
            and "noartex doctor" in content
            and "noartex session" in content
        )
    assert_ok("M1-T9", "portable skill exists and references noartex commands",
               cond, str(skill_path))


def test_m1_t10():
    """M1-T10: core opera sin claves LLM (modo no interactivo)"""
    no_llm = {
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "GEMINI_API_KEY": "",
    }
    code, out, err = run(["doctor", "--format", "json"], extra_env=no_llm)
    try:
        data = json.loads(out)
        cond = code == 0 and "overall" in data
        assert_ok("M1-T10", "core operates without LLM keys (non-interactive mode)",
                  cond, f"code={code}")
    except Exception as e:
        assert_ok("M1-T10", "core without LLM keys", False, str(e))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*60}")
    print("  NOARTEX M1 Acceptance Tests")
    print(f"  Root: {ROOT}")
    print(f"  Data: {TEST_DATA_DIR}")
    print(f"{'='*60}\n")

    tests = [
        test_m1_t1, test_m1_t2, test_m1_t3, test_m1_t4,
        test_m1_t5, test_m1_t6, test_m1_t7, test_m1_t8,
        test_m1_t9, test_m1_t10,
    ]
    for t in tests:
        try:
            t()
        except Exception as exc:
            test_name = t.__name__.replace("test_", "").upper().replace("_", "-")
            assert_ok(test_name, f"Unexpected error in {t.__name__}", False, str(exc))

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)

    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} PASS  |  {failed} FAIL")
    print(f"{'='*60}\n")

    if failed > 0:
        print("Failed tests:")
        for r in results:
            if r["status"] == "FAIL":
                print(f"  ❌ {r['id']}: {r['description']}")
                if r.get("detail"):
                    print(f"     {r['detail'][:200]}")
        sys.exit(1)
    else:
        print("🎉  M1 CLOSED — All acceptance tests PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
