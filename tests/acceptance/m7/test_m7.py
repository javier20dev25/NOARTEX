"""
NOARTEX — M7 Acceptance Tests: Memory Layer
Tests M7-T1 through M7-T5.
Run: python tests/acceptance/m7/test_m7.py
"""
from __future__ import annotations

import json
import os
import sys
import shutil
import tempfile
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root on sys.path
# ---------------------------------------------------------------------------
_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_root))

from core.memory.case_manager import CaseManager
from core.memory.models import NotableSource, FollowUpState, CaseState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
_results: list[tuple[str, str, str]] = []


def check(name: str, cond: bool, detail: str = ""):
    status = PASS if cond else FAIL
    _results.append((name, status, detail))
    icon = "✅" if cond else "❌"
    suffix = f"  ({detail})" if detail and not cond else ""
    print(f"  {icon} {name}{suffix}")


def run_test(name: str, fn):
    print(f"\n--- {name} ---")
    try:
        fn()
    except Exception as exc:
        _results.append((name, FAIL, str(exc)))
        print(f"  ❌ EXCEPTION: {exc}")
        traceback.print_exc()


def _days_ago_iso(n: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=n)
    return dt.isoformat()


def _future_iso(minutes: int = 60) -> str:
    dt = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return dt.isoformat()


def _past_iso(minutes: int = 1) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# M7-T1: Case Creation, Notes, Evidence, FollowUps — all linked by case_id
# ---------------------------------------------------------------------------

def test_m7_t1():
    with tempfile.TemporaryDirectory() as tmp:
        cm = CaseManager(Path(tmp))

        # Create case
        case = cm.create_case(
            title="Suspicious exfiltration attempt",
            description="Agent codex:local accessed /etc/passwd repeatedly",
            severity="high",
            actor="codex:local",
            tags=["exfiltration", "credential-access"],
            incident_ref="inc_abc123",
        )
        check("M7-T1: case_id assigned", case.case_id.startswith("case_"))
        check("M7-T1: state=OPEN", case.state.value == "OPEN")
        check("M7-T1: tags preserved", "exfiltration" in case.tags)
        check("M7-T1: incident_ref linked", case.incident_ref == "inc_abc123")

        # Add human note
        note_h = cm.add_note(
            case_id=case.case_id,
            source=NotableSource.HUMAN,
            author="operator@noartex",
            content="Investigating the unauthorized read pattern",
        )
        check("M7-T1: human note_id", note_h.note_id.startswith("note_"))
        check("M7-T1: note linked to case", note_h.case_id == case.case_id)
        check("M7-T1: note source=HUMAN", note_h.source.value == "human")

        # Add agent note
        note_a = cm.add_note(
            case_id=case.case_id,
            source=NotableSource.AGENT,
            author="antigravity:0.6",
            content="Found 14 accesses in audit log between 02:00-03:00 UTC",
        )
        check("M7-T1: agent note_id", note_a.note_id.startswith("note_"))
        check("M7-T1: agent note source=AGENT", note_a.source.value == "agent")

        # Add evidence
        ev = cm.add_evidence(
            case_id=case.case_id,
            title="Audit log snippet",
            source="audit.jsonl",
            content='{"event":"FILE_READ","path":"/etc/passwd","pid":1234}',
        )
        check("M7-T1: evidence_id", ev.evidence_id.startswith("ev_"))
        check("M7-T1: evidence hash is sha256", len(ev.hash) == 64)
        check("M7-T1: evidence linked to case", ev.case_id == case.case_id)

        # Add follow-up
        fu = cm.add_followup(
            case_id=case.case_id,
            title="Block agent session",
            assignee="operator@noartex",
            due_at=_future_iso(120),
        )
        check("M7-T1: followup_id", fu.followup_id.startswith("fu_"))
        check("M7-T1: followup state=OPEN", fu.state.value == "OPEN")
        check("M7-T1: followup linked to case", fu.case_id == case.case_id)

        # Retrieve and verify all linked by case_id
        retrieved = cm.get_case(case.case_id)
        check("M7-T1: get_case returns case", retrieved is not None)
        check("M7-T1: retrieved case matches", retrieved.case_id == case.case_id)

        notes_for_case = [n for n in cm._notes.values() if n.case_id == case.case_id]
        check("M7-T1: 2 notes linked", len(notes_for_case) == 2)

        ev_for_case = [e for e in cm._evidence.values() if e.case_id == case.case_id]
        check("M7-T1: 1 evidence linked", len(ev_for_case) == 1)

        fu_for_case = cm.list_followups(case.case_id)
        check("M7-T1: 1 followup linked", len(fu_for_case) == 1)


# ---------------------------------------------------------------------------
# M7-T2: Structured Query with Filters and Pagination
# ---------------------------------------------------------------------------

def test_m7_t2():
    with tempfile.TemporaryDirectory() as tmp:
        cm = CaseManager(Path(tmp))

        # Create diverse cases
        cm.create_case("Alpha exfil", "desc", "critical", "agent:alpha", ["exfil", "creds"])
        cm.create_case("Beta lateral", "desc", "high", "agent:beta", ["lateral-movement"])
        cm.create_case("Alpha persistence", "desc", "critical", "agent:alpha", ["persistence"])
        cm.create_case("Gamma recon", "desc", "medium", "agent:gamma", ["recon"])
        cm.create_case("Alpha low", "desc", "low", "agent:alpha", ["info-gather"])

        # Query by actor
        r = cm.query(actor="agent:alpha")
        check("M7-T2: actor filter returns 3", r["total"] == 3)
        check("M7-T2: all results are alpha", all(c["actor"] == "agent:alpha" for c in r["items"]))

        # Query by severity
        r = cm.query(severity="critical")
        check("M7-T2: severity=critical returns 2", r["total"] == 2)

        # Query by tag
        r = cm.query(tag="exfil")
        check("M7-T2: tag=exfil returns 1", r["total"] == 1)

        # Pagination: limit=2, offset=0
        r = cm.query(limit=2, offset=0)
        check("M7-T2: pagination limit=2 returns 2 items", len(r["items"]) == 2)
        check("M7-T2: pagination total=5", r["total"] == 5)
        check("M7-T2: pagination offset preserved", r["offset"] == 0)

        # Pagination: limit=2, offset=4 → 1 item
        r = cm.query(limit=2, offset=4)
        check("M7-T2: pagination offset=4 returns 1 item", len(r["items"]) == 1)
        check("M7-T2: pagination metadata has limit/offset", r["limit"] == 2 and r["offset"] == 4)

        # Query by state
        r = cm.query(state="OPEN")
        check("M7-T2: state=OPEN returns all 5", r["total"] == 5)


# ---------------------------------------------------------------------------
# M7-T3: Follow-up Tracking with State and Due Dates
# ---------------------------------------------------------------------------

def test_m7_t3():
    with tempfile.TemporaryDirectory() as tmp:
        cm = CaseManager(Path(tmp))

        case = cm.create_case("Tracking test", "desc", "medium", "agent:test", [])

        # Add follow-ups
        fu1 = cm.add_followup(case.case_id, "Isolate host", assignee="analyst1", due_at=_future_iso(60))
        fu2 = cm.add_followup(case.case_id, "Collect RAM dump", assignee="analyst2", due_at=_future_iso(120))

        # Update state transitions
        fu1 = cm.update_followup_state(fu1.followup_id, FollowUpState.IN_PROGRESS)
        check("M7-T3: state=IN_PROGRESS", fu1.state.value == "IN_PROGRESS")

        fu1 = cm.update_followup_state(fu1.followup_id, FollowUpState.CLOSED)
        check("M7-T3: state=CLOSED", fu1.state.value == "CLOSED")

        # List follow-ups for case
        fus = cm.list_followups(case.case_id)
        check("M7-T3: list returns 2 followups", len(fus) == 2)

        # Overdue follow-ups: add one with past due_at
        fu_overdue = cm.add_followup(
            case.case_id,
            title="Overdue task",
            assignee="analyst3",
            due_at=_past_iso(30),
        )
        check("M7-T3: overdue fu state=OPEN", fu_overdue.state.value == "OPEN")
        overdue = cm.list_overdue_followups()
        overdue_ids = [f.followup_id for f in overdue]
        check("M7-T3: fu2 not overdue (future)", fu2.followup_id not in overdue_ids)
        check("M7-T3: overdue fu in list", fu_overdue.followup_id in overdue_ids)
        check("M7-T3: closed fu1 not overdue", fu1.followup_id not in overdue_ids)


# ---------------------------------------------------------------------------
# M7-T4: Export Case with Evidence Integrity
# ---------------------------------------------------------------------------

def test_m7_t4():
    with tempfile.TemporaryDirectory() as tmp:
        cm = CaseManager(Path(tmp))

        case = cm.create_case("Export test", "Export verification", "low", "agent:export", ["export"])
        cm.add_note(case.case_id, NotableSource.HUMAN, "analyst", "Initial note")
        cm.add_note(case.case_id, NotableSource.AGENT, "bot:1", "Automated observation")
        ev = cm.add_evidence(case.case_id, "Network capture", "pcap", "192.168.1.1 → 10.0.0.1")
        cm.add_followup(case.case_id, "Verify network path", due_at=_future_iso(60))

        export = cm.export_case(case.case_id)

        # Structure checks
        check("M7-T4: export has 'case'", "case" in export)
        check("M7-T4: export has 'notes'", "notes" in export)
        check("M7-T4: export has 'evidence'", "evidence" in export)
        check("M7-T4: export has 'followups'", "followups" in export)
        check("M7-T4: export has 'export_hash'", "export_hash" in export)
        check("M7-T4: export_hash is SHA256 (64 hex)", len(export["export_hash"]) == 64)
        check("M7-T4: 2 notes in export", len(export["notes"]) == 2)
        check("M7-T4: 1 evidence in export", len(export["evidence"]) == 1)
        check("M7-T4: 1 followup in export", len(export["followups"]) == 1)

        # Reproducibility: same content → same hash
        export2 = cm.export_case(case.case_id)
        check("M7-T4: export hash is reproducible", export["export_hash"] == export2["export_hash"])

        # Verify re-import: parse JSON
        raw = {k: v for k, v in export.items() if k != "export_hash"}
        check("M7-T4: case_id recoverable from export", raw["case"]["case_id"] == case.case_id)
        check("M7-T4: evidence hash in export", export["evidence"][0]["hash"] == ev.hash)

        # Different content → different hash
        cm.add_note(case.case_id, NotableSource.SYSTEM, "sys", "Extra note")
        export3 = cm.export_case(case.case_id)
        check("M7-T4: extra note changes hash", export3["export_hash"] != export["export_hash"])


# ---------------------------------------------------------------------------
# M7-T5: Retention Policy
# ---------------------------------------------------------------------------

def test_m7_t5():
    with tempfile.TemporaryDirectory() as tmp:
        cm = CaseManager(Path(tmp))

        # Case that is old (40 days ago)
        old_case = cm.create_case(
            "Old incident",
            "Should be archived",
            "medium",
            "agent:old",
            ["stale"],
            created_at=_days_ago_iso(40),
        )
        # Add notes (audit trail) to old case
        cm.add_note(old_case.case_id, NotableSource.SYSTEM, "sys", "Old note 1")
        cm.add_note(old_case.case_id, NotableSource.HUMAN, "analyst", "Old note 2")

        # Case that is fresh (5 days ago)
        fresh_case = cm.create_case(
            "Recent incident",
            "Should NOT be archived",
            "high",
            "agent:fresh",
            ["active"],
            created_at=_days_ago_iso(5),
        )
        cm.add_note(fresh_case.case_id, NotableSource.AGENT, "bot", "Fresh note")

        # Apply retention with max_age_days=30
        result = cm.apply_retention(max_age_days=30)
        check("M7-T5: 1 case archived", result["archived"] == 1)
        check("M7-T5: audit entries preserved ≥ 2", result["preserved_audit_entries"] >= 2)

        # Old case must be ARCHIVED
        old_retrieved = cm.get_case(old_case.case_id)
        check("M7-T5: old case state=ARCHIVED", old_retrieved.state.value == "ARCHIVED")

        # Fresh case must NOT be ARCHIVED
        fresh_retrieved = cm.get_case(fresh_case.case_id)
        check("M7-T5: fresh case not archived", fresh_retrieved.state.value != "ARCHIVED")

        # Normal query excludes ARCHIVED
        q_normal = cm.query()
        normal_ids = [c["case_id"] for c in q_normal["items"]]
        check("M7-T5: archived case excluded from normal query", old_case.case_id not in normal_ids)
        check("M7-T5: fresh case in normal query", fresh_case.case_id in normal_ids)

        # include_archived=True shows all
        q_all = cm.query(include_archived=True)
        all_ids = [c["case_id"] for c in q_all["items"]]
        check("M7-T5: archived case visible with include_archived=True", old_case.case_id in all_ids)
        check("M7-T5: total=2 with include_archived", q_all["total"] == 2)

        # Notes (audit trail) are preserved
        old_notes = [n for n in cm._notes.values() if n.case_id == old_case.case_id]
        check("M7-T5: notes preserved after archiving", len(old_notes) == 2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    env_data_dir = os.environ.get("NOARTEX_DATA_DIR")
    if env_data_dir:
        # Tests use their own tempdir internally, env var just signals we're in test mode
        pass

    print("=" * 75)
    print("  NOARTEX M7 Acceptance Tests — Memory Layer")
    print("=" * 75)

    run_test("M7-T1: Case creation, notes, evidence, follow-ups — linked by case_id", test_m7_t1)
    run_test("M7-T2: Structured query with actor/severity/tag/state + pagination", test_m7_t2)
    run_test("M7-T3: Follow-up tracking with state transitions and overdue detection", test_m7_t3)
    run_test("M7-T4: Case export with deterministic integrity hash", test_m7_t4)
    run_test("M7-T5: Retention policy archives expired cases, preserves audit trail", test_m7_t5)

    print()
    passed = sum(1 for _, s, _ in _results if s == PASS)
    failed = sum(1 for _, s, _ in _results if s == FAIL)
    total = passed + failed

    print("=" * 75)
    print(f"  Results: {passed}/{total} PASS  |  {failed} FAIL")
    print("=" * 75)

    if failed == 0:
        print()
        print("🎉  M7 CLOSED — All memory, search, followup, export, and retention tests PASS")
        sys.exit(0)
    else:
        print()
        print("❌  M7 NOT CLOSED — Fix failures before closing hito")
        for name, status, detail in _results:
            if status == FAIL:
                print(f"   FAIL: {name} — {detail}")
        sys.exit(1)
