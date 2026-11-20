"""
NOARTEX — CaseManager (M7)
Manages Cases, Notes, Evidence, FollowUps with JSONL persistence.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.memory.models import (
    Case,
    CaseEvidence,
    CaseNote,
    CaseState,
    FollowUp,
    FollowUpState,
    NotableSource,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid_hex(n: int = 12) -> str:
    return uuid.uuid4().hex[:n]


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class CaseManager:
    """
    Manages Case lifecycle, notes, evidence, follow-ups, export, and retention.
    Persistence: JSONL files per entity under {data_dir}/memory/
    """

    def __init__(self, data_dir: Path):
        self._mem_dir = Path(data_dir) / "memory"
        self._mem_dir.mkdir(parents=True, exist_ok=True)
        self._cases_path = self._mem_dir / "cases.jsonl"
        self._notes_path = self._mem_dir / "notes.jsonl"
        self._evidence_path = self._mem_dir / "evidence.jsonl"
        self._followups_path = self._mem_dir / "followups.jsonl"

        # In-memory indexes (loaded lazily on first access)
        self._cases: dict[str, Case] = {}
        self._notes: dict[str, CaseNote] = {}           # note_id -> CaseNote
        self._evidence: dict[str, CaseEvidence] = {}    # evidence_id -> CaseEvidence
        self._followups: dict[str, FollowUp] = {}       # followup_id -> FollowUp
        self._loaded = False

    # ------------------------------------------------------------------
    # Load / Persist
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._cases = self._load_jsonl(self._cases_path, Case.from_dict, "case_id")
        self._notes = self._load_jsonl(self._notes_path, CaseNote.from_dict, "note_id")
        self._evidence = self._load_jsonl(self._evidence_path, CaseEvidence.from_dict, "evidence_id")
        self._followups = self._load_jsonl(self._followups_path, FollowUp.from_dict, "followup_id")
        self._loaded = True

    @staticmethod
    def _load_jsonl(path: Path, factory, id_field: str) -> dict:
        result = {}
        if not path.exists():
            return result
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    obj = factory(d)
                    result[getattr(obj, id_field)] = obj
                except Exception:
                    continue
        return result

    def _persist_jsonl(self, path: Path, objects: dict) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for obj in objects.values():
                f.write(json.dumps(obj.to_dict(), ensure_ascii=False) + "\n")

    def _persist_all(self) -> None:
        self._persist_jsonl(self._cases_path, self._cases)
        self._persist_jsonl(self._notes_path, self._notes)
        self._persist_jsonl(self._evidence_path, self._evidence)
        self._persist_jsonl(self._followups_path, self._followups)

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(
        self,
        title: str,
        description: str,
        severity: str,
        actor: str,
        tags: Optional[list[str]] = None,
        incident_ref: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> Case:
        self._ensure_loaded()
        now = created_at or _now_iso()
        case = Case(
            case_id=f"case_{_uuid_hex(12)}",
            title=title,
            description=description,
            severity=severity,
            actor=actor,
            tags=list(tags or []),
            state=CaseState.OPEN,
            created_at=now,
            updated_at=now,
            incident_ref=incident_ref,
        )
        self._cases[case.case_id] = case
        self._persist_jsonl(self._cases_path, self._cases)
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        self._ensure_loaded()
        return self._cases.get(case_id)

    def _update_case_timestamp(self, case_id: str) -> None:
        case = self._cases.get(case_id)
        if case:
            case.updated_at = _now_iso()
            self._persist_jsonl(self._cases_path, self._cases)

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def add_note(
        self,
        case_id: str,
        source: NotableSource,
        author: str,
        content: str,
    ) -> CaseNote:
        self._ensure_loaded()
        note = CaseNote(
            note_id=f"note_{_uuid_hex(12)}",
            case_id=case_id,
            source=source,
            author=author,
            content=content,
            created_at=_now_iso(),
        )
        self._notes[note.note_id] = note
        self._persist_jsonl(self._notes_path, self._notes)
        self._update_case_timestamp(case_id)
        return note

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        case_id: str,
        title: str,
        source: str,
        content: str,
        collected_at: Optional[str] = None,
    ) -> CaseEvidence:
        self._ensure_loaded()
        ev = CaseEvidence(
            evidence_id=f"ev_{_uuid_hex(12)}",
            case_id=case_id,
            title=title,
            source=source,
            content=content,
            hash=_sha256(content),
            collected_at=collected_at or _now_iso(),
        )
        self._evidence[ev.evidence_id] = ev
        self._persist_jsonl(self._evidence_path, self._evidence)
        self._update_case_timestamp(case_id)
        return ev

    # ------------------------------------------------------------------
    # Follow-ups
    # ------------------------------------------------------------------

    def add_followup(
        self,
        case_id: str,
        title: str,
        assignee: Optional[str] = None,
        due_at: Optional[str] = None,
    ) -> FollowUp:
        self._ensure_loaded()
        now = _now_iso()
        fu = FollowUp(
            followup_id=f"fu_{_uuid_hex(12)}",
            case_id=case_id,
            title=title,
            state=FollowUpState.OPEN,
            assignee=assignee,
            due_at=due_at,
            created_at=now,
            updated_at=now,
        )
        self._followups[fu.followup_id] = fu
        self._persist_jsonl(self._followups_path, self._followups)
        self._update_case_timestamp(case_id)
        return fu

    def update_followup_state(self, followup_id: str, new_state: FollowUpState) -> FollowUp:
        self._ensure_loaded()
        fu = self._followups.get(followup_id)
        if fu is None:
            raise KeyError(f"FollowUp '{followup_id}' not found")
        fu.state = new_state
        fu.updated_at = _now_iso()
        self._persist_jsonl(self._followups_path, self._followups)
        return fu

    def list_followups(self, case_id: str) -> list[FollowUp]:
        self._ensure_loaded()
        return [fu for fu in self._followups.values() if fu.case_id == case_id]

    def list_overdue_followups(self) -> list[FollowUp]:
        self._ensure_loaded()
        now = _now_iso()
        result = []
        for fu in self._followups.values():
            if fu.state != FollowUpState.CLOSED and fu.due_at and fu.due_at < now:
                result.append(fu)
        return result

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        actor: Optional[str] = None,
        severity: Optional[str] = None,
        tag: Optional[str] = None,
        state: Optional[str] = None,
        include_archived: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        self._ensure_loaded()
        items = list(self._cases.values())

        # Filter archived unless explicitly requested
        if not include_archived:
            items = [c for c in items if c.state != CaseState.ARCHIVED]

        if actor:
            items = [c for c in items if c.actor == actor]
        if severity:
            items = [c for c in items if c.severity.lower() == severity.lower()]
        if tag:
            items = [c for c in items if tag in c.tags]
        if state:
            items = [c for c in items if c.state.value == state.upper()]

        total = len(items)
        page = items[offset: offset + limit]
        return {
            "items": [c.to_dict() for c in page],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_case(self, case_id: str) -> dict:
        self._ensure_loaded()
        case = self._cases.get(case_id)
        if case is None:
            raise KeyError(f"Case '{case_id}' not found")

        notes = [n.to_dict() for n in self._notes.values() if n.case_id == case_id]
        evidence = [e.to_dict() for e in self._evidence.values() if e.case_id == case_id]
        followups = [fu.to_dict() for fu in self._followups.values() if fu.case_id == case_id]

        # Deterministic serialization: sort lists by their primary IDs
        notes_sorted = sorted(notes, key=lambda x: x["note_id"])
        evidence_sorted = sorted(evidence, key=lambda x: x["evidence_id"])
        followups_sorted = sorted(followups, key=lambda x: x["followup_id"])

        payload = {
            "case": case.to_dict(),
            "notes": notes_sorted,
            "evidence": evidence_sorted,
            "followups": followups_sorted,
        }

        # Deterministic hash: canonical JSON (sorted keys)
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        export_hash = _sha256(canonical)

        return {**payload, "export_hash": export_hash}

    # ------------------------------------------------------------------
    # Retention Policy
    # ------------------------------------------------------------------

    def apply_retention(self, max_age_days: int) -> dict:
        self._ensure_loaded()
        now = datetime.now(timezone.utc)
        archived_count = 0
        preserved_audit_entries = 0

        for case in self._cases.values():
            if case.state == CaseState.ARCHIVED:
                continue
            try:
                created = datetime.fromisoformat(case.created_at)
                # Make aware if naive
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            age_days = (now - created).days
            if age_days > max_age_days:
                case.state = CaseState.ARCHIVED
                case.updated_at = now.isoformat()
                archived_count += 1
                # Preserve notes (audit trail): count notes linked to this case
                preserved_audit_entries += sum(
                    1 for n in self._notes.values() if n.case_id == case.case_id
                )

        self._persist_all()
        return {
            "archived": archived_count,
            "preserved_audit_entries": preserved_audit_entries,
        }
