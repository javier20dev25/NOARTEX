"""
NOARTEX — Memory Layer Models (M7)
Dataclasses for Case, CaseNote, CaseEvidence, FollowUp.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CaseState(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class FollowUpState(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"


class NotableSource(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Case:
    case_id: str           # "case_<uuid4_hex[:12]>"
    title: str
    description: str
    severity: str          # "critical", "high", "medium", "low", "info"
    actor: str             # agent_id or human identifier
    tags: list[str]
    state: CaseState
    created_at: str        # ISO 8601
    updated_at: str        # ISO 8601
    incident_ref: Optional[str] = None  # link to M4 incident if any

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "actor": self.actor,
            "tags": list(self.tags),
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "incident_ref": self.incident_ref,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Case":
        return cls(
            case_id=d["case_id"],
            title=d["title"],
            description=d["description"],
            severity=d["severity"],
            actor=d["actor"],
            tags=list(d.get("tags", [])),
            state=CaseState(d["state"]),
            created_at=d["created_at"],
            updated_at=d["updated_at"],
            incident_ref=d.get("incident_ref"),
        )


@dataclass
class CaseNote:
    note_id: str           # "note_<uuid4_hex[:12]>"
    case_id: str
    source: NotableSource
    author: str
    content: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "note_id": self.note_id,
            "case_id": self.case_id,
            "source": self.source.value,
            "author": self.author,
            "content": self.content,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CaseNote":
        return cls(
            note_id=d["note_id"],
            case_id=d["case_id"],
            source=NotableSource(d["source"]),
            author=d["author"],
            content=d["content"],
            created_at=d["created_at"],
        )


@dataclass
class CaseEvidence:
    evidence_id: str       # "ev_<uuid4_hex[:12]>"
    case_id: str
    title: str
    source: str
    content: str
    hash: str              # SHA256 of content
    collected_at: str

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "title": self.title,
            "source": self.source,
            "content": self.content,
            "hash": self.hash,
            "collected_at": self.collected_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CaseEvidence":
        return cls(
            evidence_id=d["evidence_id"],
            case_id=d["case_id"],
            title=d["title"],
            source=d["source"],
            content=d["content"],
            hash=d["hash"],
            collected_at=d["collected_at"],
        )


@dataclass
class FollowUp:
    followup_id: str       # "fu_<uuid4_hex[:12]>"
    case_id: str
    title: str
    state: FollowUpState
    assignee: Optional[str]
    due_at: Optional[str]  # ISO 8601
    created_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return {
            "followup_id": self.followup_id,
            "case_id": self.case_id,
            "title": self.title,
            "state": self.state.value,
            "assignee": self.assignee,
            "due_at": self.due_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FollowUp":
        return cls(
            followup_id=d["followup_id"],
            case_id=d["case_id"],
            title=d["title"],
            state=FollowUpState(d["state"]),
            assignee=d.get("assignee"),
            due_at=d.get("due_at"),
            created_at=d["created_at"],
            updated_at=d["updated_at"],
        )
