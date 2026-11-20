"""
NOARTEX — Intelligence & Incident Models (M4)
Contratos y estructuras de datos para:
- Incidentes y casos operativos
- Correlación de eventos multi-fuente
- Verificación y análisis de incertidumbre
- Veredicto de triage normalizado
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class IncidentState(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerdictClassification(str, Enum):
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class EvidenceItem:
    """Evidencia trazable asociada a un incidente o evaluación."""
    evidence_id: str = field(default_factory=lambda: _new_id("ev"))
    source_type: str = "unknown"  # host_process, host_network, host_file, sast_finding, audit_event, etc.
    source_ref: str = ""          # ID o referencia externa
    content: dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(default_factory=_now)
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "content": self.content,
            "collected_at": self.collected_at,
            "confidence": self.confidence.value,
            "limitations": self.limitations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceItem:
        return cls(
            evidence_id=data.get("evidence_id", _new_id("ev")),
            source_type=data.get("source_type", "unknown"),
            source_ref=data.get("source_ref", ""),
            content=data.get("content", {}),
            collected_at=data.get("collected_at", _now()),
            confidence=ConfidenceLevel(data.get("confidence", "HIGH")),
            limitations=data.get("limitations", []),
        )


@dataclass
class TimelineEvent:
    """Hito o evento ordenado cronológicamente dentro de un incidente."""
    timestamp: str = field(default_factory=_now)
    event_type: str = "observation"
    description: str = ""
    actor: Optional[str] = None
    evidence_ref: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "actor": self.actor,
            "evidence_ref": self.evidence_ref,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimelineEvent:
        return cls(
            timestamp=data.get("timestamp", _now()),
            event_type=data.get("event_type", "observation"),
            description=data.get("description", ""),
            actor=data.get("actor"),
            evidence_ref=data.get("evidence_ref"),
            data=data.get("data", {}),
        )


@dataclass
class TriageVerdict:
    """Veredicto determinista de triage emitido para un incidente."""
    verdict_id: str = field(default_factory=lambda: _new_id("vrd"))
    incident_id: str = ""
    classification: VerdictClassification = VerdictClassification.UNKNOWN
    severity: Severity = Severity.MEDIUM
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    summary: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    uncertainty: dict[str, list[str]] = field(default_factory=lambda: {
        "coverage_gaps": [],
        "contradictions": [],
        "epistemic_limitations": [],
    })
    false_positive_rationale: Optional[dict[str, str]] = None
    recommended_actions: list[dict[str, str]] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "verdict_id": self.verdict_id,
            "incident_id": self.incident_id,
            "classification": self.classification.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "evidence_refs": self.evidence_refs,
            "timeline": self.timeline,
            "uncertainty": self.uncertainty,
            "created_at": self.created_at,
        }
        if self.false_positive_rationale:
            d["false_positive_rationale"] = self.false_positive_rationale
        if self.recommended_actions:
            d["recommended_actions"] = self.recommended_actions
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TriageVerdict:
        return cls(
            verdict_id=data.get("verdict_id", _new_id("vrd")),
            incident_id=data.get("incident_id", ""),
            classification=VerdictClassification(data.get("classification", "UNKNOWN")),
            severity=Severity(data.get("severity", "MEDIUM")),
            confidence=ConfidenceLevel(data.get("confidence", "MEDIUM")),
            summary=data.get("summary", ""),
            evidence_refs=data.get("evidence_refs", []),
            timeline=data.get("timeline", []),
            uncertainty=data.get("uncertainty", {
                "coverage_gaps": [],
                "contradictions": [],
                "epistemic_limitations": [],
            }),
            false_positive_rationale=data.get("false_positive_rationale"),
            recommended_actions=data.get("recommended_actions", []),
            created_at=data.get("created_at", _now()),
        )


@dataclass
class Incident:
    """Caso o incidente de seguridad con ciclo de vida completo."""
    incident_id: str = field(default_factory=lambda: _new_id("inc"))
    title: str = "Nuevo Incidente"
    state: IncidentState = IncidentState.OPEN
    severity: Severity = Severity.MEDIUM
    owner: Optional[str] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    hypotheses: list[str] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    uncertainty: dict[str, list[str]] = field(default_factory=lambda: {
        "coverage_gaps": [],
        "contradictions": [],
        "epistemic_limitations": [],
    })
    latest_verdict: Optional[TriageVerdict] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "state": self.state.value,
            "severity": self.severity.value,
            "owner": self.owner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "hypotheses": self.hypotheses,
            "notes": self.notes,
            "tags": self.tags,
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": [t.to_dict() for t in self.timeline],
            "uncertainty": self.uncertainty,
            "latest_verdict": self.latest_verdict.to_dict() if self.latest_verdict else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        inc = cls(
            incident_id=data.get("incident_id", _new_id("inc")),
            title=data.get("title", ""),
            state=IncidentState(data.get("state", "OPEN")),
            severity=Severity(data.get("severity", "MEDIUM")),
            owner=data.get("owner"),
            created_at=data.get("created_at", _now()),
            updated_at=data.get("updated_at", _now()),
            hypotheses=data.get("hypotheses", []),
            notes=data.get("notes", []),
            tags=data.get("tags", []),
            evidence=[EvidenceItem.from_dict(e) for e in data.get("evidence", [])],
            timeline=[TimelineEvent.from_dict(t) for t in data.get("timeline", [])],
            uncertainty=data.get("uncertainty", {
                "coverage_gaps": [],
                "contradictions": [],
                "epistemic_limitations": [],
            }),
        )
        if data.get("latest_verdict"):
            inc.latest_verdict = TriageVerdict.from_dict(data["latest_verdict"])
        return inc
