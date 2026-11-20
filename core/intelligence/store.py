"""
NOARTEX — Incident Store (M4 / M7)
Persistencia estructurada para incidentes, casos y notas en JSONL.
Garantiza trazabilidad y recuperación histórica.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.intelligence.models import (
    EvidenceItem,
    Incident,
    IncidentState,
    Severity,
    TimelineEvent,
    TriageVerdict,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentStore:
    """
    Almacén de incidentes con persistencia JSONL.
    Permite crear, actualizar, consultar y adjuntar evidencia/notas/verdictos.
    """

    def __init__(self, data_dir: str | Path):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._file = self._dir / "incidents.jsonl"
        self._verdicts_file = self._dir / "verdicts.jsonl"
        self._lock = threading.Lock()
        self._incidents: dict[str, Incident] = {}
        self._load()

    def _load(self) -> None:
        if not self._file.exists():
            return
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        inc = Incident.from_dict(data)
                        self._incidents[inc.incident_id] = inc
                    except Exception:
                        continue
        except Exception:
            pass

    def _persist(self) -> None:
        """Reescribe el snapshot completo de incidentes de forma atómica."""
        tmp = self._file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for inc in self._incidents.values():
                f.write(json.dumps(inc.to_dict(), ensure_ascii=False) + "\n")
        tmp.replace(self._file)

    def create(
        self,
        title: str,
        severity: Severity = Severity.MEDIUM,
        owner: Optional[str] = None,
        hypotheses: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> Incident:
        with self._lock:
            inc = Incident(
                title=title,
                severity=severity,
                owner=owner,
                hypotheses=hypotheses or [],
                tags=tags or [],
            )
            # Agregar evento de creación al timeline
            inc.timeline.append(TimelineEvent(
                timestamp=inc.created_at,
                event_type="incident_created",
                description=f"Incident '{title}' created with severity {severity.value}",
                actor=owner,
            ))
            self._incidents[inc.incident_id] = inc
            self._persist()
            return inc

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(
        self,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> list[Incident]:
        with self._lock:
            res = list(self._incidents.values())
            if state:
                res = [i for i in res if i.state.value == state.upper()]
            if severity:
                res = [i for i in res if i.severity.value == severity.upper()]
            return res[:limit]

    def update(
        self,
        incident_id: str,
        state: Optional[IncidentState] = None,
        severity: Optional[Severity] = None,
        hypotheses: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        owner: Optional[str] = None,
    ) -> Optional[Incident]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            if state:
                inc.state = state
                inc.timeline.append(TimelineEvent(
                    timestamp=_now(),
                    event_type="state_changed",
                    description=f"State transitioned to {state.value}",
                    actor=owner or inc.owner,
                ))
            if severity:
                inc.severity = severity
            if hypotheses is not None:
                inc.hypotheses = hypotheses
            if tags is not None:
                inc.tags = tags
            if owner:
                inc.owner = owner
            inc.updated_at = _now()
            self._persist()
            return inc

    def add_note(
        self,
        incident_id: str,
        author: str,
        note: str,
        tags: Optional[list[str]] = None,
    ) -> Optional[Incident]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            now_ts = _now()
            entry = {
                "author": author,
                "note": note,
                "timestamp": now_ts,
                "tags": tags or [],
            }
            inc.notes.append(entry)
            inc.timeline.append(TimelineEvent(
                timestamp=now_ts,
                event_type="note_added",
                description=f"Note by {author}: {note[:80]}",
                actor=author,
            ))
            inc.updated_at = now_ts
            self._persist()
            return inc

    def add_evidence(
        self,
        incident_id: str,
        evidence: EvidenceItem,
    ) -> Optional[Incident]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            inc.evidence.append(evidence)
            inc.timeline.append(TimelineEvent(
                timestamp=evidence.collected_at,
                event_type="evidence_attached",
                description=f"Evidence {evidence.evidence_id} ({evidence.source_type}) attached",
                evidence_ref=evidence.evidence_id,
            ))
            inc.updated_at = _now()
            self._persist()
            return inc

    def save_verdict(self, verdict: TriageVerdict) -> None:
        with self._lock:
            inc = self._incidents.get(verdict.incident_id)
            if inc:
                inc.latest_verdict = verdict
                inc.timeline.append(TimelineEvent(
                    timestamp=verdict.created_at,
                    event_type="triage_verdict_issued",
                    description=f"Triage verdict: {verdict.classification.value} ({verdict.confidence.value} confidence)",
                    data={"verdict_id": verdict.verdict_id, "summary": verdict.summary},
                ))
                inc.updated_at = _now()
                self._persist()

            # Guardar también en log append-only de veredictos
            with open(self._verdicts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(verdict.to_dict(), ensure_ascii=False) + "\n")
