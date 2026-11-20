"""
NOARTEX — Event Correlator (M4)
Motor de correlación determinista para señales heterogéneas:
- Ingesta de observaciones (Host, Network, File, Agent, Web)
- Ingesta de hallazgos SAST / Supply Chain (Sentinel)
- Ingesta de eventos de auditoría (denegaciones, approvals)
- Construcción de línea de tiempo unificada (timeline)
- Detección de lagunas de cobertura e inconsistencias epistémicas
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from core.intelligence.models import (
    ConfidenceLevel,
    EvidenceItem,
    TimelineEvent,
    _now,
    _new_id,
)
from core.observer.models import ObservationDomain, ObservationState


class EventCorrelator:
    """
    Correlaciona eventos y evidencias deterministamente.
    Nunca inventa causalidad sin evidencia de soporte.
    """

    def correlate(
        self,
        observations: Optional[list[dict[str, Any]]] = None,
        findings: Optional[list[dict[str, Any]]] = None,
        audit_records: Optional[list[dict[str, Any]]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Procesa los insumos y genera:
        - evidence: list[EvidenceItem]
        - timeline: list[TimelineEvent] (ordenada cronológicamente)
        - uncertainty: dict (coverage_gaps, contradictions, epistemic_limitations)
        - summary_signals: dict con conteos de señales por categoría
        """
        observations = observations or []
        findings = findings or []
        audit_records = audit_records or []
        context = context or {}

        evidence_items: list[EvidenceItem] = []
        timeline_events: list[TimelineEvent] = []
        coverage_gaps: list[str] = []
        contradictions: list[str] = []
        epistemic_limitations: list[str] = []

        # 1. Procesar Observaciones (Host, File, Net, Agent, Web)
        for obs in observations:
            obs_id = obs.get("event_id", _new_id("obs"))
            domain = obs.get("domain", "unknown")
            state = obs.get("state", ObservationState.NO_ACTIVITY_OBSERVED.value)
            limitations = obs.get("limitations", [])
            ts = obs.get("collected_at", _now())
            confidence_str = obs.get("confidence", "HIGH")

            # Registrar limitaciones epistémicas
            if limitations:
                epistemic_limitations.extend(limitations)

            if state in (ObservationState.OBSERVATION_UNAVAILABLE.value, ObservationState.DEGRADED.value):
                coverage_gaps.append(f"Domain '{domain}' was {state}: observation was limited or unavailable.")

            # Crear EvidenceItem
            ev = EvidenceItem(
                evidence_id=f"ev_{obs_id}",
                source_type=f"observer_{domain}",
                source_ref=obs_id,
                content=obs,
                collected_at=ts,
                confidence=ConfidenceLevel(confidence_str) if confidence_str in ConfidenceLevel._value2member_map_ else ConfidenceLevel.MEDIUM,
                limitations=limitations,
            )
            evidence_items.append(ev)

            # Crear TimelineEvent
            timeline_events.append(TimelineEvent(
                timestamp=ts,
                event_type=f"observation_{domain}",
                description=f"Observation in domain '{domain}': state={state}",
                evidence_ref=ev.evidence_id,
                data={"domain": domain, "state": state, "event_type": obs.get("event_type")},
            ))

        # 2. Procesar Hallazgos SAST / Supply Chain (Sentinel)
        for f in findings:
            fid = f.get("id") or f.get("finding_id") or _new_id("find")
            rule = f.get("rule_id", "security_rule")
            severity = f.get("severity", "MEDIUM")
            ts = f.get("detected_at", _now())

            ev = EvidenceItem(
                evidence_id=f"ev_{fid}",
                source_type="sast_or_supply_chain",
                source_ref=fid,
                content=f,
                collected_at=ts,
                confidence=ConfidenceLevel.HIGH,
                limitations=[],
            )
            evidence_items.append(ev)

            timeline_events.append(TimelineEvent(
                timestamp=ts,
                event_type="security_finding",
                description=f"Finding '{rule}' ({severity}) detected: {f.get('message', '')[:100]}",
                evidence_ref=ev.evidence_id,
                data=f,
            ))

        # 3. Procesar Registros de Auditoría
        for a in audit_records:
            atype = a.get("event_type", "AUDIT_EVENT")
            actor = a.get("actor_id")
            ts = a.get("timestamp", _now())

            if atype in ("TASK_DENIED", "APPROVAL_DENIED"):
                ev = EvidenceItem(
                    evidence_id=_new_id("ev_denial"),
                    source_type="audit_denial",
                    source_ref=a.get("task_id", ""),
                    content=a,
                    collected_at=ts,
                    confidence=ConfidenceLevel.HIGH,
                )
                evidence_items.append(ev)
                timeline_events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="policy_denial",
                    description=f"Policy denied task for actor '{actor}': {a.get('data', {}).get('reasons', ['Access denied'])}",
                    actor=actor,
                    evidence_ref=ev.evidence_id,
                    data=a,
                ))
            elif atype == "TASK_COMPLETED":
                timeline_events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="task_completed",
                    description=f"Task completed for actor '{actor}': {a.get('data', {}).get('operation')}",
                    actor=actor,
                    data=a,
                ))

        # 4. Chequeo de Contradicciones
        # Ejemplo: Proceso sospechoso pero hash en lista blanca o finding marcado FP
        suspicious_signals = [e for e in evidence_items if e.content.get("state") == ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value]
        clean_signals = [e for e in evidence_items if e.content.get("state") == ObservationState.NO_ACTIVITY_OBSERVED.value]
        if suspicious_signals and clean_signals:
            for s in suspicious_signals:
                target = s.content.get("target_scope", "target")
                for c in clean_signals:
                    if c.content.get("target_scope") == target and c.source_type == s.source_type:
                        contradictions.append(
                            f"Contradictory state in {s.source_type} for '{target}': reported both SUSPICIOUS and NO_ACTIVITY."
                        )

        # 5. Ordenar el Timeline cronológicamente
        def _parse_ts(ts_str: str) -> float:
            try:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0

        timeline_events.sort(key=lambda x: _parse_ts(x.timestamp))

        # Deduplicar brechas
        coverage_gaps = list(dict.fromkeys(coverage_gaps))
        contradictions = list(dict.fromkeys(contradictions))
        epistemic_limitations = list(dict.fromkeys(epistemic_limitations))

        return {
            "evidence": evidence_items,
            "timeline": timeline_events,
            "uncertainty": {
                "coverage_gaps": coverage_gaps,
                "contradictions": contradictions,
                "epistemic_limitations": epistemic_limitations,
            },
            "summary": {
                "total_evidence": len(evidence_items),
                "total_timeline_events": len(timeline_events),
                "has_coverage_gaps": len(coverage_gaps) > 0,
                "has_contradictions": len(contradictions) > 0,
            },
        }
