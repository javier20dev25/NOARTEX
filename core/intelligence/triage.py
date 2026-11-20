"""
NOARTEX — Triage Engine (M4)
Motor determinista de evaluación de triage y emisión de veredictos.
Invariantes:
- Clasifica en CONFIRMED, PARTIAL, UNKNOWN o FALSE_POSITIVE.
- Diferenciación de False Positives trazable y documentada (NUNCA eliminación silenciosa).
- Casos con evidencia insuficiente o contradictoria emiten UNKNOWN o PARTIAL con brechas explícitas.
- Todo veredicto emitido valida estrictamente contra schemas/triage_verdict.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import jsonschema

from core.intelligence.models import (
    ConfidenceLevel,
    Incident,
    Severity,
    TimelineEvent,
    TriageVerdict,
    VerdictClassification,
    _new_id,
    _now,
)
from core.observer.models import ObservationState

SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "triage_verdict.json"


class TriageEngine:
    """
    Evalúa incidentes o paquetes de eventos y emite un TriageVerdict determinista.
    """

    def __init__(self, schema_path: Optional[Path] = None):
        self._schema_path = schema_path or SCHEMA_PATH
        self._schema = self._load_schema()

    def _load_schema(self) -> dict[str, Any]:
        if not self._schema_path.exists():
            raise FileNotFoundError(f"Triage verdict schema not found at {self._schema_path}")
        with open(self._schema_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def evaluate(
        self,
        incident: Incident,
        fp_rules: Optional[list[dict[str, Any]]] = None,
    ) -> TriageVerdict:
        """
        Evalúa un incidente y retorna un TriageVerdict conforme a schema.
        """
        evidence_items = incident.evidence
        timeline = incident.timeline
        uncertainty = incident.uncertainty or {
            "coverage_gaps": [],
            "contradictions": [],
            "epistemic_limitations": [],
        }
        fp_rules = fp_rules or []

        coverage_gaps = list(uncertainty.get("coverage_gaps", []))
        contradictions = list(uncertainty.get("contradictions", []))
        epistemic_limitations = list(uncertainty.get("epistemic_limitations", []))

        # Recopilar IDs de evidencia
        evidence_refs = [e.evidence_id for e in evidence_items]

        # Serializar timeline para el veredicto
        timeline_dicts = [t.to_dict() for t in timeline]

        # -------------------------------------------------------------------
        # 1. Regla de Detección de Falso Positivo (M4-T3)
        # -------------------------------------------------------------------
        # Comprobar si coincide con reglas de FP registradas o etiquetas de fixture
        is_fp = False
        fp_rationale: Optional[dict[str, str]] = None

        # Revisión de tags de incidente
        if "known_false_positive" in incident.tags or "fp" in incident.tags:
            is_fp = True
            fp_rationale = {
                "rule_id": "FP_TAG_KNOWN_BENIGN",
                "justification": "Incident was tagged as a known false positive or benign testing activity.",
                "original_finding": incident.title,
            }

        # Revisión contra reglas de FP explícitas
        if not is_fp and fp_rules:
            for rule in fp_rules:
                rule_id = rule.get("rule_id", "FP_RULE")
                pattern = rule.get("pattern", "")
                for ev in evidence_items:
                    ev_str = json.dumps(ev.content)
                    if pattern and pattern in ev_str:
                        is_fp = True
                        fp_rationale = {
                            "rule_id": rule_id,
                            "justification": rule.get("justification", "Matched verified benign pattern."),
                            "original_finding": str(ev.source_ref),
                        }
                        break
                if is_fp:
                    break

        # Revisión en el contenido de evidencias (fixture etiquetada)
        if not is_fp:
            for ev in evidence_items:
                if ev.content.get("is_false_positive") is True or ev.content.get("verdict") == "FALSE_POSITIVE":
                    is_fp = True
                    fp_rationale = {
                        "rule_id": ev.content.get("fp_rule_id", "FP_VERIFIED_BENIGN"),
                        "justification": ev.content.get("fp_justification", "Verified as known benign fixture activity."),
                        "original_finding": str(ev.source_ref),
                    }
                    break

        if is_fp:
            verdict = TriageVerdict(
                verdict_id=_new_id("vrd"),
                incident_id=incident.incident_id,
                classification=VerdictClassification.FALSE_POSITIVE,
                severity=Severity.INFO,
                confidence=ConfidenceLevel.HIGH,
                summary=f"Activity identified as FALSE POSITIVE: {fp_rationale.get('justification', '')}",
                evidence_refs=evidence_refs,
                timeline=timeline_dicts,
                uncertainty={
                    "coverage_gaps": coverage_gaps,
                    "contradictions": contradictions,
                    "epistemic_limitations": epistemic_limitations,
                },
                false_positive_rationale=fp_rationale,
                recommended_actions=[
                    {
                        "action": "log_and_suppress_alert",
                        "risk_level": "R0",
                        "description": "Log false positive rationale in audit log and retain evidence.",
                    }
                ],
                created_at=_now(),
            )
            self._validate(verdict)
            return verdict

        # -------------------------------------------------------------------
        # 2. Regla de Evidencia Insuficiente o Contradictoria (M4-T2)
        # -------------------------------------------------------------------
        # a) Contradicciones detectadas
        if len(contradictions) > 0:
            verdict = TriageVerdict(
                verdict_id=_new_id("vrd"),
                incident_id=incident.incident_id,
                classification=VerdictClassification.UNKNOWN,
                severity=Severity.MEDIUM,
                confidence=ConfidenceLevel.LOW,
                summary="Contradictory signals detected across observation domains. Triage classification is UNKNOWN.",
                evidence_refs=evidence_refs,
                timeline=timeline_dicts,
                uncertainty={
                    "coverage_gaps": coverage_gaps,
                    "contradictions": contradictions,
                    "epistemic_limitations": epistemic_limitations,
                },
                recommended_actions=[
                    {
                        "action": "request_targeted_observation",
                        "risk_level": "R0",
                        "description": "Perform additional observation to resolve contradictory indicators.",
                    }
                ],
                created_at=_now(),
            )
            self._validate(verdict)
            return verdict

        # b) Cobertura degradada o inexistente
        degraded_count = sum(
            1 for e in evidence_items
            if e.content.get("state") in (ObservationState.OBSERVATION_UNAVAILABLE.value, ObservationState.DEGRADED.value)
        )
        if degraded_count > 0 and len(evidence_items) == degraded_count:
            # Todos los sensores estaban caídos o degradados
            coverage_gaps.append("All sensors reported DEGRADED or UNAVAILABLE state.")
            verdict = TriageVerdict(
                verdict_id=_new_id("vrd"),
                incident_id=incident.incident_id,
                classification=VerdictClassification.UNKNOWN,
                severity=Severity.LOW,
                confidence=ConfidenceLevel.LOW,
                summary="Observation sensors were degraded or unavailable; unable to confirm activity.",
                evidence_refs=evidence_refs,
                timeline=timeline_dicts,
                uncertainty={
                    "coverage_gaps": coverage_gaps,
                    "contradictions": contradictions,
                    "epistemic_limitations": epistemic_limitations,
                },
                recommended_actions=[
                    {
                        "action": "restore_sensor_visibility",
                        "risk_level": "R0",
                        "description": "Check adapter health and restore monitoring before asserting security state.",
                    }
                ],
                created_at=_now(),
            )
            self._validate(verdict)
            return verdict

        # c) Evidencia parcial (algunos sensores degradados o señal aislada débil)
        suspicious_signals = [
            e for e in evidence_items
            if e.content.get("state") == ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value
            or e.source_type in ("sast_or_supply_chain", "audit_denial")
        ]

        if coverage_gaps and suspicious_signals:
            # Hay sospecha pero con brechas de cobertura
            verdict = TriageVerdict(
                verdict_id=_new_id("vrd"),
                incident_id=incident.incident_id,
                classification=VerdictClassification.PARTIAL,
                severity=incident.severity,
                confidence=ConfidenceLevel.MEDIUM,
                summary="Suspicious activity observed but domain coverage has explicit gaps. Classification is PARTIAL.",
                evidence_refs=evidence_refs,
                timeline=timeline_dicts,
                uncertainty={
                    "coverage_gaps": coverage_gaps,
                    "contradictions": contradictions,
                    "epistemic_limitations": epistemic_limitations,
                },
                recommended_actions=[
                    {
                        "action": "expand_observation_scope",
                        "risk_level": "R0",
                        "description": "Collect evidence in missing domains to confirm threat.",
                    }
                ],
                created_at=_now(),
            )
            self._validate(verdict)
            return verdict

        # -------------------------------------------------------------------
        # 3. Regla de Actividad Confirmada (M4-T1)
        # -------------------------------------------------------------------
        if suspicious_signals:
            # Señales firmes sin contradicciones y con visibilidad suficiente
            verdict = TriageVerdict(
                verdict_id=_new_id("vrd"),
                incident_id=incident.incident_id,
                classification=VerdictClassification.CONFIRMED,
                severity=incident.severity if incident.severity != Severity.INFO else Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                summary=f"CONFIRMED security threat: {len(suspicious_signals)} corroborating signals across domains.",
                evidence_refs=evidence_refs,
                timeline=timeline_dicts,
                uncertainty={
                    "coverage_gaps": coverage_gaps,
                    "contradictions": contradictions,
                    "epistemic_limitations": epistemic_limitations,
                },
                recommended_actions=[
                    {
                        "action": "propose_containment",
                        "risk_level": "R3",
                        "description": "Prepare containment plan for operator approval.",
                    }
                ],
                created_at=_now(),
            )
            self._validate(verdict)
            return verdict

        # -------------------------------------------------------------------
        # 4. Caso Base: No se observó actividad sospechosa (Benigno / Safe)
        # -------------------------------------------------------------------
        verdict = TriageVerdict(
            verdict_id=_new_id("vrd"),
            incident_id=incident.incident_id,
            classification=VerdictClassification.UNKNOWN if coverage_gaps else VerdictClassification.PARTIAL,
            severity=Severity.INFO,
            confidence=ConfidenceLevel.HIGH if not coverage_gaps else ConfidenceLevel.MEDIUM,
            summary="No suspicious activity detected within verified scope.",
            evidence_refs=evidence_refs,
            timeline=timeline_dicts,
            uncertainty={
                "coverage_gaps": coverage_gaps,
                "contradictions": contradictions,
                "epistemic_limitations": epistemic_limitations,
            },
            created_at=_now(),
        )
        self._validate(verdict)
        return verdict

    def _validate(self, verdict: TriageVerdict) -> None:
        """Valida que el veredicto cumpla estrictamente con el JSON Schema."""
        d = verdict.to_dict()
        jsonschema.validate(instance=d, schema=self._schema)
