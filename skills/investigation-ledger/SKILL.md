---
name: investigation-ledger
version: 1.0.0
risk_tier: R1
reversible: true
description: >
  Maintains an immutable, cryptographically verifiable investigation ledger
  for active security incidents. Records tool invocations, evidentiary citations,
  analyst hypotheses, and groundedness metrics. Computes provenance hashes to
  prevent reasoning drift and uncorroborated conclusions.
commands:
  - noartex task submit --module M7 --skill investigation-ledger
---

# Investigation Ledger Skill

## Purpose

Track and audit the complete investigative trajectory of defensive agents and
human operators during incident triage. Ensures that every conclusion, threat
attribution, and recommended remediation rests on verified telemetry artifacts,
preventing epistemic drift, hallucinations, and ungrounded assertions.

Adapted from architectural patterns in AiSOC (open source, MIT license)
Investigation Ledger & Groundedness evaluation, integrated directly with
NOARTEX M7 Memory Layer and Append-Only Audit Logging.

## Core Ledger Tenets

1. **Groundedness Requirement:**
   Every analytical claim must cite at least one verified evidence ID recorded
   in the incident ledger. Uncited claims are rejected with an `UNGROUNDED_CLAIM`
   warning and cannot influence policy decisions.

2. **Immutable Append-Only Audit:**
   Each ledger entry (observation, hypothesis, tool execution, intermediate
   conclusion) is appended with a cryptographic SHA256 chain hash linked to
   the previous entry, guaranteeing tamper evidence.

3. **Explicit Blind-Spot Logging:**
   Tools that failed, timed out, or returned zero records must be logged as
   investigative boundaries. Hiding or omitting failed queries invalidates
   the case's integrity certificate.

## Ledger Entry Categories

### L1 -- Telemetry Ingestion Entry
- Records raw signals, telemetry snapshots, and connector identifiers.
- Captures sensor metadata: host ID, kernel version, adapter status.

### L2 -- Hypothesis Entry
- Formulates a specific testable threat scenario.
- Declares the required corroborating evidence threshold.

### L3 -- Tool Execution & Observation
- Records exact tool parameters, exit status, duration, and returned payload hash.
- Distinguishes sensor-grounded facts from adversary-controlled arguments.

### L4 -- Contradiction & Corroboration Entry
- Explicitly flags when two pieces of evidence contradict each other
  (e.g., netstat shows established connection, but eBPF socket table has no record).
- Calculates the corroboration confidence ratio.

### L5 -- Final Disposition & Case Sign-Off
- Summarizes the findings into a machine-readable verdict:
  `CONFIRMED`, `PARTIAL`, `FALSE_POSITIVE`, or `UNKNOWN`.
- Exports a complete case dossier with SHA256 verification seal.

## Groundedness Calculation

The skill evaluates the case dossier using a deterministic groundedness formula:

$$\text{Groundedness Score} = \frac{\sum \text{Claims with Verified Sensor Evidence}}{\text{Total Analytical Claims}}$$

- If Groundedness $< 0.85$, the case is downgraded to `LOW_CONFIDENCE` and
  automated containment actions are blocked, requiring manual human review.
- If any claim references adversary-authored text without sensor verification,
  the claim is tagged as `UNVERIFIED_ADVERSARY_ASSERTION`.

## Output Format

```yaml
ledger_case_summary:
  case_id: "case-YYYYMMDD-XXXX"
  created_at: "2026-11-20T04:10:00Z"
  total_entries: 14
  chain_head_sha256: "9f83c12a4b82173f4e27f...3e"
  groundedness_score: 0.93
  uncited_claims: 0
  contradictions_resolved: 1
  verdict: "CONFIRMED"
  evidence_citations:
    - claim: "Unauthorized python3 interpreter accessed root secret file"
      citations: ["ev-001 (eBPF openat2)", "ev-002 (filesystem checksum)"]
      status: "VERIFIED"
  artifacts:
    - name: "evidence-dossier.json"
      sha256: "b45a...12"
```

## NOARTEX Integration

```bash
noartex task submit \
  --module M7 \
  --skill investigation-ledger \
  --params '{"action": "RECORD_HYPOTHESIS", "case_id": "case-01", "text": "Adversary attempting lateral movement"}' \
  --policy R1
```
