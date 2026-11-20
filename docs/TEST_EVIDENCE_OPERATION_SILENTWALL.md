# Test Evidence: Operation Silentwall (M8) and Acceptance Context

**Status:** Preserved evidence summary (not rerun in this session).  
**Primary preserved artifact:** `C:\Users\sleyt\.gemini\antigravity\brain\0d1396e6-5418-4d68-b1f9-719e68d60d60\.system_generated\tasks\task-1000.log`  
**Scenario implementation:** `tests/acceptance/m8/test_m8.py` (`_run_silentwall`, `M8-T1`–`M8-T10`)  
**Environment/scope:** Synthetic lab fixture only; no external targets, no production systems, no real network connections. Results are lab/prototype evidence and do not certify production or ARTEX readiness.

## Preserved M8 execution result (from task-1000.log)

- Suite: `NOARTEX M8 Acceptance Tests - End-to-End Integration` / Scenario: `Operation Silentwall (lab fixture only)`
- Scenario executed: session created, incident `inc_*`, triage verdict `PARTIAL`, case `case_*` (ephemeral IDs in preserved run)
- Reported outcome: **`Results: 51/51 PASS | 0 FAIL`**
- Reported closure message: `M8 CLOSED - End-to-End integration validated` demonstrating detection/triage/authorization/containment/rollback/memory/audit orchestration in lab conditions

## Scenario: Operation Silentwall

`_run_silentwall` simulates a synthetic lab incident where an agent (`codex:lab`) exhibits suspicious file/process activity consistent with unauthorized reads/exfiltration attempts, then drives a governed defensive response.

### Stages and governed operations invoked

| Stage | Purpose | Key operations/capabilities | Inputs/artifacts (synthetic/lab) | Observed handling in test assertions |
|---|---|---|---|---|
| 0. Session | Establish governed context | session creation (orchestrator), task dispatch | actor `codex:lab`, TTL session | Active session used for subsequent tasks |
| 1. Detection | Host observation snapshot | `observer.host.files` | `paths=[tmp]`, `authorized_root=tmp` | Succeeded or degraded accepted per environment state |
| 2. Investigation | Agent/host activity inspection | `observer.host.processes` (repeated), `observer.agent.activity` | audit/task activity in temp data dir | Succeeded or degraded accepted; activity surfaced for correlation |
| 3. Correlation/incident | Create incident record | `intelligence.incident.create` | title/severity `HIGH`, owner `codex:lab`, hypotheses (exfiltration, privilege escalation), tags (`silentwall`, `lab-exercise`) | Incident created with `inc_*` ID |
| 4. Triage | Deterministic verdict under evidence | `intelligence.triage.evaluate` | observations (host.files spike, agent.activity burst), finding (path traversal pattern, `HIGH`), severity/hypotheses | Verdict classification present (preserved run: `PARTIAL`); no false certainty required |
| 5. Authorization | Human/operator approval for R2 defense action | `policy.approval.grant` | target `defense.artifact.quarantine`, scope `{environment: lab, target: <file>}`, approver `operator:human`, TTL | Approval/token issued for scoped one-time use |
| 6. Containment | Lab quarantine of suspected artifact | `defense.artifact.quarantine` | `target_path` = lab file containing synthetic marker `EXFIL DATA: ...`, `environment=lab`, approval/context | Quarantine executed in lab; containment status/plan/effects asserted in T1/T6 |
| 7. Validation | Post-action observation | `observer.host.files` | same authorized root | Observer check executed (succeeded/degraded allowed) |
| 8. Rollback | Restore pre-containment state | `defense.action.rollback` (with granted rollback approval where required) | rollback plan from quarantine, `environment=lab` | Rollback path exercised; restoration asserted in T7 |
| 9. Memory and audit | Case lifecycle, evidence, export | `memory.case.create`, `memory.note.add` (human/agent), `memory.evidence.add`, `memory.followup.add`, `memory.export`, audit query | incident ref, verdict, containment/rollback context, tags `silentwall,e2e,lab` | Case linked, notes/evidence/followups present, export hash (SHA256) present, audit trail populated |

### Attack/abuse patterns simulated (synthetic)

- Repeated/rapid agent task/activity pattern (burst used to drive agent activity observation).
- Suspicious file access/exfiltration indicator (synthetic artifact with exfil-like content in lab temp path).
- Path traversal pattern signal included as triage finding input (synthetic finding content).
- Unauthorized defense attempt without approval (blocked, no effect) — T4.
- Approval replay/over-broad use attempts (one-time, scoped token enforcement) — T5.
- Operations under kill-switch activation (protected actions halted) — T8.
- Degraded/missing observer evidence paths (must not assert clean/confirmed) — T3.

### Responses, decisions, and controls exercised

- **Policy/governance:** session-scoped task submission, approval-gated defense action, kill-switch activation/deactivation, scoped/TTL/one-time approval behavior.
- **Defense (lab):** quarantine containment with rollback capability and restoration verification.
- **Intelligence:** incident creation and triage evaluation with explicit handling of insufficient/degraded evidence (no false `CONFIRMED` when evidence absent/degraded).
- **Memory/case:** case creation, human and agent notes, evidence attachment, follow-up tracking, deterministic export with integrity hash.
- **Auditability:** task and memory-related events recorded and comparable across repeated runs.

## M8 test matrix (from `tests/acceptance/m8/test_m8.py`)

| Test | Focus | Key assertions (high level) |
|---|---|---|
| M8-T1 | Normal E2E flow | Host/agent observations run, incident created, triage evaluated with valid classification, defense containment ran, export hash present, case linked to incident |
| M8-T2 | Insufficient evidence | Triage succeeds but does not return false `CONFIRMED`; returns `PARTIAL`/`UNKNOWN`; gaps/uncertainty/limitations documented |
| M8-T3 | Degraded observer | Bad/missing observation path does not yield `CONFIRMED`; triage remains `PARTIAL`/`UNKNOWN` (no clean-state assertion) |
| M8-T4 | Unauthorized defense | Quarantine without approval blocked/denied as applicable; target file unmodified |
| M8-T5 | Approval token controls | Approval granted with token, not pre-consumed, first authorized use allowed, replay blocked |
| M8-T6 | Lab quarantine containment | Quarantine runs in lab, containment evidence/status present, artifact moved from source to quarantine location |
| M8-T7 | Rollback | Quarantine then rollback restores original file and content |
| M8-T8 | Kill switch | Activation blocks protected defense op without modifying target; deactivation restores normal (pending/not kill-switch-blocked) flow |
| M8-T9 | Memory/case completeness | Case linked to incident, >=2 notes, >=1 evidence, >=1 followup, 64-char export hash, case retrievable/tagged, audit trail has task events |
| M8-T10 | Repeatability | Two independent runs produce equivalent structure/verdict class/case/export presence and comparable counts/trail sizes |

**Preserved totals:** 51 checks, 51 PASS, 0 FAIL (per `task-1000.log`).

## M1–M8 acceptance suite context (not rerun here)

| Suite | File | Focus (from inspected tests) | Environment notes |
|---|---|---|---|
| M1 | `tests/acceptance/m1/test_m1.py` | Core CLI/doctor/capabilities/session/task/audit basics | Subprocess CLI, local temp data dir |
| M2 | `tests/acceptance/m2/test_m2.py` | Sentinel CLI adapter contract/discovery/execution and negative controls | Some checks require available/configured local `sentinel` CLI; not default-CI safe |
| M3 | `tests/acceptance/m3/test_m3.py` | Host/web/agent observers and unified observation/degradation behavior | OS/environment dependent observers; subprocess CLI paths |
| M4 | `tests/acceptance/m4/test_m4.py` | Correlation/timeline, uncertainty/false-positive handling, schema validation, incident history, E2E/CLI | Requires `jsonschema`; uses subprocess/CLI in parts |
| M5 | `tests/acceptance/m5/test_m5.py` | Policy matrix R0–R4, approvals, revocation, kill switch, fail-safe, automatic mode constraints | In-process + subprocess checks |
| M6 | `tests/acceptance/m6/test_m6.py` | Defense lab containment, post-validation, approval/scope enforcement, remediation/rollback, fail-safe, lab scope | Lab temp environments |
| M7 | `tests/acceptance/m7/test_m7.py` | Case/notes/evidence/followups, query/pagination, overdue, export hash, retention | In-process CaseManager/temp dirs |
| M8 | `tests/acceptance/m8/test_m8.py` | End-to-end Operation Silentwall integration and repeatability | Lab fixtures only; preserved 51/51 PASS evidence |

Aggregate M1–M8 totals previously reported in project status docs are not independently rebound to a frozen immutable release in this repository state.

## Tools/capabilities inventory exercised by M8

- **Core/governance:** session lifecycle, task submission/status/result flow, policy decisions/constraints, audit logging.
- **Policy controls:** `policy.approval.grant`, kill-switch activate/deactivate paths (T8), scoped/TTL/one-time approval enforcement.
- **Intelligence:** `intelligence.incident.create`, `intelligence.triage.evaluate`.
- **Observers:** `observer.host.files`, `observer.host.processes`, `observer.agent.activity` (via registered adapters).
- **Defense lab:** `defense.artifact.quarantine`, `defense.action.rollback` with lab-scoped containment and restoration.
- **Memory:** `memory.case.create`, `memory.note.add`, `memory.evidence.add`, `memory.followup.add`, `memory.export`.

## Limitations

- Evidence is preserved and documentary; this file does not constitute a rerun, frozen release manifest, or production/active-defense certification.
- Runtime/CLI version labels in-tree (`0.6.0-m6`) are not aligned to declared target `v0.8.0-m8`; release identity remains unfrozen.
- External tool integrations (e.g. Sentinel CLI in M2) are environment-dependent and excluded from default CI where appropriate.
