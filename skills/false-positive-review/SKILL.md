---
name: false-positive-review
version: 1.0.0
risk_tier: R1
reversible: true
description: >
  Systematic workflow for reviewing, validating, and resolving candidate
  security findings that may be false positives. Requires independent
  re-validation by a separate analysis pass before a finding is dismissed.
  Produces an auditable disposition record for each reviewed candidate.
  Prevents premature dismissal of valid findings through rationalization
  rejection rules.
commands:
  - noartex task submit --module M4 --skill false-positive-review
---

# False Positive Review Skill

## Purpose

Provide a structured, auditable process for determining whether a security
finding is a confirmed vulnerability, a false positive, or a true signal with
incorrect severity. Prevents the common failure mode of dismissing valid
findings through plausible-sounding rationalizations.

Independently implemented; inspired by structured validation methodology
in published security research. No code or text from any external repository
was used.

## Rationalization Rejection Rules

Reject the following reasoning patterns when evaluating a candidate. Each is
a rationalization that leads to incorrect dismissal.

**R1**: "This code path is never reached in practice."
Reject unless you have traced the call graph and confirmed the path is
statically unreachable or requires an impossible precondition.

**R2**: "An attacker would need to know the internal structure to exploit this."
Reject. Assume the attacker has read access to the source code.

**R3**: "This is behind authentication, so external attackers cannot reach it."
Reject for findings that affect authenticated users, insider threat actors,
or systems where the authentication layer may itself be bypassed.

**R4**: "The severity is low because exploitation is complex."
Complexity reduces the likelihood of exploitation, not the severity of the
impact. Assess severity against the worst-case impact, then separately
assess exploitability.

**R5**: "This is the same pattern used throughout the codebase."
Widespread use does not make a vulnerable pattern safe.

## Review Phases

### Phase 1 -- Candidate Intake

For each candidate finding provided for review:
1. Record the original finding: source, location (file + line), severity,
   detection method, and the analyst who raised it.
2. Record the proposed disposition: false positive, true positive, or
   severity adjustment.
3. Record the proposing analyst's rationale verbatim.

### Phase 2 -- Rationalization Check

Apply each rule in the rejection list to the proposing rationale.
If any rejection rule matches, flag the rationale as "requires escalation"
and do not proceed to dismissal. The finding remains open until the
rationalization is replaced with a concrete technical argument.

### Phase 3 -- Independent Re-validation

Assign a different analyst (or a separate agent subagent) to independently
attempt to reproduce the finding without reference to the Phase 2 rationale.

The independent validator must:
1. Start from the original source location and finding description only.
2. Attempt to construct a reproduction path using local fixtures.
3. Determine whether the attack vector is reachable from the declared
   threat actor principal.
4. Report independently: "reproduced", "not reproduced", or "needs further
   investigation".

A finding may be dismissed as a false positive only when:
- The independent validator confirms "not reproduced", AND
- The technical reason for non-reproduction is documented (compensating
  control identified, attack vector confirmed unreachable), AND
- The dismissal is reviewed by the original finder or a senior analyst.

### Phase 4 -- Disposition Record

For each reviewed candidate, produce a structured disposition:

```
disposition:
  finding_id: <original-id>
  candidate_disposition: false_positive | true_positive | severity_adjusted
  final_severity: CRITICAL | HIGH | MEDIUM | LOW | INFO | N/A
  independent_validation: reproduced | not_reproduced | inconclusive
  non_reproduction_reason: <technical explanation if not_reproduced>
  rationalization_flags: [list of rejection rules triggered, if any]
  reviewed_by: [analyst-1, analyst-2]
  reviewed_at: <ISO-8601>
  audit_note: <free text, required if any rationalization flag was raised>
```

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill false-positive-review \
  --findings <findings-file-path> \
  --policy R1
```

All dispositions are written to the NOARTEX audit log automatically.
