---
name: structured-audit
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Structured six-phase security audit for codebases, APIs, services, CLI tools,
  libraries, and daemons. Finds vulnerabilities that cross a real trust boundary
  and produces source-referenced, reproducible findings with priority and
  minimal-effective-fix recommendations. Operates in guidance mode by default;
  full audit mode requires explicit user request. All execution is read-only
  against source; target-controlled processes require an OS-enforced sandbox.
commands:
  - noartex task submit --module M4 --skill structured-audit
---

# Structured Audit Skill

## Purpose

Find vulnerabilities that violate a real trust boundary. A candidate without
a concrete affected principal, resource, or security outcome is not a confirmed
finding. This skill is source-first and defensive.

Adapted from architectural patterns in the Cloudflare security-audit skill
(MIT license). No code or text copied verbatim; concepts re-implemented
independently under Apache-2.0.

## Operating Modes

**Guidance mode** (default): Answer security questions, perform focused reviews,
triage specific findings, or investigate methodology. Do not automatically run
all phases, create output directories, or write report artifacts.

**Full audit mode**: Run all six phases and write structured findings. Requires
explicit user request ("audit this codebase", "run a full security review",
"produce an audit report"). If the request is ambiguous, ask one clarifying
question before starting.

## Execution Safety

Source inspection is read-only. Any target-controlled process (builds, tests,
fuzzers, fixture processing) requires an OS-enforced sandbox with:
- no external network access
- empty environment populated from an explicit allowlist
- target writes confined to its own scratch directory
- explicit CPU, memory, process, file-size, disk, and wall-clock limits

Do not probe live deployed endpoints, production identities, or shared
infrastructure. Report any missing sandbox capability as a blocker rather
than proceeding without it.

## Phase 1 -- Reconnaissance

Establish the attack surface before looking for specific vulnerabilities.

1. Identify trust boundaries: authentication perimeters, privilege levels,
   data-flow entry points, inter-service interfaces, and external inputs.
2. Map components: enumerate executables, libraries, services, APIs, and
   their exposed interfaces.
3. Record the reviewed commit/ref, build toolchain, and runtime dependencies.
4. Identify high-value assets: credential stores, cryptographic material,
   persistent state, admin interfaces, and privileged execution paths.

Output: attack surface map (components, trust boundaries, assets, entry points).

## Phase 2 -- Coverage Mapping

Confirm that subsequent phases will cover the meaningful attack surface.

1. Cross-check the asset list against test coverage, fuzz targets, and
   existing audit reports.
2. Identify gaps: untested code paths, undocumented interfaces, dead code
   with lingering privilege.
3. Document coverage percentage per component and flag areas with zero
   coverage.

Output: coverage gap report with prioritized blind spots.

## Phase 3 -- Vulnerability Hunting

Systematic enumeration of candidate vulnerabilities.

For each trust boundary and entry point identified in Phase 1:
1. Trace data flow from input to sensitive operation.
2. Check for missing authorization checks at privilege transitions.
3. Check for injection sinks: command construction, query construction,
   deserialization of untrusted data, format strings.
4. Check for state management errors: TOCTOU, session fixation, concurrent
   modification without locking.
5. Check for cryptographic misuse: weak algorithms, static keys, IV reuse,
   unauthenticated encryption.
6. Check for secret handling: hardcoded credentials, secrets in logs, secrets
   in error messages, secrets in environment variables passed to subprocesses.
7. Check for dependency risks: known-vulnerable versions, typosquatting risk,
   transitive dependencies with broader permissions than the declared API.

For each candidate: record location (file, line), affected principal,
affected resource, attack vector, and severity rationale.

## Phase 4 -- Independent Validation

Attempt to refute each candidate from Phase 3 before classifying it as a
confirmed finding.

1. Check whether a compensating control elsewhere in the codebase prevents
   exploitation.
2. Construct a minimal reproduction path using local fixtures and dummy
   principals only. If reproduction requires a live external service, mark
   as "needs-validation" and document the validation plan.
3. Determine exploitability: is the attack vector reachable from an
   unauthenticated or low-privilege principal?
4. Discard candidates that cannot be reproduced or lack a reachable attack
   vector. Document the discard reason.

Output: validated finding list with reproduction steps or discard rationale.

## Phase 5 -- Structured Findings

Produce machine-readable, evidence-linked findings.

Each finding includes:
- id: unique finding identifier (repo-name-NNN)
- title: one-line description
- severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- cvss_vector: CVSS 3.1 vector string if applicable
- location: file path and line range
- trust_boundary: which boundary is violated
- affected_principal: who can exploit this
- affected_resource: what is at risk
- reproduction: step-by-step reproduction using local fixtures
- fix: smallest effective remediation
- references: CVE, CWE, or comparable identifier where applicable

## Phase 6 -- Evidence Verification

Before delivering the report:
1. Verify that every finding cites a specific file and line in the reviewed
   source ref.
2. Verify that every reproduction step uses only local fixtures and dummy data.
3. Verify that no finding was produced without an independent validation
   attempt in Phase 4.
4. Verify that discarded candidates are listed with rationale.
5. Confirm the reviewed commit matches the target.

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill structured-audit \
  --target <repo-path> \
  --mode full \
  --policy R2
```

The policy engine enforces read-only posture (R2) throughout. File writes
(output directory, findings report) are authorized only by the parent agent
after the task result is returned.
