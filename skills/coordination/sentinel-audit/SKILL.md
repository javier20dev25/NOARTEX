---
name: sentinel-audit-coordination
description: Coordinate with external Sentinel Audit for coverage-aware, pinned security audit workflows. Use when an agent needs structured audit evidence, analyzer coverage, or adjudication-ready reports without confusing coverage gaps with clean results.
---

# Sentinel Audit Coordination (External)

## Scope
- Sentinel Audit is an **external** orchestrator/project, not an in-tree NOARTEX adapter.
- Audit value is evidence and coverage accounting, not vulnerability invention.

## Coordination rules
1. Pin target (repo/PR/commit) and capture clean/dirty state context when relevant.
2. Start from preflight/coverage-aware outputs; never treat unexecuted checks as clean.
3. Preserve specialist/tool coverage, failures, and unknowns in any summary.
4. Stop for human adjudication before asserting a vulnerability or merge decision.
5. Import structured results into NOARTEX as evidence/notes with provenance and timestamps.

## Boundaries
- No in-tree `sentinel-audit` adapter is registered in NOARTEX by default.
- Do not read/execute untrusted target code beyond the audit tool's governed/read-only workflow.
- Do not upgrade "no finding reported" to "secure".

## Cloud/pulse note
If Sentinel Audit or related flows offer hosted/cloud actions, treat them as explicit, separately authorized actions; NOARTEX contains no Sentinel Cloud code.
