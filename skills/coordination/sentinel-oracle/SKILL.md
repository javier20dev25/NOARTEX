---
name: sentinel-oracle-coordination
description: Coordinate with external Sentinel Oracle, a separate merge-authorization enclave/service. Use when an agent must respect out-of-band merge authority, authorization state, or PR decision evidence without assuming NOARTEX can grant merges.
---

# Sentinel Oracle Coordination (External)

## Scope
- Sentinel Oracle is an **external** merge-authorization system (separate trust boundary/enclave), not an in-tree NOARTEX adapter.
- Oracle decisions are authoritative only within its configured deployment and policy.

## Coordination rules
1. Treat merge authorization as an external control-plane decision; NOARTEX may inform but not replace it.
2. Collect relevant evidence (scan/audit findings, case context, risk summary) before requesting or referencing authorization.
3. Record Oracle decision artifacts/provenance when available; do not infer approval from silence.
4. Respect separation of duties: compromised workstation assumptions and physical/biometric controls remain Oracle concerns.

## Boundaries
- No in-tree `sentinel-oracle` adapter is registered in NOARTEX by default.
- NOARTEX must not store merge credentials/tokens for Oracle.
- Do not claim branch protection, enclave integrity, or authorization correctness without evidence.

## ARTEX
No ARTEX execution or defensive certification implied.
