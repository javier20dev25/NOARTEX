---
name: sentinel-runtime-coordination
description: Coordinate with external Sentinel Runtime (observe-only Linux telemetry/evidence service) from a NOARTEX-governed workflow. Use when an agent needs runtime telemetry, loss/health context, or local ledger evidence from a separately deployed Sentinel Runtime without assuming in-tree NOARTEX adapter support.
---

# Sentinel Runtime Coordination (External)

## Scope
- Sentinel Runtime is an **external** project/service, not an in-tree NOARTEX adapter.
- Runtime is **observe-only** in its documented posture: it does not block/kill/quarantine/retaliate.
- Treat Runtime outputs as telemetry/evidence with possible loss, degradation, or unknown coverage.

## Coordination rules
1. Confirm deployment/context (host, service state, permissions, data path) before requesting evidence.
2. Prefer read-only inspection commands and documented health/ledger verification flows.
3. Do not claim detection, prevention, or full visibility from absence of findings.
4. Record provenance: source host/service, time window, command/query used, and any degraded/loss signals.
5. Map relevant findings into NOARTEX cases/incidents/notes/evidence only through governed NOARTEX operations.

## Boundaries
- No in-tree `sentinel-runtime` adapter is registered in NOARTEX by default.
- Root/kernel compromise and sensor tampering are outside Runtime/NOARTEX safety guarantees.
- Do not execute untrusted target code as part of coordination.

## ARTEX
No ARTEX execution, no active-defense certification implied.
