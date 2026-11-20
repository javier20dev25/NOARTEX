# Tools and Reverse-Engineered Integration Inventory

This document enumerates the tools and components that confirm parts of NOARTEX and describes how they were identified/integrated. It distinguishes **direct in-tree integration**, **external tool invocation**, and **skill-guided coordination**. Statements are evidence-based; unknowns are marked explicitly.

## Scope and method

- Evidence sources: NOARTEX source tree (`core/`, `adapters/`, `cli/`, `schemas/`, `tests/`), runtime observations (`doctor`, `capabilities`), and locally inspected Sentinel ecosystem projects/readmes/manifests present on this workstation.
- "Reverse-engineered" in this context means: understanding external tool behavior/interfaces from observed binaries, local repositories, command surfaces, manifests, and runtime contracts sufficiently to build governed adapters/skills and interoperability mappings. It does **not** imply bypassing protections, violating licenses, or embedding proprietary cloud code.

## In-tree components (confirmed implementation)

| Component | Path | Confirms | Integration basis | Evidence |
|---|---|---|---|---|
| CLI + entrypoint | `noartex.py`, `cli/noartex/cli.py` | Agent/operator interface, command routing, version/contract declarations | Direct implementation | File inspection, `--version`/`--help` |
| Contracts/models | `core/contracts/models.py` | Task/session/policy/decision/result model, risk levels, statuses | Direct implementation | File inspection |
| Orchestrator | `core/orchestrator.py` | Central mediation: request -> policy -> dispatch -> audit | Direct implementation | File inspection |
| Capability registry | `core/discovery/registry.py` | 50 capabilities, domain/risk/adapter binding, health aggregation | Direct implementation + runtime | `capabilities`/`doctor` output |
| Policy engine/approvals/killswitch | `core/policy/*.py` | Deterministic governance, approvals, kill switch, revocation primitives | Direct implementation + M5/M8 tests | File/test inspection |
| Session manager | `core/session/manager.py` | Session lifecycle and validation | Direct implementation | File inspection |
| Audit store | `core/audit/store.py` | JSONL append-only audit logging | Direct implementation + runtime state | File inspection, `.noartex/audit.jsonl` presence |
| Intelligence | `core/intelligence/*`, `schemas/triage_verdict.json` | Correlation, incidents, deterministic triage schema | Direct implementation + schema | Files/tests |
| Memory/cases | `core/memory/*` | Cases, notes, evidence, followups, export hash, retention | Direct implementation + M7/M8 tests | Files/tests/log evidence |
| Adapter framework | `core/adapters/base.py` | Uniform adapter contract, limits, path validation hooks | Direct implementation | File inspection |

## Adapters (confirmed integrations)

| Adapter | Path | External/tool dependency | How integrated | Capabilities | Notes / limits |
|---|---|---|---|---|---|
| Sentinel CLI adapter | `adapters/sentinel_cli/adapter.py` | Local `sentinel`/`sentinel.cmd` binary (e.g. Sentinel CLI install) | Subprocess invocation with argument vector (no shell), path validation, JSON extraction, timeout/env handling | `sentinel.sast.scan`, `sentinel.cicd.audit`, `sentinel.supply_chain.audit`, `sentinel.report.generate` | Availability depends on binary/health; reports degraded/unavailable states. Does not embed Sentinel Cloud code. May reflect Cloud-backed CLI features only if user configured them in Sentinel CLI. |
| Host observer | `adapters/observer_host/adapter.py` | Host OS inspection APIs/commands via adapter logic | Native adapter (read-only snapshot operations) | `observer.host.processes/files/network` | Snapshot-oriented; not continuous kernel telemetry |
| Agent observer | `adapters/observer_agent/adapter.py` | NOARTEX audit/activity records | Native adapter | `observer.agent.activity`, `observer.agent.denials` | Observes NOARTEX-mediated activity, not LLM internals |
| Web observer | `adapters/observer_web/adapter.py` | DNS/HTTP header checks | Native adapter | `observer.web.headers`, `observer.web.dns` | Targeted checks; no TLS session/browser internals inspection |
| Defense lab | `adapters/defense_lab/adapter.py` | Local lab filesystem/state (`~/.noartex/defense_lab`) | Native adapter with reversible lab actions and rollback plans | `defense.artifact.quarantine/tag`, `defense.host.isolate/remediate`, `defense.action.rollback` | Lab/sandbox scope; not production-certified containment/remediation |

## External Sentinel ecosystem components (locally inspected, not embedded)

These projects are separate from NOARTEX. NOARTEX may coordinate with them via adapter (CLI only, in-tree) or via skills/runbooks.

| Component | Local evidence inspected | Nature | NOARTEX relationship | Reverse-engineering / mapping notes |
|---|---|---|---|---|
| Sentinel CLI (`sntnl-cli`, local repo) | `C:\Users\sleyt\sentinel-cli` README/package/LICENSE | CLI security platform (SAST, supply chain, network/audit features, Cloud-backed commands when configured) | **Integrated** through `adapter.sentinel.cli` | Command/JSON behavior inferred from CLI docs and adapter implementation; adapter normalizes outputs into NOARTEX task results. User API keys/config remain in Sentinel CLI environment, not in NOARTEX. |
| Sentinel Runtime | `C:\Users\sleyt\sentinel-runtime` README/package/LICENSE | Linux runtime telemetry/evidence service (Tetragon-based, observe-only) | **Not integrated as adapter**; coordination skill provided | Interface/constraints understood from local docs (service/systemd, ledger, health/loss semantics). Coordination must respect its observe-only and trust-boundary limits. |
| Sentinel Audit | `C:\Users\sleyt\sentinel-audit` README/package/LICENSE | Audit orchestrator with coverage-aware evidence and human adjudication | **Not integrated as adapter**; coordination skill provided | Workflow/evidence model understood from local docs (preflight, pinned checkouts, coverage/gaps, human adjudication). |
| Sentinel Oracle | `C:\Users\sleyt\sentinel-oracle` README/package/LICENSE | Physically isolated merge authorization server | **Not integrated as adapter**; coordination skill provided | Authority boundary understood from local docs (separate enclave/device, merge authorization, not CI/linter replacement). |
| Sentinel Cloud | `C:\Users\sleyt\sentinel-cloud` README/LICENSE (separate repo) | Hosted/private cloud platform/service | **No code embedded in NOARTEX**; usage via Sentinel CLI when user configures API key | Only usage/coordination guidance is provided. NOARTEX must not contain cloud backend/client secrets or cloud service code copied into this tree. |

## Sentinel Cloud boundary statement

- NOARTEX repository contains **no Sentinel Cloud service/backend implementation** and **no embedded Sentinel Cloud API client**.
- `adapter.sentinel.cli` can invoke the local Sentinel CLI binary; if that CLI is configured by the user to use Sentinel Cloud (including API key/token stored/managed by Sentinel CLI or user environment), Cloud-backed commands execute in the **Sentinel CLI** context, not as NOARTEX cloud code.
- Coordination/usage skills may describe this path but must not store, request, or hardcode credentials.

## ARTEX

- ARTEX is referenced as adversarial/contextual subject matter from project history; **no ARTEX execution is performed** by this reconciliation/repository state.
- No claim is made that NOARTEX detects, contains, or remediates ARTEX in production conditions.

## Confirmed vs not confirmed

| Claim | Status |
|---|---|
| 50 capabilities and 5 adapters exposed in observed runtime | Confirmed (runtime observation) |
| Sentinel CLI integration via in-tree adapter | Confirmed |
| Native in-tree adapters for Sentinel Runtime/Audit/Oracle/Cloud | Not confirmed / not present |
| Skill-guided coordination paths for Runtime/Audit/Oracle/Cloud-via-CLI | Provided in this repo (documentation/skills), operational effectiveness depends on external installs/config |
| Production readiness, active defense, or ARTEX containment certification | Not confirmed |

## Known traceability gaps

- Version identity mismatch (`0.6.0-m6` CLI vs declared `v0.8.0-m8` target).
- No frozen Git commit/tag/release manifest in current working tree state at time of reconciliation.
- Full M1-M8 acceptance totals are reported/preserved in artifacts but not fully rebound to an immutable release package here.
