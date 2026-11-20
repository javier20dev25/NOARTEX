# Skills and ARTEX

## Skills in NOARTEX

NOARTEX uses skills as **agent-facing operating instructions** that describe how to discover capabilities, respect governance, and coordinate tools without embedding large implementation context into every prompt.

### In-repository skills

| Skill | Path | Role | Status |
|---|---|---|---|
| Canonical NOARTEX skill | `skills/canonical/SKILL.md` | Defines NOARTEX mission, governed workflow, command/capability usage patterns, and safety invariants for agents | Present (canonical in-tree) |
| Sentinel Runtime coordination | `skills/coordination/sentinel-runtime/SKILL.md` | Guides coordination with external Sentinel Runtime (observe-only telemetry/evidence service) without claiming in-tree adapter support | Added |
| Sentinel Audit coordination | `skills/coordination/sentinel-audit/SKILL.md` | Guides coordination with external Sentinel Audit (coverage-aware, pinned, human-adjudicated workflows) | Added |
| Sentinel Oracle coordination | `skills/coordination/sentinel-oracle/SKILL.md` | Guides coordination with external Sentinel Oracle (separate merge-authorization authority/enclave) | Added |
| Sentinel Cloud usage via Sentinel CLI | `skills/coordination/sentinel-cloud-usage/SKILL.md` | Guides Cloud-backed usage only through user-configured Sentinel CLI; states no Sentinel Cloud code in NOARTEX | Added |

### External/portable skill copies

- A portable NOARTEX skill copy may exist outside the repo (for example under agent skill directories). During reconciliation, canonical and portable NOARTEX skill content were observed identical at one point in time; **release alignment requires keeping copies synchronized when versions are frozen**.
- Other Sentinel ecosystem skills (e.g. `sentinel`, `sentinel-audit-triage`, `sentinel-ecosystem-orchestrator`) may exist in the user environment and can complement NOARTEX, but they are not owned by this repository unless copied here.

### Skill governance expectations

- Skills must not claim capabilities that are unavailable, unverified, or outside policy.
- Skills must preserve evidence boundaries: degraded/unknown/unavailable states are not "clean".
- Skills must not embed or request secrets (including Sentinel Cloud API keys). Credentials belong to user-managed tool configuration (e.g. Sentinel CLI), not to NOARTEX skills or code.
- Skills that coordinate external systems must state trust boundaries and avoid implying native in-tree integration when only runbook/CLI coordination exists.

## ARTEX

| Topic | Position |
|---|---|
| What ARTEX is in this context | An adversarial/reference context discussed in project history and security evaluation goals; not a component of this repository. |
| Execution status | **Not performed** in this repository state/reconciliation context. |
| Certification claim | **None.** NOARTEX is not certified for active defense, containment, or remediation against ARTEX. |
| Required before any such claim | Authorized environment, explicit scope, hardened/verified controls, reproducible evidence, and safety review proportionate to impact. |
| Relationship to NOARTEX roadmap | Potential future validation target/context only; not a completed or certified capability of `v0.8.0-m8` prototype. |

## Practical implication

Agents using NOARTEX should treat:
- **In-tree adapters/capabilities** as the only natively dispatchable NOARTEX operations (subject to policy/health).
- **External Sentinel components** as separate systems coordinated through explicit tools/skills and user authorization.
- **ARTEX** as out-of-scope for execution/certification unless separately authorized and evidenced.
