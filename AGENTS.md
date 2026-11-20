# AGENTS.md

Model-agnostic instructions for AI agents working in this repository.

## Purpose and boundaries

NOARTEX is a defensive coordination and capability infrastructure prototype for AI agents. Core principle: **the agent thinks; NOARTEX provides capabilities and governs execution.**

- Treat this repository as a **lab-validated prototype**, not a production-certified or ARTEX-certified defense system.
- Do not claim clean/safe/contained states when evidence is missing, degraded, or unavailable.
- Do not present Sentinel Cloud as embedded in NOARTEX. Sentinel CLI is integrated via `adapter.sentinel.cli`; Sentinel Runtime/Audit/Oracle/Cloud coordination is external and must respect separate trust boundaries.
- PHASE 4T is a separate, closed reconciliation track with remediation still open (`R-001`–`R-004`); do not rerun 4T, execute ARTEX, modify production systems, or leak sensitive marker values.

## Repository layout

- `noartex.py`, `cli/noartex/cli.py`: entrypoints (`CLI VERSION` currently `0.6.0-m6`; declared target `v0.8.0-m8` is not frozen).
- `core/`: contracts, orchestrator, discovery/registry, policy, session, audit, intelligence, memory, adapter base.
- `adapters/`: `sentinel_cli`, `observer_host`, `observer_agent`, `observer_web`, `defense_lab`.
- `schemas/`: JSON schemas (e.g. triage verdict).
- `skills/`: canonical and coordination skills.
- `tests/acceptance/m1-m8/`: acceptance suites and fixtures.
- `docs/`: architecture graph/images, tools/reverse-engineering, skills/ARTEX notes, release reconciliation, test evidence.

`data/`, caches, logs, and local runtime artifacts are excluded by `.gitignore`. Do not commit secrets, API keys, local `.noartex` state, or `data/test_*` artifacts.

## Working conventions

- Prefer small, evidence-backed changes. Inspect existing patterns before editing.
- Keep documentation clear and factual; **no ASCII art and no emojis** in repo docs/README unless explicitly requested later.
- Preserve provenance: do not alter historical evidence artifacts outside the repo unless explicitly asked; when adding evidence docs, cite source paths and state whether tests were rerun.
- Avoid adding dependencies or packaging metadata unless required; there is currently no `pyproject.toml`/`requirements*.txt`.

## Common commands

```powershell
python noartex.py --help
python noartex.py --version
python noartex.py doctor --format json
python noartex.py capabilities --format json
```

Governed operations are submitted via tasks (example shape):

```powershell
python noartex.py session create --agent <agent-id> --format json
python noartex.py task submit --session <session-id> --operation <capability> --params '<json>'
python noartex.py audit query --task <task-id>
```

## Capabilities and known gaps

- Runtime/catalog exposes 50 capabilities across core, intelligence, policy, observer, sentinel, defense, and memory domains with 5 adapters.
- Memory/case operations are implemented and invocable via governed task operations (e.g. `memory.case.create`, `memory.note.add`, `memory.evidence.add`, `memory.followup.*`, `memory.export`, `memory.retention`), with JSONL persistence/export hashes in runtime data dirs. There is **no dedicated `noartex memory` CLI subcommand** in the current CLI.
- No built-in command stack/shortcut/macro/playbook/alias orchestration feature is present in inspected CLI/core; agents may script sequences externally using governed commands/skills.
- Defense actions are lab-scoped in this prototype and subject to policy/approval/kill-switch controls.

## Tests

Acceptance suites live under `tests/acceptance/m1`–`m8` and are runnable as scripts (some depend on environment/tools):

```powershell
$env:PYTHONIOENCODING='utf-8'
python tests/acceptance/m1/test_m1.py
# ...
python tests/acceptance/m8/test_m8.py
```

Notes:
- `m4` requires `jsonschema`.
- `m2` includes checks that depend on an available/configured local `sentinel` CLI; negative/contract checks may still be valuable but full-suite pass is environment-dependent.
- Do not claim aggregate pass counts as rerun/frozen release evidence unless you actually executed and recorded them.

## CI/CD

GitHub Actions workflow is scoped to available dependencies and environment-independent acceptance suites. It does not certify production readiness or replace full environment-specific validation (e.g. Sentinel CLI integration).

## Security and secrets

- Never store Sentinel Cloud/API credentials, tokens, or secrets in repo files, skills, or logs.
- Keep outputs free of raw sensitive markers; redact when documenting incidents or evidence.
- Prefer least privilege and explicit, auditable operations.
