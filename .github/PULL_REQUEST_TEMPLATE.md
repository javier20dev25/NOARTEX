## Description
<!-- Provide a concise technical summary of the changes and motivation -->

## Capability & Module Affected
- [ ] Core Engine (`core/engine.py`, `core/reactive/`, `core/policy/`)
- [ ] Adapters (`adapters/tetragon_stream/`, `adapters/docker/`, etc.)
- [ ] CLI / Interfaces (`cli/`, `noartex.py`)
- [ ] Capabilities Registry (`data/capabilities.json`, `schemas/`)
- [ ] Documentation / Specs (`docs/`, `README.md`)

## Security Tenets Checklist
- [ ] Fail-closed semantics preserved across all modified paths
- [ ] Zero unvalidated or unparsed shell execution paths introduced
- [ ] No emojis or marketing hype included in code, logs, comments, or documentation
- [ ] Any state mutations or case records include SHA256 integrity validation

## Testing & Verification
- [ ] Automated acceptance tests added or updated
- [ ] Full regression suite (M1–M9) executed and passing locally:
  ```bash
  python -m unittest discover tests/acceptance
  ```
- [ ] `python noartex.py doctor --format json` reports all systems healthy
