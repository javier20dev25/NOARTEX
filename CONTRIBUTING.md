# Contributing to NOARTEX

## Invitation to Continuous Improvement

NOARTEX is designed as an open, governed control plane for defensive AI operators operating against machine-speed autonomous malware (ARTEX class). Defending production infrastructure from autonomous threats requires continuous evolution, rigorous engineering, and empirical validation.

We welcome contributions, research collaborations, and continuous improvements from:
- **Systems Security Engineers:** Hardening kernel probes, expanding eBPF tracing, developing Linux cgroup isolation, and refining network socket containment.
- **AI Safety & Alignment Researchers:** Enhancing capability boundaries, formalizing agent intent verification, and stress-testing policy engines against jailbreaks and prompt-injection-mediated tool invocations.
- **Threat Researchers & Red Teams:** Creating repeatable, safe test vectors in laboratory environments to benchmark NOARTEX response latencies and evasion resilience.
- **Tooling Developers:** Adding adapters for runtime telemetry (Cilium, Falco, OSQuery, Auditd) and defensive integrations (Sentinel Cloud, SIEMs, containment sidecars).

Whether submitting a targeted bug fix, proposing a new observer capability, or optimizing bus dispatch latency, your contributions help advance the state of defensive autonomy.

---

## Code of Engineering Rigor

Contributions to NOARTEX must adhere to the following core tenets:

1. **Fail-Closed by Default:** Any uncertainty, parsing failure, missing policy definition, or corrupted state MUST fail closed (block execution, reject task, or trigger bounded containment).
2. **Determinism First:** Outputs must be reproducible. State mutations and forensic cases must be cryptographically hashed (SHA256) and verifiable.
3. **Empirical Verification:** Every new capability, policy rule, or adapter must include full acceptance tests. PRs without automated tests will not be merged.
4. **Zero Emojis & Marketing Hyperbole:** NOARTEX is a high-assurance systems security tool. Keep code comments, commits, pull request descriptions, documentation, and log outputs clean, technical, and free of emojis or marketing hype.

---

## Pull Request (PR) Policy

All contributions are reviewed under strict engineering standards:

### 1. Branching Strategy
- Fork the repository and create a descriptive feature branch from `master` (e.g., `feat/ebpf-bpf-ringbuf` or `fix/event-bus-race-condition`).
- Keep individual PRs focused on a single logical change or capability.

### 2. PR Title Convention
Use conventional commit formatting:
- `feat: <description>` — New capability, adapter, or engine feature
- `fix: <description>` — Bug fix or error handling enhancement
- `perf: <description>` — Latency or throughput optimization
- `test: <description>` — Acceptance or regression test coverage
- `docs: <description>` — Technical documentation, specs, or ADRs

### 3. Testing Requirements
Before submitting a PR:
- All existing acceptance suites (M1 through M9) must pass with zero regressions.
- If introducing a new capability:
  1. Add capability definition in `data/capabilities.json` conforming to `schemas/capability.json`.
  2. Implement bounded execution in the appropriate module under `core/` or `adapters/`.
  3. Provide an acceptance test in `tests/acceptance/` validating both authorized (positive) and unauthorized/tampered (negative) paths.
- Run tests locally:
  ```powershell
  python -m unittest discover tests/acceptance
  ```

### 4. Review Process
- PRs require at least one approving review by a maintainer.
- Continuous Integration (CI) checks must pass cleanly across supported platforms.
- Rebase or squash commits cleanly before final merge.

---

## Issue Policy

We maintain GitHub Issues for actionable technical tracking:

### What Belongs in Public Issues
- **Bug Reports:** Deterministic unexpected behaviors, crashes, or schema validation failures. Include environment details (OS, Python version), logs, and reproducible steps.
- **Feature Requests / RFCs:** Concrete proposals for new capabilities, adapters, or architectural enhancements. Describe the operational threat model and proposed schema.
- **Documentation Improvements:** Clarifications of API interfaces, missing CLI command examples, or architectural diagrams.

### What Does NOT Belong in Public Issues
- **Security Vulnerabilities:** Never report active exploits, policy bypasses, privilege escalations, or security flaws in public issues. Refer to [SECURITY.md](SECURITY.md) and email `sleytherjavier2025@gmail.com` directly.
- **Support Requests or Enterprise Inquiries:** General inquiries should be directed to `nighttracesec@gmail.com`.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/javier20dev25/NOARTEX.git
cd NOARTEX

# Install minimal test dependencies
pip install jsonschema

# Validate environment and tool health
python noartex.py doctor --format json

# Execute the complete test suite
python tests/acceptance/m1/test_m1.py
python tests/acceptance/m3/test_m3.py
python tests/acceptance/m4/test_m4.py
python tests/acceptance/m5/test_m5.py
python tests/acceptance/m6/test_m6.py
python tests/acceptance/m7/test_m7.py
python tests/acceptance/m8/test_m8.py
python tests/acceptance/m9/test_reactive_pipeline.py
python tests/acceptance/m9/test_tetragon_adapter.py
python tests/acceptance/m9/test_realtime_integration.py
```
