---
name: process-isolation-audit
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Audits whether processes spawned by an AI agent or its governed skills are
  subject to appropriate OS-level isolation constraints. Checks for filesystem
  path restrictions, network namespace controls, capability bounding sets,
  resource limits, and sandbox policy completeness on Linux (seccomp,
  namespaces, cgroups) and macOS (sandbox-exec). Produces a gap analysis
  against a least-privilege baseline. Does not modify running processes.
commands:
  - noartex task submit --module M4 --skill process-isolation-audit
---

# Process Isolation Audit Skill

## Purpose

Verify that the OS-level isolation boundaries around agent-spawned processes
are complete and correctly configured. An agent that can spawn processes without
isolation constraints provides no meaningful sandbox guarantee, regardless of
higher-level policy controls.

Adapted from architectural concepts in the Anthropic Sandbox Runtime (srt)
(Apache-2.0, anthropic-experimental/sandbox-runtime). No code or text copied
verbatim; audit criteria re-implemented independently under Apache-2.0.

## Audit Dimensions

### A1 -- Filesystem Restrictions

For each process spawning mechanism used by the agent (subprocess, exec,
tool calls that run external commands):

1. Is there a declared filesystem allowlist restricting which paths the
   spawned process can read?
2. Is there a declared filesystem allowlist restricting which paths the
   spawned process can write?
3. Are paths outside the working directory and explicitly declared data
   directories blocked by default?
4. Are sensitive paths explicitly denied: /etc/passwd, /etc/shadow, ~/.ssh/,
   credential stores, NOARTEX runtime sockets, Tetragon sockets?
5. Is the enforcement mechanism OS-level (sandbox-exec profile, bubblewrap
   bind mounts, seccomp) or advisory-only (agent instruction)?

Advisory-only restrictions (instructions without OS enforcement) are
insufficient and classified as MEDIUM regardless of content.

### A2 -- Network Restrictions

1. Does the spawned process run in a network namespace separate from the
   host network?
2. If not namespace-isolated, is outbound network access restricted by an
   allowlist enforced at the proxy or firewall level?
3. Can the spawned process access loopback services that expose internal
   agent state (NOARTEX metrics ports, Tetragon gRPC, database sockets)?
4. Are DNS queries for the spawned process routed through a controlled
   resolver or unrestricted?

A process with unrestricted network access that also handles untrusted input
is a CRITICAL finding.

### A3 -- Capability Bounding (Linux)

If running on Linux:
1. Record the capability set of the spawned process (if inspectable from
   configuration).
2. Flag any capability beyond the minimum required: CAP_NET_ADMIN,
   CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE are HIGH by default
   in agent-spawned processes without documented justification.
3. Verify that the process does not inherit ambient capabilities from the
   agent parent.
4. Verify that seccomp filters are applied if the process handles untrusted
   input.

### A4 -- Resource Limits

1. Are explicit CPU, memory, process count, file descriptor, and wall-clock
   limits applied to spawned processes?
2. Are limits enforced at the OS level (ulimit, cgroup, systemd resource
   control) or advisory-only?
3. Is there a timeout that terminates stuck processes independent of the
   agent's own timeout logic?

Absence of enforced resource limits when the process handles untrusted input
is MEDIUM (denial of service vector).

### A5 -- Sandbox Policy Completeness

If a formal sandbox policy is used (sandbox-exec profile, bubblewrap config,
seccomp filter):
1. Is the policy in deny-by-default mode (allowlist) or allow-by-default
   (blocklist)?
2. Are the allowed operations the minimum necessary for the declared task?
3. Is the policy version-controlled alongside the code that uses it?
4. Is there a test that verifies the policy blocks the specific operations
   it is intended to block?

Allow-by-default policies and untested policies are HIGH.

## Minimum Isolation Baseline

A process spawned to handle untrusted input meets minimum isolation when:
- Filesystem: read-only access to its own source directory; write access
  only to an assigned scratch directory; no access to host home directory
  or credential stores.
- Network: no external network; loopback only within its own namespace if
  needed for local client/server test traffic.
- Capabilities: standard user, no elevated capabilities, seccomp applied.
- Resources: explicit CPU, memory, process, and wall-clock limits.
- Enforcement: OS-level, not advisory.

Any gap against this baseline is at minimum MEDIUM.

## Output Format

```
isolation-audit-report:
  evaluated_at: <ISO-8601>
  target: <process or tool description>
  enforcement_mechanism: <sandbox-exec | bubblewrap | seccomp | none | mixed>
  findings:
    - id: pia-NNN
      dimension: A1 | A2 | A3 | A4 | A5
      severity: CRITICAL | HIGH | MEDIUM | LOW
      description: <what gap was found>
      evidence: <config fragment or absence of config>
      remediation: <specific OS-level control to add>
  baseline_gaps:
    filesystem: compliant | non-compliant
    network: compliant | non-compliant
    capabilities: compliant | non-compliant
    resources: compliant | non-compliant
    enforcement: os-level | advisory-only
```

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill process-isolation-audit \
  --target <process-config-path> \
  --policy R2
```
