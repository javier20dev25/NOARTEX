---
name: egress-audit
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Static and behavioral analysis of outbound network access patterns in agent
  deployments. Identifies unauthorized exfiltration paths, overly broad egress
  allowlists, unmediated tool-call network access, and absence of egress control
  infrastructure. Does not perform live network testing. Produces a remediation
  plan specifying minimum required egress rules.
commands:
  - noartex task submit --module M4 --skill egress-audit
---

# Egress Audit Skill

## Purpose

Determine whether an agent deployment has appropriate controls on outbound
network access. Unconstrained egress is the primary exfiltration vector for
compromised agents and malicious tool calls.

Adapted from architectural threat model concepts in Pipelock (Apache-2.0,
pipelab-org/pipelock). No code or text copied verbatim; concepts
re-implemented independently under Apache-2.0.

## Analysis Phases

### Phase 1 -- Declared Egress Surface

Enumerate all declared outbound connections from configuration and source:
1. MCP server upstreams (HTTP/HTTPS endpoints, local sockets, stdio)
2. Tool-call targets: APIs, file systems, databases, shell commands that
   invoke network utilities (curl, wget, fetch, requests, http.client)
3. Webhook and notification targets in hook definitions
4. Telemetry and logging endpoints
5. Package manager registries used at runtime (npm, pip, cargo)

For each: record protocol, host pattern, port, authentication method, and
whether the connection is to a fixed host or to an agent-determined host.

### Phase 2 -- Egress Control Infrastructure Check

Determine whether a network-level egress control is present:
- Is agent traffic routed through a proxy or firewall that can enforce policy?
- Is there an explicit allowlist of permitted outbound hosts/ports?
- Is direct egress from the agent process prevented by OS/container/network
  controls (seccomp, network namespace, iptables/nft OUTPUT rules)?
- Are MCP server connections mediated through a policy-aware middleware layer?

Absence of egress control infrastructure when the agent has shell access or
unrestricted network tools is a CRITICAL finding.

### Phase 3 -- Exfiltration Path Analysis

For each declared tool or capability with network access:
1. Can agent-generated content (including tool outputs and user data) be
   included in the outbound payload?
2. Can the destination host be controlled by agent output rather than fixed
   configuration?
3. Is there a DLP (data-loss prevention) layer inspecting outbound payloads?
4. Are credential values excluded from outbound logging and telemetry?

### Phase 4 -- Minimum Required Egress

Produce a minimum-required egress specification:
- List every host:port pair that the agent legitimately needs to reach.
- Flag any tool or capability that requires agent-determined destinations
  (inherently high risk; document the justification or recommend removal).
- Produce an allowlist in a format compatible with common proxy configurations
  (domain-based, not IP-based, to handle CDN rotation).

## Output Format

Each finding:
- id: ea-NNN
- phase: 1 through 4
- severity: CRITICAL / HIGH / MEDIUM / LOW
- component: which tool, hook, or MCP server
- description: what path exists and why it is a risk
- remediation: specific control to add

Minimum egress specification: a plain list of host patterns with justification.

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill egress-audit \
  --target <agent-deployment-path> \
  --policy R2
```
