---
name: agent-config-audit
version: 1.0.0
risk_tier: R1
reversible: true
description: >
  Static audit of AI agent configurations: instruction files (CLAUDE.md,
  AGENTS.md, .cursorrules, system prompts), MCP server registrations, hook
  definitions, and permission manifests. Detects hardcoded secrets, excessive
  permission grants, hook injection risk, MCP supply-chain exposure, and
  misconfigured trust boundaries. Read-only. No runtime execution of agent
  configs or MCP servers.
commands:
  - noartex task submit --module M4 --skill agent-config-audit
---

# Agent Configuration Audit Skill

## Purpose

Scan the static configuration surface of an AI agent deployment to find
exploitable misconfigurations before they are exercised at runtime. Covers
instruction files, MCP server registrations, tool permission manifests, and
hook definitions.

Adapted from architectural patterns in AgentShield (MIT license,
affaan-m/agentshield). No code or text copied verbatim; concepts
re-implemented independently under Apache-2.0.

## Scope

**In scope:**
- Agent instruction files: CLAUDE.md, AGENTS.md, .cursorrules, system prompts
  stored as files, custom instruction documents
- MCP server configuration: server URIs, transport types, authentication
  methods, declared tool scopes
- Hook definitions: pre-tool, post-tool, notification, and stop hooks
- Permission manifests: declared tool allow-lists and deny-lists
- Environment variable references in configs

**Out of scope:**
- Runtime behavior of agent systems (use M9 for runtime monitoring)
- Dynamic prompt injection via live input (use M8 for runtime threat
  correlation)
- Source code of the agent platform itself (use structured-audit)

## Check Categories

### C1 -- Hardcoded Secrets

Scan instruction files and config documents for:
- API keys matching known provider patterns (regex-based, no live validation)
- Bearer tokens, PATs, and SSH private key material
- Database connection strings with embedded credentials
- Environment variable expansion that resolves to a secret at load time

Finding threshold: any match in an agent instruction file or MCP config is HIGH
regardless of key validity, because the file is likely committed to version
control.

### C2 -- Excessive Permission Grants

Review declared tool allow-lists against least-privilege principle:
- Does the agent have write access to paths outside its declared working
  directory?
- Does the agent have unrestricted shell execution (bash, sh, arbitrary
  command tools)?
- Does the agent have network access beyond its declared upstream dependencies?
- Does the agent have access to credential stores, key management, or secrets
  managers?

Classify: necessary (documented justification present), excessive (no documented
justification), or unknown (no allow-list defined, implying all tools permitted).

### C3 -- Hook Injection Risk

For each registered hook:
- Is the hook code stored in the repository or fetched from an external URL?
- Is the external URL pinned to a specific commit hash or mutable
  (branch/tag)?
- Does the hook execute shell commands constructed from agent output or user
  input?
- Does the hook have access to environment variables that contain credentials?

A hook that fetches and executes remote code without integrity verification is
CRITICAL regardless of other factors.

### C4 -- MCP Server Supply Chain

For each registered MCP server:
- Is it pinned to a specific version or commit?
- Is it fetched via npx/uvx (mutable) or from a pinned local path/locked
  registry?
- Does it declare broader filesystem or network scope than the agent needs?
- Is the server from an organization with an auditable track record?

Flag any MCP server fetched at runtime from an unpinned source as HIGH.

### C5 -- Trust Boundary Misconfiguration

- Does the agent instruction file accept external content (URLs, file paths,
  git repositories) as inputs to its reasoning without sanitization guidance?
- Does the config enable direct prompt injection vectors (reading file content
  into context without sandboxing)?
- Are there wildcard user allowlists (*) in CI/CD-integrated agent configs?

## Output Format

Each finding:
- id: aca-NNN
- check: C1 through C5
- severity: CRITICAL / HIGH / MEDIUM / LOW
- location: file path and line or key
- description: what was found and why it matters
- evidence: quoted config fragment (redact actual secret values, show pattern
  only)
- remediation: specific, minimal fix

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill agent-config-audit \
  --target <agent-repo-path> \
  --policy R1
```

R1 posture: read-only file access, no network, no process execution.
