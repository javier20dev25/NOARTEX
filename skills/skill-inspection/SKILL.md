---
name: skill-inspection
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Static and semantic inspection of third-party skills and plugins before
  registration in NOARTEX or any governed agent platform. Detects prompt
  injection patterns, privilege escalation instructions, exfiltration
  indicators, supply-chain risks, and policy violations. Runs deterministic
  analysis first; optional semantic analysis requires explicit authorization.
  Produces a registration decision: APPROVE / CONDITIONAL / REJECT.
commands:
  - noartex task submit --module M4 --skill skill-inspection
---

# Skill Inspection Skill

## Purpose

Vet a third-party skill or plugin before allowing it to operate under NOARTEX
governance. A skill that bypasses the policy engine, claims permissions it was
not granted, or contains prompt injection payloads must be rejected before
registration.

Adapted from architectural patterns in NVIDIA SkillSpector (Apache-2.0) and
Cisco AI Defense Skill Scanner (Apache-2.0, cisco-ai-defense/skill-scanner).
No code or text copied verbatim; detection categories re-implemented
independently under Apache-2.0.

## Inspection Pipeline

### Stage 1 -- Load and Normalize

1. Accept the skill as a directory, archive, or SKILL.md file path.
2. Extract all text files: SKILL.md, instruction documents, scripts,
   templates.
3. Identify the skill format: NOARTEX SKILL.md, Anthropic skill, Cursor rule,
   OpenAI assistant instruction, or unknown.
4. Record declared metadata: name, version, author, declared permissions,
   declared risk tier.

### Stage 2 -- Static Pattern Analysis

Run deterministic pattern matching before any semantic analysis.

**P1 -- Prompt Injection Payloads**
Patterns indicating the skill attempts to override system instructions:
- Phrases: "ignore previous instructions", "disregard the above",
  "new instruction", "you are now", "your true purpose", "pretend you are",
  "act as if"
- Encoded variants: base64-encoded instruction overrides, unicode homoglyphs
  substituting ASCII in commands
- Invisible text: zero-width characters, whitespace-padded content designed
  to hide in rendered output

Severity: CRITICAL if present in any instruction text.

**P2 -- Privilege Escalation**
Instructions that attempt to obtain permissions beyond declared scope:
- Requests to read files outside declared working directories
- Requests to execute shell commands not in the declared tool allow-list
- Instructions to register additional MCP servers or modify agent configuration
- Instructions to access credential stores, environment variables containing
  secrets, or key management services

Severity: HIGH if present.

**P3 -- Exfiltration Indicators**
Instructions that direct the agent to send data to external destinations:
- Hardcoded URLs receiving agent context, tool outputs, or user data
- Instructions to include session content in ostensibly unrelated outputs
- Steganographic techniques: encoding data in file names, commit messages,
  or binary content

Severity: CRITICAL if the destination is external and not in the declared
egress allowlist.

**P4 -- Supply Chain Risk**
- Does the skill fetch and execute remote code at runtime (curl | sh pattern)?
- Does the skill reference external resources by mutable identifier (branch,
  latest tag) rather than pinned hash?
- Does the skill declare dependencies on packages with no published source?

Severity: HIGH for mutable remote execution, MEDIUM for unverifiable
dependencies.

**P5 -- Policy Violation**
- Does the skill declare a risk tier lower than its actual capabilities
  warrant?
- Does the skill include instructions to suppress audit logging?
- Does the skill include instructions to modify NOARTEX policy or session
  state?

Severity: HIGH.

### Stage 3 -- Semantic Analysis (optional, R3 required)

If static analysis produces no CRITICAL findings and the registering operator
requests semantic analysis:

1. Present the skill text and detected static findings to a sandboxed
   inference context.
2. Ask the inference context to identify instruction patterns not covered by
   static rules.
3. Record semantic findings separately; they require human review before
   influencing the registration decision.

Semantic analysis requires explicit R3 authorization from the NOARTEX policy
engine. It is not run by default.

### Stage 4 -- Registration Decision

**APPROVE**: No CRITICAL or HIGH findings. MEDIUM findings documented and
accepted by the registering operator.

**CONDITIONAL**: HIGH findings present but have documented mitigations. The
operator must acknowledge each HIGH finding and provide written justification.
NOARTEX logs the acknowledgment in the audit trail.

**REJECT**: Any CRITICAL finding, or HIGH findings without accepted mitigation.
The skill is not registered. The rejection is logged with the finding list.

## Output Format

```
skill-inspection-report:
  skill: <name>
  version: <version>
  reviewed_at: <ISO-8601>
  decision: APPROVE | CONDITIONAL | REJECT
  findings:
    - id: si-NNN
      stage: P1 | P2 | P3 | P4 | P5 | semantic
      severity: CRITICAL | HIGH | MEDIUM | LOW
      location: <file>:<line>
      description: <what was found>
      evidence: <quoted fragment, truncated to 200 chars>
```

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill skill-inspection \
  --target <skill-path> \
  --policy R2
```
