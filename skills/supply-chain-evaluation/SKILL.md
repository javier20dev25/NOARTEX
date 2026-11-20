---
name: supply-chain-evaluation
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Evaluates the supply chain integrity of packages, tools, and dependencies
  that an AI agent or its governed skills execute at runtime. Covers package
  provenance, version pinning, lockfile integrity, maintainer trust indicators,
  typosquatting risk, and known-vulnerability status. Produces a risk-tiered
  dependency manifest. Does not execute dependency code.
commands:
  - noartex task submit --module M4 --skill supply-chain-evaluation
---

# Supply Chain Evaluation Skill

## Purpose

Assess the trustworthiness of the software supply chain that an agent
deployment depends on. A compromised dependency or malicious package can
undermine all higher-level security controls, including NOARTEX governance.

Concepts studied from Trail of Bits supply-chain-risk-auditor (CC BY-SA 4.0 --
concepts only, re-implemented independently; no code or text from that
repository is included) and Cisco AI Defense Skill Scanner (Apache-2.0).
Independently implemented under Apache-2.0.

## Evaluation Dimensions

### D1 -- Lockfile Integrity

1. Verify that a lockfile exists (package-lock.json, yarn.lock, Pipfile.lock,
   uv.lock, Cargo.lock).
2. Verify the lockfile is committed to version control and not in .gitignore.
3. Verify that the lockfile hashes match the declared package versions
   (do not install; check the manifest structure for hash fields).
4. Flag any dependency present in the manifest but absent from the lockfile.
5. Flag any dependency with a mutable version specifier (^, ~, >=, *) in
   the manifest that could resolve to a different version than the lockfile
   records.

### D2 -- Provenance

For each direct dependency:
1. Confirm the package exists in the expected registry under the expected
   namespace (e.g., @org/package vs package).
2. Check for typosquatting risk: packages whose names differ from popular
   packages by one character, transposition, or common homoglyph substitution.
3. Confirm the package source URL in the lockfile points to the expected
   registry, not a custom registry that could be an attacker-controlled
   mirror.
4. Flag packages installed from git URLs without pinned commit hashes.
5. Flag packages installed from local paths in production manifests.

### D3 -- Maintainer Trust Indicators

For each direct dependency (read-only metadata check):
1. Record whether the package has a published security policy.
2. Record the publish date of the pinned version -- versions published very
   recently (< 7 days) for a package with a long stable history warrant
   review.
3. Flag packages that have transferred ownership within the last 90 days if
   registry metadata is available locally.
4. Flag packages with a single maintainer and no organizational backing for
   dependencies classified as critical path.

### D4 -- Known Vulnerability Status

Cross-reference each dependency version against:
- Local OSV database snapshot if available (osv-scanner compatible format)
- NOARTEX local threat intelligence store if available:
  noartex task submit --module M4 --capability intelligence.supply_chain.vuln_lookup

Do not make live network requests to vulnerability databases during the scan.
Document any database staleness (snapshot age > 30 days) in the report.

### D5 -- Runtime Fetch Risk

Identify any pattern in the agent's skills, hooks, or configuration that
fetches and executes code at runtime without integrity verification:
- curl/wget piped to sh or python
- npx/uvx with mutable package specifiers
- dynamic import() of paths constructed from user or agent input
- MCP servers that fetch plugin code on first use

Each instance is HIGH regardless of the fetched content, because the fetch
target can be changed by a supply-chain compromise.

## Output Format

```
supply-chain-report:
  evaluated_at: <ISO-8601>
  manifest_file: <path>
  lockfile: <path | MISSING>
  findings:
    - id: sce-NNN
      dimension: D1 | D2 | D3 | D4 | D5
      severity: CRITICAL | HIGH | MEDIUM | LOW
      package: <name@version>
      description: <what was found>
      remediation: <specific action>
  risk_summary:
    CRITICAL: N
    HIGH: N
    MEDIUM: N
    LOW: N
```

## NOARTEX Integration

```
noartex task submit \
  --module M4 \
  --skill supply-chain-evaluation \
  --target <project-path> \
  --policy R2
```
