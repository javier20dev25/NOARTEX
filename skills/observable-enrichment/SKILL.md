---
name: observable-enrichment
version: 1.0.0
risk_tier: R1
reversible: true
description: >
  Deep observable investigation and multi-source enrichment for IP addresses,
  domains, file hashes, URLs, process names, and system entities. Implements
  structured analyzer contracts, multi-feed consensus scoring, cache invalidation,
  and anti-bias safeguards. Never assumes unknown observables are benign.
commands:
  - noartex task submit --module M4 --skill observable-enrichment
---

# Observable Enrichment Skill

## Purpose

Enrich and contextualize security observables extracted from raw telemetry or
incident alerts. Standardizes evidence intake across heterogeneous threat
intelligence feeds, local historical databases, and contextual lookups.

Adapted from architectural patterns in Cortex Analyzers and TheHive
(open source, AGPL-3.0/GPL-3.0 concepts re-implemented under Apache-2.0
clean-room architecture).

## Investigative Principles

1. **Absence of Proof is Not Proof of Absence:**
   An observable that returns no hits in threat intelligence feeds or known
   blocklists is categorized as `UNSEEN` or `NEUTRAL`, never `BENIGN`. Zero-day
   adversary infrastructure and newly registered domains frequently exhibit
   clean reputations.

2. **Multi-Source Corroboration:**
   Single-source reputation hits are weighted conservatively. Confirmed
   attribution requires corroboration across multiple independent intelligence
   providers, historical telemetry patterns, or active local telemetry.

3. **Contextual Normalization:**
   Observables are mapped into standardized entity types before analysis:
   `ip_v4`, `ip_v6`, `fqdn`, `url`, `hash_sha256`, `hash_md5`, `process_path`,
   `user_account`.

## Analyzer Pipeline

### Stage 1 -- Observable Intake & Validation

1. Validate observable syntax and normalize formatting (lowercase domains,
   strip tracking parameters from URLs, validate CIDR and hash length).
2. Filter out RFC 1918 private IP ranges, loopback addresses (127.0.0.0/8),
   and standard internal domains unless the investigation explicitly targets
   internal lateral movement.

### Stage 2 -- Reputation & Metadata Lookup

Query configured intelligence sources (local Threat Intel Vault, CISA KEV
snapshots, OSV, and connected API adapters):
- Passive DNS: First seen, last seen, historical resolving IPs.
- Domain Age & Registrar: Flags newly registered domains (< 30 days old).
- Certificate Transparency: Validates SSL/TLS subject names, issuer authority,
  and self-signed certificates.
- File Hash Reputation: Matches against known malware signatures, compiler
  timestamps, and import table hashes (imphash).

### Stage 3 -- Local Context Correlation

Check local system memory and historical incident ledgers (NOARTEX M7 Memory):
- Has this observable been seen in prior investigations on the host or cluster?
- Is the observable linked to a legitimate CI/CD runner, admin user, or
  known service dependency?
- Has this observable been flagged in a previous FALSE_POSITIVE review?

### Stage 4 -- Consensus Scoring

Synthesize intelligence scores into an auditable classification:
- `MALICIOUS`: Verified adversary infrastructure, active C2 node, or confirmed
  exploit payload.
- `SUSPICIOUS`: High anomaly score, dynamic DNS usage, newly registered domain,
  or association with low-reputation ASNs without confirmed malicious payload.
- `BENIGN_VERIFIED`: Cryptographically signed system binary, verified provider
  infrastructure, or explicitly allowlisted internal endpoint.
- `UNKNOWN`: Insufficient intelligence to confirm or refute risk.

## Output Format

```yaml
enrichment_result:
  observable: "198.51.100.23"
  type: "ip_v4"
  verdict: "SUSPICIOUS"
  confidence: "MEDIUM"
  first_seen: "2026-11-18T04:12:00Z"
  tags:
    - "asn:bulletproof_hoster"
    - "geo:offshore"
    - "port:8443_non_standard_https"
  feed_hits:
    - provider: "local_threat_vault"
      score: 65
      verdict: "suspicious"
    - provider: "cisa_kev"
      score: 0
      verdict: "unlisted"
  local_context:
    seen_in_cluster: false
    matched_allowlist: false
  recommendation: "restrict_egress_and_trace_process_lineage"
```

## NOARTEX Integration

```bash
noartex task submit \
  --module M4 \
  --skill observable-enrichment \
  --params '{"observable": "198.51.100.23", "type": "ip_v4"}' \
  --policy R1
```
