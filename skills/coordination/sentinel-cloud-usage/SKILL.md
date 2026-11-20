---
name: sentinel-cloud-usage-via-cli
description: Governed guidance for using Sentinel Cloud-backed capabilities through a user-configured Sentinel CLI, without embedding Sentinel Cloud code or credentials in NOARTEX.
---

# Sentinel Cloud Usage via Sentinel CLI (No Cloud Code in NOARTEX)

## Scope
- NOARTEX does **not** include Sentinel Cloud backend code, SDK/client implementation, or stored Cloud credentials.
- Some Sentinel CLI commands/features may interact with Sentinel Cloud **only when the user has configured Sentinel CLI** (endpoint/auth/API key/tokens/pulses as applicable).

## Coordination rules
1. Use NOARTEX `adapter.sentinel.cli` capabilities for local/governed Sentinel CLI operations where available.
2. Before any Cloud-backed CLI action, confirm: user intent, CLI configuration/auth state, data to be sent, and policy/approval requirements.
3. Treat networked/cloud actions as explicit external transmissions; disclose scope to the user.
4. Never copy API keys into NOARTEX files, logs, cases, or skills. Credentials belong to user-managed Sentinel CLI/env configuration.
5. Capture command, target, result summary, and limitations in NOARTEX audit/memory records without secrets.

## Boundaries
- If Sentinel CLI is unavailable, degraded, or not authenticated for Cloud actions, report `UNAVAILABLE`/`DEGRADED`/denied honestly.
- Cloud results are external evidence inputs; validate and correlate before high-impact decisions.
- This skill does not grant cloud access and does not implement cloud APIs.
