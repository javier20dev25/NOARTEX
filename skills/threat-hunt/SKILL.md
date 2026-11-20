---
name: threat-hunt
version: 1.0.0
risk_tier: R2
reversible: true
description: >
  Autonomous hypothesis-driven threat hunting across endpoint telemetry, process
  lineages, socket activity, and memory artifacts. Formulates explicit threat
  hypotheses, validates against sensor-attested facts, isolates attacker-authored
  inputs from sensor-grounded telemetry, and tracks visibility blind spots.
  Operates read-only under NOARTEX governance.
commands:
  - noartex task submit --module M4 --skill threat-hunt
---

# Threat Hunt Skill

## Purpose

Execute structured, hypothesis-driven threat hunting investigations across
system telemetry without relying on pre-existing static alert signatures.
Validates suspected threat actor behavior (such as ARTEX-class autonomous
adversary patterns), identifies lateral movement, credential extraction,
and covert execution loops.

Adapted from architectural patterns in Vigil SOC (open source, Apache-2.0)
and DFIR hunting workflows. Independently implemented under Apache-2.0.

## Core Hunting Principles

1. **Hypothesis-First Investigation:**
   Every hunt begins with an explicit, falsifiable technical hypothesis.
   Example: "An unauthorized interpreter process spawned by a service worker
   is accessing credential paths or initiating loopback/egress sockets."

2. **Evidentiary Authorship Triangulation:**
   Every evaluated record must be classified by its source of authority:
   - `sensor`: Facts verified by the kernel or telemetry agent that the adversary
     cannot rewrite without full kernel compromise (process PID, PPID, kernel
     timestamps, connection socket 5-tuples, verified binary hashes).
   - `adversary`: Data fields chosen or malleable by the attacker (process names,
     command-line arguments, file paths, User-Agent strings, injected headers).
   - `third_party`: Claims provided by external reputation services or feeds.
   A hunt verdict can never rest solely on adversary-controlled or third-party
   claims without corroborating sensor-level evidence.

3. **Visibility Gap Accounting:**
   A query that returns zero matches or times out is NOT proof of benign state.
   It must be recorded as an epistemic blind spot (`visibility_gap: true`) and
   factored into the final confidence calculation.

## Hunt Execution Pipeline

### Stage 1 -- Hypothesis Formulation & Scoping

1. Define hypothesis identifier and threat model target (e.g., T1059.004 Unix Shell,
   T1003 OS Credential Dumping, T1071 Application Layer Protocol).
2. Define observable bounds: target entities (host, user, container, cluster),
   time window (start and end timestamps), and required telemetry domains.
3. Validate telemetry adapter availability (`adapter.observer.host`,
   `adapter.observer.tetragon.stream`, `adapter.observer.web`).

### Stage 2 -- Telemetry Interrogation

Query relevant telemetry domains using structured read-only filters:
- Process Lineage: Trace ancestor chains (PPID -> PID -> child processes) to
  detect unexpected execution breaks (e.g., web server spawning bash or python).
- File System Access: Identify reads or writes to sensitive stores
  (/etc/passwd, /etc/shadow, ~/.ssh, application secret files, environment stores).
- Socket Telemetry: Interrogate local listening ports, established outbound
  connections, and sudden bursts of non-standard protocol traffic.
- Memory & Module Integrity: Check for dynamically injected modules or
  anomalous shared library mappings.

### Stage 3 -- Adversarial Pattern Disambiguation

Differentiate legitimate administrative tasks from autonomous adversary activity:
- Reject the assumption that administrative credentials imply benign intent.
- Evaluate command burstiness, tokenized evasion sequences, and automated
  directory reconnaissance characteristic of machine-driven agent attacks.
- Correlate temporal proximity between unexpected file access and subsequent
  socket connections.

### Stage 4 -- Hypothesis Resolution & Verdict

Assign one of the four NOARTEX deterministic verdicts:
- `CONFIRMED`: Corroborated sensor evidence directly demonstrates the
  hypothesized malicious activity.
- `PARTIAL`: Suspicious anomalous indicators found, but key sensor telemetry
  is missing or incomplete.
- `FALSE_POSITIVE`: Disproved by confirmed legitimate process origin, approved
  maintenance window, or non-malicious workflow proof.
- `UNKNOWN`: Inconclusive due to telemetry gaps or query failures.

## Output Format

```yaml
threat_hunt_result:
  hunt_id: "hunt-YYYYMMDD-XXXX"
  hypothesis: "Process lineage anomaly with credential store access"
  verdict: "CONFIRMED | PARTIAL | UNKNOWN | FALSE_POSITIVE"
  confidence: "HIGH | MEDIUM | LOW"
  mitre_techniques:
    - "T1059"
    - "T1003"
  evidence:
    - field: "process.executable"
      value: "/usr/bin/python3"
      authorship: "sensor"
    - field: "process.args"
      value: "dump_secrets.py"
      authorship: "adversary"
    - field: "file.target"
      value: "/srv/secrets/app-secret.txt"
      authorship: "sensor"
  visibility_gaps:
    - domain: "network_flow"
      reason: "adapter buffer overrun during event window"
  recommended_action: "escalate_to_containment | continue_monitoring | dismiss"
```

## NOARTEX Integration

```bash
noartex task submit \
  --module M4 \
  --skill threat-hunt \
  --params '{"hypothesis": "ARTEX agent lateral movement", "window_minutes": 60}' \
  --policy R2
```
