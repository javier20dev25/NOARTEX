# Security Policy

## Supported Versions

NOARTEX is a defensive capability governance and control plane for AI agents. Security updates and patches are actively applied to the primary release branch and latest minor tags.

| Version | Supported          | Status                                      |
|---------|--------------------|---------------------------------------------|
| 0.9.x   | Yes                | Active development & security patches       |
| 0.8.x   | Limited (Critical) | Security hotfixes only                      |
| < 0.8.0 | No                 | End of life; upgrade to >= 0.9.0-m9         |

---

## Reporting a Vulnerability

We prioritize the security and integrity of NOARTEX, its policy engine, and the runtime defense stack. If you discover a vulnerability, policy bypass, elevation of capability privilege, sandbox escape, or tampering vector, please report it responsibly under coordinated disclosure.

### Private Reporting Channel

**DO NOT file public GitHub Issues or PRs for security vulnerabilities.**

Direct all vulnerability reports to the project maintainer's personal email:

- **Personal Security Contact:** `sleytherjavier2025@gmail.com`
- **Subject Line:** `[NOARTEX-SECURITY] <Vulnerability Short Summary>`

Alternatively, if you prefer using GitHub's native advisory infrastructure:
- Use the **Report a vulnerability** button under the repository's [Security Advisories](https://github.com/javier20dev25/NOARTEX/security/advisories) tab.

> Note: For general agency inquiries, architectural questions, or enterprise research collaborations, use the NIGHTTRACE agency address (`nighttracesec@gmail.com`). For actual vulnerability findings, security flaws, and zero-day disclosures, use the personal email specified above (`sleytherjavier2025@gmail.com`) to ensure direct and immediate triage by the lead author.

---

## What to Include in Your Report

To help us investigate, triage, and remediate the issue promptly, please include:

1. **Description:** Clear summary of the flaw, its root cause, and affected components (`core/policy`, `core/reactive`, `adapters/tetragon_stream`, `cli`, etc.).
2. **Impact Assessment:** Severity, attack vector, and potential impact on defensive agents or host isolation (e.g., policy bypass from R2 to R0, stream interception, PID race condition).
3. **Reproducible Proof of Concept (PoC):** Step-by-step instructions, minimal reproducible code snippet, or JSON task payload demonstrating the issue.
4. **Environment Details:** Operating System (Linux kernel / WSL2 / Windows), Python version, NOARTEX version/commit, and active adapters.
5. **Proposed Remediation (Optional):** Suggested patch or architectural fix, if identified.

---

## Response and Disclosure Timelines

- **Initial Acknowledgment:** Within 48 hours of receipt.
- **Triage & Severity Confirmation:** Within 5 business days, including an estimated timeline for remediation.
- **Remediation Release:** A security patch and coordinated advisory will be prepared and tested against the full acceptance regression suite.
- **Coordinated Public Disclosure:** Typically coordinated 90 days following initial report, or sooner upon mutual agreement once patches are deployed.
