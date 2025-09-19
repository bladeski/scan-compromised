# Security Policy

## Reporting a Vulnerability

- **Primary channel:** Use GitHub’s private advisories.  
  In the repository, go to **Security → Report a vulnerability** and follow the prompts.
- **What to include:**
  - **Description:** What’s the issue, and why is it a security risk?
  - **Impact:** Who/what is affected; potential worst case.
  - **Versions:** Affected package version(s) and environment details.
  - **Reproduction:** Minimal steps, PoC code, or sample inputs.
  - **Mitigations:** Any known workarounds or configuration changes.
  - **Research context:** If part of coordinated disclosure, include timelines or IDs.

> Please do not open public issues for security reports. Use the private channels above.

---

## Supported Versions

| Version range     | Status      | Notes                                      |
| ----------------- | ----------- | ------------------------------------------ |
| Latest major (N, N‑1) | Supported   | Security fixes and critical bug fixes      |
| Older than N‑1    | Not supported | Please upgrade to a supported version      |

We may backport critical fixes case‑by‑case if upgrading is infeasible.

---

## Handling Process and Timelines

- **Acknowledgement:** We reply within 3 business days.
- **Triage:** We assess impact/severity within 7 days.
- **Fix window:** Target timelines after confirmation:
  - **Critical/High:** 30 days
  - **Medium:** 60 days
  - **Low/Informational:** 90 days
- **Advisory:** We publish a GitHub security advisory with CVE/CVSS details once a fix or mitigation is available and coordinate a disclosure date with you.
- **Communication:** We’ll keep you updated at key milestones (triage, fix in review, release scheduled, publication).

---

## Severity, Scope, and What We Accept

- **Severity model:** CVSS v3.1. Provide your vector if you have one; we will independently validate.
- **In scope examples:**
  - Remote code execution via package APIs, configuration, or supply chain.
  - Privilege escalation / sandbox escape within documented use.
  - Data integrity issues: tampering, unsafe defaults, or bypass of intended verification.
  - Denial of service: significant and repeatable resource exhaustion via normal interfaces.
  - Supply chain risks: typosquatting, compromised dependencies, unsafe transitive behavior.
- **Out of scope examples:**
  - Best‑practice requests (e.g., missing headers) not affecting this package.
  - Deprecated/unsupported versions (older than N‑1).
  - Experimental flags or undocumented behavior not intended for production.
  - Environmental issues caused solely by misconfiguration outside the package.
  - Duplicate reports of previously reported issues.

---

## Disclosure Policy and Safe Harbor

- **Coordinated disclosure:** Keep reports private. We coordinate a public advisory after a fix/mitigation is available, or after a mutually agreed embargo.
- **Researcher credit:** We credit reporters in the advisory unless you prefer anonymity.
- **Safe harbor:** We will not pursue legal action for good‑faith, non‑destructive research that:
  - Respects privacy: no data exfiltration or unnecessary access.
  - Avoids harm: no service disruption, degradation, or lateral movement.
  - Acts within scope: only targets this package and its documented interfaces.
  - Uses private channels: reporting via the mechanisms above.
  - Follows laws: complies with applicable regulations.

---

## Release and Remediation

- **Fix strategy:** Prefer minimal, backwards‑compatible patches; may introduce opt‑in hardening for breaking mitigations.
- **Pre‑release validation:** Security fixes receive targeted tests and, where applicable, fuzz or negative testing.
- **Advisory contents:** Impact, affected versions, CVSS, remediation steps, and references.
- **Distribution:**
  - Git tag: semantic versioned release notes calling out security impacts.
  - npm: patched versions published promptly; previous vulnerable versions are not unpublished but will be marked as affected in advisory metadata.
- **Consumer guidance:**
  - Upgrade: we will recommend the minimal safe version to upgrade to.
  - Mitigations: if upgrade is not possible, we’ll provide configuration or operational workarounds when available.
