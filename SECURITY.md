# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in FORGE, please report it responsibly as described below.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Send a report to **opensource@dynatrace.com**. Include as much detail as possible:

- Type of issue (e.g., command injection, path traversal, credential exposure)
- Full path of the affected source file(s)
- Steps to reproduce
- Proof-of-concept or exploit code (if available)
- Impact assessment

### Response Process

We will acknowledge receipt within 5 business days and send regular updates as we investigate. The Dynatrace Open Source Community and the reporter will negotiate a public disclosure date. We prefer to fully remediate before public disclosure.

**Typical disclosure timeline:**
- Immediate if the vulnerability is already publicly known
- Within 7 days for issues with straightforward mitigations
- Several weeks for complex issues requiring significant code changes

## Important Note on Generated Artifacts

FORGE intentionally generates **vulnerable applications** for CVE research purposes. Container images, source code, and exploit scripts produced by FORGE are designed to be exploitable. These artifacts:

- Should **never** be deployed in production or exposed to untrusted networks
- May contain intentional weaknesses and mock credentials (by design)
- Are sandboxed within Podman containers with resource limits during FORGE runs

If you discover a genuine security issue in FORGE's own codebase (not in generated artifacts), please use the reporting process above.

---

This security policy is based on the [Dynatrace Open Source Security Policy](https://github.com/dynatrace-oss).
