# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main` (latest) | Yes |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

<<<<<<< HEAD
Use [GitHub Private Vulnerability Reporting](https://github.com/QuantumLogicsLabs/QuantumChat-Backend/security/advisories/new) on this repository.

Include:

- Affected endpoints, events, or components
- Reproduction steps and expected vs actual behavior
- Impact (confidentiality / integrity / availability)
- PoC only when it stays non-destructive

### What to expect

- Acknowledgement when maintainers triage the report
- Coordination on fix and disclosure timing
=======
Use [GitHub Private Vulnerability Reporting](https://github.com/QuantumLogicsLabs/QuantumChat-Frontend/security/advisories/new).

Include reproduction steps, affected UI flows, and impact. Prefer non-destructive PoCs.

### What to expect

- Triage acknowledgement
- Coordinated fix and disclosure
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f
- Credit when appropriate and desired

## In scope

<<<<<<< HEAD
- Auth bypass, JWT misuse, rate-limit evasion with security impact
- IDOR / privilege escalation
- Injection (NoSQL, path traversal, unsafe deserialization)
- E2E / X5 regressions (server storing or notifying plaintext chat content)
- Broken sealed call signaling, story envelopes, or push blindness
- Secrets leakage in logs, artifacts, or CI

## Out of scope

- Lost client keyrings / `keys.txt`
- Compromised user devices
- Pure DoS without a practical, actionable exploit
- Issues solely in Frontend or QuantumAI (report to those repos)

## XSS controls

- Helmet CSP for API responses (`default-src 'none'`), `nosniff`, `frameguard: deny`
- Avatar / group photo / story image uploads allowlist JPEG, PNG, WebP, GIF only (no SVG)
- Served media uses allowlisted `Content-Type` (does not trust client MIME for raster images)

## Safe harbor

Good-faith research that follows this policy and avoids privacy abuse or destructive
testing will not be pursued legally by the maintainers.
=======
- Private key / keyring exposure (logs, exports, storage bugs)
- Plaintext message or call-signaling leakage to the network
- XSS or client bugs that steal session tokens or key material
- Broken seal/unseal or key-import validation
- Dependency issues with a realistic exploit path in this app

## Out of scope

- Users who lose `keys.txt` or clear site data
- Compromised devices / malicious browser extensions (general)
- Backend-only issues (report to QuantumChat-Backend)

## XSS controls

- Content-Security-Policy on the SPA (`script-src 'self'`, no inline scripts)
- Chat text rendered as React text nodes (escaped)
- SVG attachments are not image-previewed; PDF iframes use `sandbox="allow-same-origin"`
- Avatar file picker limited to raster image types

## Safe harbor

Good-faith research that follows this policy and avoids abusing real users’ data
will not be pursued legally by the maintainers.
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f
