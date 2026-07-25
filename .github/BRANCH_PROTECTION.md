# Required checks for `main`

Configure repository branch protection to require:

<<<<<<< HEAD
## Security and Vulnerability Detection System (L0–L4)

- Static Analysis
- Crypto Confidentiality
- Auth Abuse
- API Vuln Detection
- Transport Hardening
- Security Canary (must fail)
- E2E Ciphertext Confidentiality (must not decode)
- E2E X5 Invariants
- Socket Auth Security

## Supply chain (required)

- Dependency Review *(pull requests — npm audit high+)*
- Gitleaks

## Legacy / umbrella (recommended)

- Security Attack Suite
- Crypto Algorithms
- Backend Build
=======
## Build

- Frontend Build

## Security (required)

- npm audit (high+)
- Analyze *(CodeQL)*
- Gitleaks
- Crypto Static Guards
- Dependency Review *(pull requests — npm audit high+)*
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f

Require the branch to be up to date and disable administrator bypass.

## Not required for merge (scheduled / informational)

<<<<<<< HEAD
- Deep Fuzz and Stress (`security-nightly.yml`)
- OpenSSF Scorecard (`ossf-scorecard.yml`)
- SBOM (`sbom.yml`)

## External checks (not controlled by this repo)

- **Vercel** — “Authorization required to deploy” needs a team admin to open the
  Vercel authorize link on the PR (or reconnect the GitHub integration). It is not
  a backend code or security-suite failure.
=======
- OpenSSF Scorecard (`ossf-scorecard.yml`)

## External checks (not controlled by this repo)

- **Vercel** — “Authorization required to deploy” means a team admin must open the
  Vercel authorize link on the PR (or reconnect the GitHub integration). It is not
  a frontend code failure.
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f
