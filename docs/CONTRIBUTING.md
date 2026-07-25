<<<<<<< HEAD
# Contributing to QuantumChat Backend

Thanks for contributing to the QuantumChat API and real-time relay.

## Before you start

1. Read the product rules in the meta repo: [`docs/REQUIREMENTS.md`](https://github.com/QuantumLogicsLabs/QuantumChat/blob/main/docs/REQUIREMENTS.md).
2. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
3. For vulnerabilities, use [SECURITY.md](SECURITY.md) — never file a public issue.
=======
# Contributing to QuantumChat Frontend

Thanks for contributing to the QuantumChat client — where all message encryption happens.

## Before you start

1. Read [`docs/REQUIREMENTS.md`](https://github.com/QuantumLogicsLabs/QuantumChat/blob/main/docs/REQUIREMENTS.md) (E2E X5 rules).
2. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
3. Report vulnerabilities via [SECURITY.md](SECURITY.md), not public issues.
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f

## Development setup

```bash
npm ci
<<<<<<< HEAD
cp .env.example .env   # set MONGODB_URI and JWT_SECRET
npm run dev            # http://localhost:5000
```

## Security checks (required)

A failing security suite is a **merge blocker**:

```bash
npm run test:security
```

Useful lanes:

- `npm run test:security:crypto`
- `npm run test:security:x5`
- `npm run test:security:auth`
- `npm run test:security:api`
- `npm run test:security:socket`

See [README.md](../README.md) and [`.github/BRANCH_PROTECTION.md`](../.github/BRANCH_PROTECTION.md).

## Pull requests

1. Keep PRs focused (one concern per PR when practical).
2. Do not weaken E2E X5 invariants (server must not need plaintext for chat content).
3. Add or update security tests when changing crypto, auth, or authorization surfaces.
4. Fill out the pull request template.
5. Ensure GitHub Actions required checks pass.
=======
cp .env.example .env   # VITE_API_URL → backend, default http://localhost:5000
npm run dev            # http://localhost:5173
```

You typically also need [QuantumChat-Backend](https://github.com/QuantumLogicsLabs/QuantumChat-Backend) running locally.

## Checks before a PR

```bash
npm run build
```

CI also runs CodeQL, `npm audit`, Gitleaks, and crypto static guards. Do not introduce:

- Plaintext WebRTC SDP/ICE on `call:*` socket emits (use sealed envelopes)
- Logging of private keys / seeds
- Sending message plaintext to the API or QuantumAI without an explicit client opt-in path

## Pull requests

1. Keep changes focused.
2. Preserve client-held keys and X5 sealed-box behavior.
3. Fill out the PR template.
4. Ensure required GitHub Actions checks pass.
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](../LICENSE).
