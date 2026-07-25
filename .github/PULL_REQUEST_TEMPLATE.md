## Summary

What does this PR change and why?

## Type of change

- [ ] Bug fix
- [ ] Feature
<<<<<<< HEAD
- [ ] Security / hardening
- [ ] Tests / CI
- [ ] Docs

## E2E / X5 impact

- [ ] No change to ciphertext, envelopes, call signaling, stories, or push payloads
- [ ] Changes sealed surfaces — tests updated (`test:security:x5` / crypto lanes)
=======
- [ ] Security / crypto hardening
- [ ] UI / UX
- [ ] Docs / CI

## Crypto checklist

- [ ] Private keys never leave the device or appear in logs
- [ ] Chat content remains sealed before network send
- [ ] Call signaling (if touched) uses X5 envelopes, not raw SDP/ICE
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f

## Checklist

- [ ] I read [CONTRIBUTING.md](../docs/CONTRIBUTING.md)
<<<<<<< HEAD
- [ ] `npm run test:security` (or the relevant lane) passes locally
- [ ] No secrets, private keys, or plaintext chat content in the diff
- [ ] Branch protection required checks are expected to pass
=======
- [ ] `npm run build` succeeds
- [ ] No secrets or key material in the diff
>>>>>>> 9d2bd3842e9cc45c912ac09908bd70f02464070f
