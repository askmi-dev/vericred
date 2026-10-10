# Security Policy

## Supported versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.1.x   | yes (development) | Pre-release; security fixes land on `main` |

No stable/LTS line exists yet. Security-relevant fixes are released as patch bumps within 0.1.x and announced in release notes.

## Reporting a vulnerability

**Do not open public issues for security problems.**

1. Email **askmi.dev@icloud.com** with subject `[vericred security]`.
2. Include: affected component/route, reproduction steps, impact assessment, and (if possible) a PoC.
3. Acknowledgement within 72 hours; assessment and triage within 14 days.
4. We will coordinate disclosure timing with you. Credit is given on request.

## Issuer key handling

- Signing keys are currently stored in configuration files, loaded at boot (`vericred.config.json` / environment). **Never commit real keys** — the repository accepts only `.env.example` placeholders.
- Keys are rotatable via configuration. Rotation procedure: generate new key → publish new JWKS/`did:web` document → keep old key for verification only → remove after credential expiry.
- **Production / high-assurance deployments must not use software-held keys.** Use an HSM or managed KMS; a pluggable adapter interface is planned (see roadmap). Until then, treat this gateway as dev/demo-grade for issuance trust.
- Compromise of an issuer key: rotate immediately, revoke status-list entries for affected credentials, and disclose to relying parties via the published trust list.

## Security model boundaries

- VeriCred authenticates data source admins and issues credentials; **holder/wallet security and verification are out of scope** (handled by the wallet and verifier components of the AskMI stack).
- PII masking is enabled by default. `PII_ADMIN_MODE` is an explicit override; its use should appear in access logs.
- All external input is validated with Zod schemas; unvalidated request bodies are rejected fail-closed.

## Disclosure policy

- Coordinated disclosure; we ask for up to 90 days before public disclosure of accepted vulnerabilities.
- Well-scoped reports will be credited in release notes (opt-in).
