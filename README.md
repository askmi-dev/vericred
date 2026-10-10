# VeriCred

> **Open-source credential issuer gateway.** Connect your existing database or user store and start issuing W3C / SD-JWT-VC credentials via OID4VCI — without building issuer infrastructure yourself.

**Status: early stage (v0.1.x).** Development/demo-hardened; not certified under eIDAS, not audited, not production-ready for high-assurance use. See [Security](SECURITY.md) and the roadmap notes below.

## What VeriCred is

- An **issuer-side gateway**: it takes identity attributes you already hold (e.g. in SQL/Postgres, HR or CRM systems) and issues **selectively disclosable credentials** (SD-JWT VC) over **OID4VCI**.
- Standards-based: [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html), [OID4VCI](https://openid.net/specs/openid-4-vc-high-assurance-1_0.html), [StatusList2021](https://www.w3.org/TR/vc-status-list/) style revocation, `did:web` issuer identifiers.
- Deliberately **not** a wallet, verifier or presentation layer — that role is delegated to the [AskMI/miTch](https://github.com/Late-bloomer420/miTch) stack.

## What VeriCred is not

- **Not a blockchain project** — no on-chain identity data, no ledger dependency.
- **Not an identity provider** — it bridges *your* authoritative data into credential form.
- **Not certified** — no eIDAS/LoA conformance claims are made. Test coverage exists (151 backend tests incl. auth-bypass regression, EUDI interop suite), but formal review is pending.

## Quickstart

```bash
git clone https://github.com/askmi-dev/vericred.git
cd vericred
npm install
cp .env.example .env          # configure issuer keys, DB connection, base URL
npm run dev
```

Issues test credentials via OID4VCI; verify the flow against your wallet of choice (e.g. the [miTch wallet-pwa](https://github.com/Late-bloomer420/miTch) or any EUDI-compatible wallet).

## Security posture (summary)

- Route partitioning is applied **before** `express.static` (no path traversal into internals).
- Session-bound CSRF tokens, fail-closed 403 on mismatch.
- PII masking on by default (`PII_ADMIN_MODE` is an explicit, audited override).
- Zod schema validation on all external input.
- No hand-rolled cryptography: `jose` and `@noble/*` only.

See [SECURITY.md](SECURITY.md) for supported versions, key-handling rules and disclosure policy.

## Key management — read this before production

In the current version **issuer signing keys are held in local config files** (rotatable). This is acceptable for development and demos, but **not sufficient for high-assurance issuance**:

- For anything approaching regulated or LoA-High use, keys must live in an HSM or managed KMS (AWS KMS, PKCS#11, Azure Key Vault, …).
- A pluggable KMS/HSM adapter interface is on the roadmap so the audit story becomes "software keys for dev, hardware-backed for production".

## Non-goals

- Custody of end-user identity data beyond the issuance transaction (no profiling, no analytics on issued attributes).
- Wallet or verifier functionality.
- Any claim of regulatory approval.

## License

See [LICENSE](LICENSE) for terms. Maintained by [askmi-dev](https://github.com/askmi-dev) — contact: askmi.dev@icloud.com
