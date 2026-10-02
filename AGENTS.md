# AGENTS.md — VeriCred Project Instructions

These instructions apply to every AI-assisted session in this repository. Read them fully before making changes.

## What VeriCred is

VeriCred is a **lightweight, open-source OID4VCI issuer gateway**. It lets any organization (university, employer, guild) connect their existing database and start issuing W3C Verifiable Credentials into EU wallets in under 30 minutes.

- **Credential format:** SD-JWT-VC (selective disclosure, miTch-compatible)
- **Issuance protocol:** OID4VCI (draft 13+)
- **Revocation:** W3C StatusList2021
- **DID method:** `did:web`
- **No blockchain.** Trust comes from the issuer signature, not a chain. Do not reintroduce blockchain components.

**What VeriCred is NOT:** a presentation layer. That is miTch's job. VeriCred only handles the issuer side. Do not add wallet/presentation/verification features here.

## Stack & structure

- **Runtime:** Node.js + TypeScript (ESM, `"type": "module"`)
- **Server:** Express (`src/server.ts`)
- **Crypto:** `jose`, `@noble/curves`, `@noble/hashes` — never hand-roll crypto
- **Validation:** `zod` for all input validation
- **Shared packages:** `@askmi/shared-crypto`, `@askmi/shared-types`, `@askmi/revocation-statuslist`
- **Frontend/Admin UI:** built in `stitch-out/` (console pages served from `stitch-out/dist/console/`)

Key source directories in `src/`:

```
admin/        admin API + console auth
config/       gateway configuration
connectors/   data-source connectors (JSON, Postgres/MySQL/REST planned)
credentials/  credential issuance logic
did/          did:web document generation & serving
keys/         issuer key management
middleware/   Express middleware (requireAdmin, etc.)
oid4vci/      OID4VCI endpoints (offer, token, credentials)
oid4vp/       verification-side helpers (minimal — miTch is the presenter)
revocation/   StatusList2021
sdjwt/        SD-JWT-VC issuance
types/        shared TypeScript types
```

Reference docs: `docs/` (Railway deploy, wallet interop, credential templates), `implementation_plan_v2.md` (architecture decisions), `task.md` (current phase checklist).

## Commands

```bash
npm run dev              # dev server (tsx watch src/server.ts)
npm run build            # frontend build + tsc backend build
npm start                # run built server (node dist/server.js)
npm test                 # vitest run
npm run test:watch       # vitest watch mode
```

## Non-negotiable security rules

These are implemented deliberately. Never weaken or remove them without an explicit user request:

1. **Route partitioning:** All `/console/*` routes are intercepted in Express *before* any `express.static` registration and protected by the `requireAdmin` session middleware. Direct file paths (e.g. `/console/dashboard/index.html`) must also stay blocked.
2. **Session-bound CSRF:** CSRF tokens are bound to the `admin_session` cookie via `GET /admin/api/csrf-handshake` (with `Cache-Control: no-store`). All state-changing admin APIs require the token in `x-csrf-token` and must fail closed with 403 on missing/mismatched tokens.
3. **Default PII masking:** `/admin/api/holders` and `/admin/api/credentials` mask names, emails, and claims by default. Unmasking is only allowed when `PII_ADMIN_MODE === 'true'`.
4. **Secrets:** Issuer keypairs persist in config files (rotatable), not env vars. Never commit keys or `.env`. Use `.env.example` as the template.

## Conventions

- TypeScript strict mode (`tsconfig.json`); no `any` unless unavoidable — prefer `zod`-inferred types.
- ESM imports only (no `require`).
- Every new endpoint or security-relevant change gets tests in `vitest`. Treat the task.md tests (unauthorized fetches, CSRF fail-closed, PII masking) as regression-critical.
- API payload changes must remain **backward compatible**: e.g. `POST /offer` accepts both `{ "identifier": "..." }` and `{ "holderId": "...", "credentialType": "..." }`; `credentialType`/`holderId` are bound to the offer/token state at creation time and used at issuance.
- Database-agnostic design: the connector layer (`src/connectors/`) abstracts the data source; don't hardcode a specific DB into core logic.
- Commit messages: short imperative summary in English.

## Deployment context

- Dockerized (`Dockerfile`), deployed on Railway (`railway.toml`, see `docs/RAILWAY_DEPLOY.md`).
- The gateway serves its own `did:web` document at `/.well-known/did.json` and OID4VCI metadata at `/.well-known/openid-credential-issuer`.

## Working style for agents

- Before implementing, check `task.md` and `implementation_plan_v2.md` for the current phase and architecture rationale.
- Don't refactor working Phase-1 security code for style; only change what the task requires.
- When ambiguity remains between this file and the docs, ask instead of guessing.
- After changes, run `npm test` before reporting done.
