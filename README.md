# VeriCred

Lightweight OID4VCI issuer gateway — connect your data source, issue W3C Verifiable Credentials.

> **Status: Sprint 1–3 / Local Demo**  
> Not production-hardened. See [Security Notes](#security-notes) below.

## What it does

- Issues SD-JWT-VC credentials via OID4VCI pre-authorized code flow
- Generates `did:web` identity from a persistent P-256 keypair
- Supports JSON, Postgres, MySQL, REST, and CSV data sources
- StatusList2021 revocation built in
- Admin dashboard with holder management, credential status, and revocation

## Architecture position

```
VeriCred          miTch                    Mensch / Verifier
(Issuer Gateway)  (User Policy Boundary)   (Verifier Portal)
     │                   │                        │
     └── issues VCs ──▶  │── consent + proof ──▶  │── audit evidence
```

VeriCred is Issuer infrastructure. It is not the User-sovereignty core — that is miTch.

## Quick start

```bash
cp .env.example .env      # set DEMO_MODE=true for local testing
npm install
npm run dev               # runs on http://localhost:3100
```

On first start: admin API key is printed once to the terminal. Save it.

Admin UI: http://localhost:3100/admin

## Configuration

Edit `vericred.config.json` (auto-created in project root on first start):

```json
{
  "issuer": { "name": "My Issuer", "url": "http://localhost:3100" },
  "credential": { "type": "VerifiableCredential", "expiresInDays": 365 },
  "dataSource": { "type": "json", "path": "./data/holders.json" },
  "fieldMappings": { "given_name": "firstName", "family_name": "lastName" }
}
```

## Security Notes

This is a local demo / Sprint 1–3 prototype. Before any production use:

- [ ] Replace in-memory session store with persistent, signed sessions
- [ ] Add CSRF protection on admin POST endpoints
- [ ] Add login rate limiting
- [ ] Run behind HTTPS reverse proxy (nginx, Caddy) — never expose directly
- [ ] Set `DEMO_MODE=false` — synthetic holders must not appear in production
- [ ] Replace synthetic data connector with a real, audited data source
- [ ] Review SD-JWT VC claim structure for standard compliance
- [ ] Add audit logging for all credential issuance and revocation events

## Privacy design

- Demo holder secrets are derived (SHA-256 based) for local testing only. Production deployments must use Argon2id/bcrypt or an external IAM system
- Pairwise pseudonyms via HMAC — no global user ID reuse across verifiers
- Admin dashboard shows no credential content — only status and counts
- `data/` directory is gitignored — holder data never leaves the machine via git

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3100` | Server port |
| `DEMO_MODE` | unset | Set to `true` to generate synthetic holders on startup |
| `PII_ADMIN_MODE` | unset | Set to `true` to show full emails in admin UI (default: masked) |
| `NODE_ENV` | unset | Set to `production` to enforce Secure cookie flag |

## Repo structure

```
src/
  admin/        Admin dashboard and runtime stats
  config/       Config loader and secrets manager
  connectors/   Data source connectors (JSON, Postgres, MySQL, REST, CSV)
  did/          did:web publisher
  keys/         P-256 keypair manager
  middleware/   Auth middleware (session-based, not key-in-cookie)
  oid4vci/      OID4VCI issuer: metadata, token, credential, offer
  revocation/   StatusList2021 revocation router and state
```

## Relation to miTch

VeriCred issues miTch-compatible Verifiable Credentials. It is designed to be one input into the miTch ecosystem, not a replacement for user-side policy enforcement. See `docs/ARCHITECTURE.md` (coming soon).
