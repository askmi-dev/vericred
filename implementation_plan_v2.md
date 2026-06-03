# VeriCred — Production Implementation Plan v2

## What we're building

VeriCred is a lightweight, open-source issuer gateway that lets any organization (university, employer, guild) connect their existing database and start issuing W3C Verifiable Credentials into EU wallets — in under 30 minutes. No blockchain. No crypto expertise required. Credentials are miTch-compatible out of the box.

**What VeriCred is NOT:** a presentation layer. That's miTch's job. VeriCred only handles the issuer side.

---

## Architecture decisions

| Decision | Choice | Reason |
|---|---|---|
| Blockchain | Dropped | Trust comes from issuer signature, not a chain. Adds complexity, no value for trusted issuers. |
| Issuance protocol | OID4VCI (draft 13+) | Native EU wallet standard. Works with EUDIW, any compliant wallet. |
| Credential format | SD-JWT-VC | Standard, selective disclosure, miTch-compatible. |
| Revocation | W3C StatusList2021 | Simple signed JSON, no special infrastructure needed. |
| DID method | `did:web` | Easy to deploy, no ledger dependency, orgs control their own DID. |
| Deployment | Open source + optional SaaS | Self-hostable by default. Hosted option for orgs that don't want to run infra. |
| Stack | Node.js (TypeScript) | Strong OID4VC ecosystem (walt.id libs, Spruce, MATTR). Easy to deploy. |

---

## System components

```
┌─────────────────────────────────────────────┐
│              VeriCred Gateway               │
│                                             │
│  ┌─────────────┐    ┌────────────────────┐  │
│  │  Admin UI   │    │   OID4VCI Server   │  │
│  │  (config,   │    │  /credential-offer │  │
│  │   mapping,  │    │  /token            │  │
│  │   revoke)   │    │  /credentials      │  │
│  └──────┬──────┘    └────────┬───────────┘  │
│         │                    │              │
│  ┌──────▼────────────────────▼───────────┐  │
│  │           Core Engine                 │  │
│  │  - Field mapper (DB → VC claims)      │  │
│  │  - SD-JWT-VC issuer                   │  │
│  │  - Key manager (issuer keypair)       │  │
│  │  - DID document publisher (did:web)   │  │
│  │  - StatusList manager                 │  │
│  └──────────────────┬────────────────────┘  │
│                     │                       │
│  ┌──────────────────▼────────────────────┐  │
│  │          DB Connector Layer           │  │
│  │  PostgreSQL / MySQL / REST API /      │  │
│  │  CSV / manual entry                   │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  EU Wallet (holder)         miTch (presenter)
  pulls credential via       accepts SD-JWT-VC,
  OID4VCI offer link         creates presentation
```

---

## Sprint plan

### Sprint 1 — Core issuer engine (the hard part)

Goal: a working OID4VCI endpoint that issues a real SD-JWT-VC a wallet can receive.

- [ ] Project scaffold: Node.js + TypeScript, Express, Jest
- [ ] Key management: generate P-256 issuer keypair, persist to config file (not env vars — orgs need to rotate)
- [ ] `did:web` document: auto-generate and serve `/.well-known/did.json` from issuer public key
- [ ] OID4VCI well-known: serve `/.well-known/openid-credential-issuer` metadata
- [ ] Authorization code flow: `/authorize`, `/token` endpoints (pre-auth flow first — simpler for orgs)
- [ ] Credential endpoint: `/credentials` — issues SD-JWT-VC with salted claim commitments + pairwise pseudonym (keeping the privacy layer from VeriCred prototype)
- [ ] Wallet integration test: verify credential lands in EUDIW reference wallet

**Done when:** a student can scan a QR code and receive a credential in their EU wallet.

---

### Sprint 2 — DB connector layer

Goal: org connects their data source, maps fields, credentials use real data.

- [ ] Config schema: define `vericred.config.json` — issuer name, DID, credential type, field mappings
- [ ] Connector interface: abstract base that any data source implements
- [ ] PostgreSQL connector: query by holder identifier (email, student ID), map rows to VC claims
- [ ] MySQL connector
- [ ] REST API connector: call an existing org endpoint to fetch holder data
- [ ] CSV connector: upload a CSV, issue credentials to the list (batch mode)
- [ ] Manual entry connector: UI form for small orgs with no database
- [ ] Field mapper: drag-and-drop or config-based mapping of source fields to SD-JWT-VC claim names

**Done when:** a university with a Postgres student DB can issue credentials from real records with a config file and no code.

---

### Sprint 3 — StatusList + revocation

Goal: credentials can be revoked and verifiers can check status.

- [ ] StatusList2021 implementation: generate and serve signed status list at `/status/{listId}`
- [ ] Assign status list index to each issued credential
- [ ] Revocation endpoint: mark a credential revoked by index or credential ID
- [ ] Embed `credentialStatus` in issued SD-JWT-VCs pointing to the status list URL
- [ ] Admin UI: revocation panel — search issued credentials, revoke with one click
- [ ] StatusList auto-refresh: re-sign and re-publish the list on any revocation

**Done when:** a revoked credential fails verification in any OID4VP-compliant verifier.

---

### Sprint 4 — Admin UI

Goal: any non-technical org admin can set up and manage VeriCred with a browser.

- [ ] Setup wizard: step-by-step onboarding (issuer name → DB connection → field mapping → go live)
- [ ] Dashboard: credentials issued, active, revoked; status list health
- [ ] Credential schema builder: define what claims a credential type contains, types, whether selectively disclosable
- [ ] Offer management: generate and share credential offer QR codes / deep links
- [ ] Key rotation UI: rotate issuer keys without breaking existing credentials
- [ ] Audit log: who issued what, when, with what data source

**Done when:** an org admin with no technical background can onboard and issue credentials without touching a config file.

---

### Sprint 5 — miTch handoff + interop

Goal: credentials issued by VeriCred flow cleanly into miTch presentations.

- [ ] Confirm SD-JWT-VC output format matches miTch's `MitchPresentationEnvelope` intake
- [ ] Pairwise pseudonym alignment: ensure VeriCred's HMAC-SHA256 pseudonym scheme is compatible with miTch's holder identity model
- [ ] OID4VP verifier endpoint: so VeriCred-issued credentials can be verified in the VeriCred UI too (useful for orgs demoing the full flow)
- [ ] Interop test suite: issue from VeriCred → present via miTch → verify at a third-party verifier
- [ ] Publish credential schema to a public schema registry (schema.org / EBSI schema registry)

**Done when:** a credential from VeriCred passes through miTch to an independent verifier without modification.

---

### Sprint 6 — Packaging + deployment

Goal: any developer can self-host VeriCred in under 10 minutes.

- [ ] Docker image: single-container deployment with sensible defaults
- [ ] Docker Compose: VeriCred + Postgres + Nginx in one file
- [ ] Environment config: document all env vars, secrets management
- [ ] `npx create-vericred` CLI: scaffold a new issuer instance with guided prompts
- [ ] Hosted SaaS deployment: one-click deploy to Vercel/Railway for orgs that don't want Docker
- [ ] Docs site: getting started, connector guides, credential schema reference, miTch integration guide

**Done when:** a new org can go from zero to issuing real credentials in 30 minutes following the docs.

---

## What carries over from the prototype

Keep these — they're good and non-trivial:
- Pairwise pseudonym scheme (HMAC-SHA256 scoped DIDs)
- Salted claim commitments
- SD-JWT-VC selective disclosure structure
- The walkthrough and demo for pitching to new orgs

Drop these:
- Proof-of-work blockchain and miner
- Local storage as the database
- Browser-only architecture

---

## Open questions to resolve before Sprint 1

1. **Pre-auth vs. auth code flow first?** Pre-auth (org generates offer, holder scans, gets credential) is simpler. Auth code flow (holder authenticates with org's IdP first) is more secure for sensitive credentials. Recommend starting with pre-auth, adding auth code in Sprint 2.

2. **Key storage for hosted SaaS?** Self-hosted = file. SaaS = HSM or KMS (AWS KMS / Azure Key Vault). Decision needed before Sprint 6.

3. **Which credential types first?** Define 2–3 pilot schemas (e.g. university degree, professional certification, employment record) to drive the field mapper design.

---

## Success metric for v1

A university can connect their student database, configure a credential schema, and have students receive verifiable credentials in their EU wallet — all without writing a single line of code.
