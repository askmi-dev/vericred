# VeriCred

**Lightweight, template-driven OID4VCI issuer gateway with privacy-preserving defaults.**

VeriCred sits between a holder data source and a wallet. It issues SD-JWT-VC credentials without exposing raw PII from the source — each credential template defines exactly which claims are derived, which are omitted, and why.

```
Holder Data Source → VeriCred (Issuer) → Wallet
                         ↓
                     miTch (User Policy Boundary)
                         ↓
                     Verifier Portal
```

## Quick start

```bash
cp .env.example .env       # edit secrets
npm run dev
# open http://localhost:3100/admin
```

## Configuration

`vericred.config.json` (auto-created on first run):

```json
{
  "issuer": { "name": "VeriCred Issuer", "url": "http://localhost:3100", "did": "did:web:localhost%3A3100" },
  "credential": { "type": "AgeCredential", "expiresInDays": 30 },
  "templateOptions": { "ageThresholds": [18, 21], "jurisdiction": "EU" },
  "dataSource": { "type": "json", "path": "./data/holders.json" },
  "fieldMappings": { "dateOfBirth": "dateOfBirth" }
}
```

See [`docs/templates.md`](docs/templates.md) for per-template field reference.

## Credential Templates

| Template | Purpose | Never emits |
|---|---|---|
| `AgeCredential` | Age predicates (age_over_N) without revealing DOB | `dateOfBirth` |
| `EmployeeCredential` | Professional identity | `email`, `dateOfBirth`, `address` |
| `MembershipCredential` | Org membership, works with only a member ID | `email` |

The server **refuses to start** if the configured template type is unknown or `fieldMappings` are incomplete. `templateOptions` are also validated at startup for templates that declare `validateOptions()`.

---

## Capability Matrix

### Protocol

| Capability | Status | Notes |
|---|---|---|
| OID4VCI pre-authorized code flow | ✅ Implemented | Token endpoint, offer endpoint, credential endpoint |
| did:web issuer DID | ✅ Implemented | `/.well-known/did.json` |
| OID4VCI metadata | ✅ Implemented | `/.well-known/openid-credential-issuer` |
| SD-JWT-VC credential format | ✅ Implemented | vct, iss, iat, exp, sub, jti top-level; all claims in `_sd` hashes; Combined Format with `~disclosure~` appended |
| IETF SD-JWT disclosure serialization | ✅ Implemented | `src/sdjwt/disclosures.ts`; base64url(JSON[salt, name, value]); SHA-256 digests in `_sd`; Combined Format `<jwt>~<d1>~<d2>~` |
| Holder binding (cnf claim) | ❌ Not implemented | `proof_thumbprint` accepted but not verified; anonymous fallback in DEMO_MODE |
| OID4VP verifier endpoint | ❌ Not in scope | Planned for future sprint |
| mDoc / ISO 18013-5 | ❌ Not in scope | See miTch for reference implementation |

### Credential Templates

| Capability | Status | Notes |
|---|---|---|
| Template registry | ✅ Implemented | `registerTemplate()` / `getTemplate()` / `listTemplates()` |
| AgeCredential (predicates only) | ✅ Implemented | Exact UTC age; DOB never emitted |
| EmployeeCredential | ✅ Implemented | No email, DOB, or address |
| MembershipCredential | ✅ Implemented | Works without name or email |
| `validateMappings()` at startup | ✅ Implemented | `process.exit(1)` on missing required fields |
| `validateOptions()` at startup | ✅ Implemented | Template-defined, called at boot |
| Claim name consistency (snake_case) | ✅ Implemented | `age_over_N`, `member_id`, `valid_until`, etc. |

### Security

| Capability | Status | Notes |
|---|---|---|
| Session token auth (admin) | ✅ Implemented | 64-char hex token, 8h TTL, server-side store |
| CSRF protection | ✅ Implemented | Single-use 48-char tokens; all state-mutating admin routes protected |
| API key never stored in cookie | ✅ Implemented | Session token only |
| PII masking in admin UI | ✅ Implemented | `PII_ADMIN_MODE=true` to reveal |
| DEMO_MODE flag | ✅ Implemented | Synthetic holders only when explicitly set |
| Atomic file writes | ✅ Implemented | tmpdir + rename; prevents truncation on crash |
| HTTPS enforcement | ⚠️ Partial | "; Secure" cookie flag set in production; TLS termination external |
| Pairwise pseudonyms | ✅ Implemented | HMAC-SHA256(thumbprint\|issuer\|type) |
| Proof-of-possession verification | ❌ Not implemented | Holder binding not enforced |
| Rate limiting | ❌ Not implemented | Planned |
| Audit log | ❌ Not implemented | Planned |

### Revocation

| Capability | Status | Notes |
|---|---|---|
| StatusList2021 | ✅ Implemented | Status index assignment, revocation endpoint |
| Status list credential endpoint | ✅ Implemented | `GET /status/:listId` |
| Revocation via admin UI | ✅ Implemented | CSRF-protected |

### Privacy

| Capability | Status | Notes |
|---|---|---|
| Privacy-by-design credential templates | ✅ Implemented | Templates declare what is never emitted |
| Selective disclosure (holder-controlled) | ⚠️ Partial | Commitments generated; disclosure protocol not yet wallet-interoperable |
| Crypto-shredding | ❌ Not in scope | See miTch |
| GDPR Art. 25 (data minimisation) | ✅ By design | AgeCredential as archetype |

---

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (planned).

Related projects:
- **[miTch](https://github.com/Late-bloomer420/miTch)** — User policy boundary, ZK-style proof mediation, crypto-shredding
- **Mensch** — Verifier portal (private)

## Security checklist (pre-production)

- [ ] Enable TLS termination (nginx / Caddy in front)
- [ ] Replace `anonymous` thumbprint fallback with fail-closed or DEMO_MODE guard
- [ ] Implement holder binding (cnf claim verification)
- [ ] Add rate limiting on `/token` and `/credentials`
- [ ] Add audit log (immutable trail per credential issuance)
- [ ] Review SD-JWT disclosure serialization for wallet interop
- [ ] Rotate `PSEUDONYM_SECRET` with a documented key-rotation procedure
