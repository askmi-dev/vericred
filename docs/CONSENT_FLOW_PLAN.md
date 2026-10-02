# Implementation Plan — Human-Centered Consent Flow

## Status

Proposal. Not started. No code in this repo implements any part of this yet
(`grep -ri consent src/` returns zero matches as of this writing).

## Why this plan exists

`implementation_plan_v2.md` states VeriCred's scope plainly: an **issuer
gateway** that lets an organization connect a database and issue W3C
Verifiable Credentials, explicitly deferring the *presentation* side to
miTch. That scope is sound — but "issuer" still includes one decision that
current the code hands entirely to the organization: **whether and what to
issue about a specific holder.** The holder is not part of that decision
today.

## 1. Facts — what the code currently does

Traced through `src/oid4vci/offer.ts`, `token.ts`, `issuer.ts`, and the
mount order in `server.ts`:

1. `POST /offer` is admin-only (`app.use('/offer', requireAdmin)`,
   `server.ts:172`). An admin picks a `holderId` + `credentialType`; the
   server looks up the holder's DB row, maps fields, and mints a
   pre-authorized code — **no holder involved.**
2. The resulting `offer_uri` (QR code, per `task.md` Task 5) is handed to
   the holder out-of-band, by the org, however the org sees fit.
3. When the holder's wallet redeems it (`POST /token` → `POST
   /credentials`), the only check performed is a cryptographic
   proof-of-possession (`proof.ts`) — it proves the wallet controls a key,
   not that the holder reviewed or agreed to the claims about to be signed.
4. Once the pre-auth code is redeemed, the credential is issued
   immediately and irreversibly (revocation exists afterward via
   `admin/revoke`, but that is an *admin* action too — `task.md` Task 12).

Net effect: the holder's only moment of agency is deciding whether to tap
"accept" in their wallet's own UI — which is miTch's or another wallet's
surface, entirely outside VeriCred's control and not something this repo
can audit or guarantee.

One thing already done well and worth preserving, not replacing: **claim
minimization is already real**, not just a slogan. `AgeCredential`
(`src/credentials/templates/age.ts`) explicitly never emits `dateOfBirth`
— it emits `age_over_18`-style predicates only, with a comment enforcing
that rule. The consent flow below should sit on top of this, not
duplicate it: consent is about *whether an already-minimized set of claims
gets issued at all*, not about re-deciding minimization.

## 2. The gap

There is no point in the flow where the **holder** — the person the data
is about — sees the exact claims before they're cryptographically signed
into a credential, or can decline specific ones, or can revoke their own
consent later without going through the organization's admin.

This is a real gap relative to VeriCred's own "miTch-compatible" framing:
if the presentation side (miTch) is built around informed, user-controlled
disclosure, an issuer that issues without the holder's own confirmation is
a mismatch at the boundary between the two systems.

## 3. Design principles (values, not facts)

These follow directly from data-minimization / privacy-by-design /
user-control priorities, applied to this specific gap:

- **Informed**: the holder must see the literal claim set before a
  signature exists, not after.
- **Granular where the template allows it**: `optionalFields` already
  exists in `CredentialTemplate` (see `age.ts`: `optionalFields:
  ['jurisdiction']`) — the holder should be able to decline those
  specifically, not just accept-or-reject the whole credential.
  `requiredFields` are not negotiable at issuance time; if a required
  field is unacceptable to the holder, the answer is not issuing, not a
  partial credential.
- **No dark patterns**: consent is a distinct step with equally-weighted
  accept/decline actions — never a pre-ticked box inside a wallet-import
  screen the org controls.
- **Revocable by the holder, not only the org**: today only an admin can
  hit `/admin/revoke`. A holder should be able to trigger the same
  mechanism for their own credential.
- **Minimal new PII surface**: this plan must not become an excuse to add
  a new user database, login system, or email marketing list. Whatever
  identifies "this holder approved this offer" should be scoped as
  tightly as the pre-auth code already is (single-use, short TTL,
  no persistent account).

## 4. Proposed architecture

### 4.1 New flow shape

Current:

```
Admin -> POST /offer -> pre-auth code (immediately redeemable) -> QR -> Wallet
```

Proposed:

```
Admin -> POST /offer -> pending offer (NOT yet redeemable)
                          |
                          v
                 consent link (single-use, short TTL)
                          |
                          v
              Holder opens link, sees exact claims,
              approves (in full or minus optional fields) or declines
                          |
                          v
              only on approval: pre-auth code is activated -> QR -> Wallet
```

The pre-auth code itself doesn't need to change shape — it just shouldn't
be *usable* until a consent record exists for it.

### 4.2 New data: consent record

In-memory today is fine (mirrors `preAuthCodes`/`accessTokens` maps in
`token.ts`) — this does not need a database dependency to start:

```ts
interface ConsentRecord {
  consentId: string;          // random, single-use — this IS the link token
  offerCode: string;          // ties back to the pre-auth code
  credentialType: string;
  offeredClaims: string[];    // template field names, pre-computed, human-readable
  declinableClaims: string[]; // subset the holder may opt out of (== template.optionalFields)
  status: 'pending' | 'approved' | 'declined' | 'expired';
  declinedClaims: string[];   // populated on approval if partial
  createdAt: number;
  decidedAt?: number;
  expiresAt: number;          // short TTL, same order as existing pre-auth (10 min)
}
```

No holder name/email needs to live in this record beyond what's already in
`holderData` for claim-building — the consent record should reference the
existing holder lookup, not duplicate PII into a new store.

### 4.3 New endpoints

| Route | Access | Purpose |
| :--- | :--- | :--- |
| `POST /offer` | Admin (unchanged call site) | Now creates a **pending** offer + consent record; returns a `consent_url` instead of an immediately-usable `offer_uri` |
| `GET /consent/:consentId` | Public (token-gated by the id itself, single-use) | Renders the plain-language claim list for the holder to review |
| `POST /consent/:consentId/decide` | Public (same gate) | Body: `{ approved: boolean, declinedClaims?: string[] }`. On approval, activates the underlying pre-auth code and returns/redirects to the `openid-credential-offer://` URI. On decline, the offer is permanently dead — no re-approval. |
| `POST /consent/:consentId/revoke` *(post-issuance)* | Public (requires a durable-enough reference — see open question 4) | Calls the same mechanism as `admin/revoke`, scoped to holder-initiated |

### 4.4 Template changes

`resolveMappedData` and `buildClaims` (`issuer.ts`) don't need to change —
partial/declined optional fields are handled *before* that stage, by
filtering `holderData`/`fieldMappings` down to only the claims the holder
approved, before calling `resolveMappedData`. `CredentialTemplate` doesn't
need a new interface field: `optionalFields` already is the declinable
set.

### 4.5 UI

A new Astro page, styled consistently with the existing "warm-light
glassmorphism" direction from Task 18 (`AdminLayout.astro` /
`index.astro`), not a bare form: plain-language claim names (map
`age_over_18` → "That you are over 18", not the raw JSON key), an
Approve / Decline pair with equal visual weight, and — where
`declinableClaims` is non-empty — individual toggles for those specific
claims.

## 5. Open questions (decisions for you, not defaults I should assume)

1. **Link delivery.** How does the holder actually receive the consent
   link? Options: (a) the org still distributes it out-of-band exactly
   like today's QR, just pointing at `/consent/:id` instead of the wallet
   URI directly — zero new infrastructure; (b) VeriCred emails it directly
   — requires adding an SMTP/email dependency and a holder email field
   requirement, which is new scope and a new PII-handling surface. (a) is
   the smaller, more consistent-with-current-scope choice; (b) is more
   "complete" but is a bigger addition than this plan should assume you
   want.
2. **Partial disclosure granularity.** Is per-optional-field toggling
   (4.4) worth building for MVP, or is full accept/decline sufficient
   initially, with per-field toggles as a fast-follow? Templates today
   have very few optional fields (`AgeCredential` has exactly one:
   `jurisdiction`), so the payoff of granular toggles is currently small.
3. **Post-issuance holder-initiated revocation (4.3, last row).** This
   needs *some* way for the holder to prove "I am the one this credential
   was issued to" later, without VeriCred storing a persistent account.
   A time-unlimited capability link handed to the holder at issuance time
   (distinct from the short-lived consent link) is the minimal option, but
   it's a bearer secret with no expiry — worth deciding deliberately
   whether that tradeoff is acceptable versus requiring the org to relay
   revocation requests.
4. **Expiry of the pending offer.** Should an un-decided consent link
   expire at the same 10-minute TTL as the existing pre-auth code, or
   longer, given a human now has to read something and click, not a
   wallet processing programmatically? Recommend decoupling: give the
   consent decision itself a longer TTL (e.g. 24h), and only start the
   existing short pre-auth-code TTL once approval activates it.

## 6. Suggested phases

- [ ] **Phase 1 — Consent record + gate.** Add the in-memory consent store,
      change `POST /offer` to return a `consent_url` instead of an active
      `offer_uri`, add `GET/POST /consent/:consentId` to activate the
      underlying pre-auth code only on approval.
- [ ] **Phase 2 — Consent UI.** Astro page rendering claims in plain
      language, approve/decline actions, styled per Task 18's aesthetic.
- [ ] **Phase 3 — Partial disclosure.** Per-optional-field decline,
      filtering holder data before `resolveMappedData` accordingly
      (only if Open Question 2 resolves toward building this now).
- [ ] **Phase 4 — Holder-initiated revocation.** New endpoint reusing the
      existing StatusList revoke path, gated per Open Question 3's
      resolution.
- [ ] **Phase 5 — Audit trail.** Extend the existing revocation audit log
      (`task.md` Task 12) to also record consent grant/decline/withdraw
      events (who/what/when — no new PII beyond what's already logged).
- [ ] **Phase 6 — Tests.** Mirror the existing test style
      (`src/**/__tests__/*.test.ts`): unauthorized/expired/replayed
      consent-link attempts must fail closed, exactly like the existing
      CSRF and auth-bypass test suites do for the admin side.

## 7. Non-goals

- Not a presentation-layer feature — VeriCred still only issues; this
  plan doesn't touch how or where the *holder's wallet* later shows the
  credential to a verifier. That stays miTch's job, per
  `implementation_plan_v2.md`.
- Not an identity/account system for holders. The consent link is a
  single-use capability, not a login.
- Not a change to what claims templates compute — `age.ts`'s
  minimization logic (predicates instead of raw DOB) is out of scope and
  should not be touched by this work.
