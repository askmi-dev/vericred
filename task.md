# Task Checklist: VeriCred (miTch Evidence-Bridge & Gateway)

- [x] **Sprint 0: Architecture Freeze & Defensive Startup (UI Routing Fix)**
  - [x] Wrap `store.initialize()` and `auditAndSyncLedgerUI()` in try/catch blocks on DOMContentLoaded to guarantee routing bindings execute
  - [x] Implement preservative ledger self-repair: isolate/quarantine a corrupt ledger while leaving worker and employer keys intact
  - [x] Set up persistent gateway secrets (`localGatewaySecret`) on first initialization

- [x] **Sprint 1: Proof Intake Contract (`MitchPresentationEnvelope`)**
  - [x] Define standard-aligned `MitchPresentationEnvelope` schema combining an issuer-signed base credential and holder key binding
  - [x] Implement RFC 7638 JWK public key thumbprint calculation (`calculateJWKThumbprint`) using alphabetical EC sorting and Base64URL encoding
  - [x] Add a visual "miTch Wallet Sync Area" to the Worker tab with mock eID and academic certificates
  - [x] Add challenge-terminal for real-time Gateway Nonce generation (short TTL, mapped in-memory)
  - [x] Implement client-side signed presentation generation using the worker's private key (Key Binding Proof-of-Possession)

- [x] **Sprint 2: Verification Policy (Fail-Closed Gates)**
  - [x] Implement `verifyMitchPresentationSequential()` executing the sequential validation: Parse -> Version -> Nonce/Aud/Expiry -> Issuer Trust -> Issuer Signature -> Holder Binding -> Revocation
  - [x] Implement atomic nonce consumption (pop and invalidate the nonce on first structurally valid verification attempt)
  - [x] Wire the gatekeeper verification into the Employer Panel, locking professional claim forms until a miTch presentation is verified successfully

- [x] **Sprint 3: VeriCred Credential Issuance (SD-JWT VC & Metadata Budget)**
  - [x] Implement the pairwise scoped DID generator using Web Crypto HMAC-SHA256: `did:vericred:pairwise:<hmacBase64url>`
  - [x] Refactor transaction schema in `blockchain.js` to store only: `holderPseudonym`, `mitchProofHash`, `credentialHash`, `claimCommitments` (salted hashes), `issuerId`, and `statusListIndex` (no plain text claims!)
  - [x] Implement exporting the complete, off-chain credential JSON to the worker (including raw claims and salts)
  - [x] Update `isChainValid()` to audit blocks for PII leaks (flagging block index if raw names, keys, or stable addresses are found)
  - [x] Rewrite standard ledger seed generation using the anonymized format referencing mock miTch proof hashes

- [x] **Sprint 4: Evidence UI & Universal Verifier Expansion**
  - [x] Redesign the Universal Verifier in `index.html` into a premium 5-stage horizontal visual checklist
  - [x] Implement live visual audit flows for:
    - Stage 1: miTch Wallet Presentation Verification (Issuer signature + Holder binding)
    - Stage 2: VeriCred Issuer Signature Audit
    - Stage 3: Ledger Anchor Validation
    - Stage 4: Revocation Status Audit
    - Stage 5: Metadata Budget Compliance Audit
  - [x] Wire up audit results displaying precise validation details, showing how off-chain claims match on-chain commitment hashes using salts

- [x] **Sprint 5: Attacks & Abuse Sandbox (Audit Cases)**
  - [x] Build a "Security Attack & Abuse Sandbox" UI panel with 5 interactive simulators:
    - Replay Attack (resubmitting an envelope with an old or invalid nonce)
    - Fake EUDI Trust Anchor (signing miTch envelopes with an rogue key not in EUDI list)
    - Credential Revocation (revoking base or extension credentials in the StatusList)
    - Metadata Budget Leak (writing plain-text names or raw worker keys on-chain)
    - Block Link Corruption (corrupting previous-hash block linkages in memory)
  - [x] Attach UI event handlers to trigger each attack, forcing the verifier to raise correct alert flags
  - [x] Verify all test cases and perform a complete walkthrough verification

- [x] **Sprint 6: Security Verification Harness & Browser QA**
  - [x] Add a 5th navigation tab (`nav-qa` / `#qa-harness`) inside `index.html` with a premium glassmorphic dashboard design
  - [x] Implement Visual Test Suite Panel with category tags (`Cryptographic`, `Protocol`, `Ledger Leak`, `Reseed`)
  - [x] Add a pulsing trigger button (`btn-run-qa-tests`) displaying test timings and pass/fail states
  - [x] Add live inspection nodes (collapsible accordion details) showing exact mathematical inputs, hashes, signatures, and error traces
  - [x] Add Operational Truth Pass Status diagnostic card reflecting live `localStorage` and challenge nonce cache states
  - [x] Implement 8 precise browser-executable cryptographic test assertions in `app.js` using real system functions:
    - [x] Test 1: RFC 7638 Thumbprint Determinism (asserts alphabetical sorting and stable Base64URL encoding)
    - [x] Test 2: HMAC Pairwise Pseudonym Stability & Scoping (asserts stable output, but secure divergence if any parameter varies)
    - [x] Test 3: Atomic Nonce Lifecycle (non-consumption on malformed structure, instant consumption on structural validity even with invalid signature)
    - [x] Test 4: Strict Replay Rejection (asserts same-envelope consecutive submissions fail)
    - [x] Test 5: Fake EUDI Trust Anchor Rejection (asserts signatures with rogue keys fail-closed)
    - [x] Test 6: Holder Key Mismatch Rejection (asserts transient key tampering fails-closed)
    - [x] Test 7: Zero-PII Ledger Compliance Audit (asserts block validation fails if plaintext metadata leaks)
    - [x] Test 8: Preservative Ledger Reseed & Quarantine (asserts database corruption isolates broken chains but preserves user identity keypairs)
  - [x] Embed visual Standards Gap Panel highlighting differences vs. production-grade deployments (compact SD-JWT-VC, distributed DIDs, signature EUTLs, verifiable registries)
  - [x] Embed high-contrast security warnings/disclaimers about educational prototype nature

- [x] **Sprint 7: Standards-Gap & Security Hardening (Pre-Production Transition)**
  - [x] Implement RFC 9901-compliant compact SD-JWT-VC serialization:
    - [x] Encode individual disclosures as standard `[salt, claim_name, claim_value]` JSON arrays
    - [x] Calculate the SHA-256 digest over the US-ASCII bytes of the Base64URL-encoded disclosure string, and Base64URL-encode the digest
    - [x] Structure Signed JWS payload with `_sd` array and `_sd_alg: "sha-256"`
    - [x] Export both decoded JSON and compact tilde (`~`)-separated SD-JWT-VC string in download bundles
  - [x] Implement compact SD-JWT-VC parsing and decoding in the Universal Verifier:
    - [x] Automatically detect compact tilde-separated inputs or JSON wrappers
    - [x] Split, parse, and decode Base64URL disclosures back into claims/salts
    - [x] Recompute and match Base64URL-encoded SHA-256 hashes against `_sd` array to verify disclosure integrity
    - [x] Perform standard JWS ECDSA signature verification
  - [x] Inject Pragmatic Compatibility CSP `<meta>` tag into `index.html` and document how to achieve strict CSP
  - [x] Build interactive visual **Threat Modeling & Safeguards Matrix** on the Security Harness tab:
    - [x] Design a gorgeous CSS-grid and glassmorphic threat cards layout
    - [x] Connect clicks to an inspector displaying precise code references
  - [x] Implement **Test 9: Compact SD-JWT-VC Serialization Integrity** inside the automated QA Harness

- [x] **Sprint 8: Production Readiness Boundary (Engineering Hardening & CSP Transition)**
  - [x] Harden CSP meta tag in `index.html`: set script-src strictly to `'self'` and worker-src to `'self' blob:`
  - [x] Implement robust schema validation for JSON Envelopes and compact SD-JWT-VC strings on file import/paste in `app.js`
  - [x] Update UI with polished, non-crashing alert states in Universal Verifier for malformed inputs
  - [x] Embed the interactive "Production vs. Simulation" Boundary Matrix grid in the Security Harness tab of `index.html`
  - [x] Implement **Test 10: Strict CSP & Robust Import Validation** in the automated QA Harness
  - [x] Run and verify that all 10 system assertions pass with a green state

- [x] **Sprint 9: Evidence Export & Interop Polish (Visual Conformance)**
  - [x] Implement explicit version tags (`"formatVersion": "1.1.0"`) and epoch timestamps (`"issuedAt"`) in dual-format wrappers, payloads, and parsed outputs
  - [x] Integrate `validateCredentialSchema(parsed)` in `app.js` performing strict structural checks prior to cryptographic validation
  - [x] Build `#verifier-examples` interactive row with 4 dynamic one-click example pills (Valid, Revoked, Tampered, Malformed) that compile session-valid signatures in real time
  - [x] Append beautiful, glassmorphic `#conformance-report-card` below the Universal Verifier outlining RFC 9901 compliant items, simulation layers, and production roadmap
  - [x] Implement **Test 11: Export Format Versioning & Strictest Schema Verification** in the automated QA Harness
  - [x] Run and verify that all 11 system assertions pass with a bright green state
