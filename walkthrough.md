# Walkthrough Guide - VeriCred: miTch Evidence-Bridge & Credential Extension Gateway

Welcome to **VeriCred**, a decentralized, trustless, and privacy-preserving professional qualification gateway. VeriCred acts as a standard-conforming **miTch Evidence-Bridge**, validating secure, European Union Digital Identity (EUDI) compliant identity proofs and extending them with verifiable professional credentials.

By combining **RFC 7638 Key Thumbprints**, **HMAC-SHA256 Scoped Pairwise Pseudonyms**, and **Salted Claim Commitments**, VeriCred satisfies the strict metadata budget constraints of eIDAS 2.0. **No personal identifiable information (PII) ever touches the public blockchain ledger.**

---

## Technical Architecture Overview

VeriCred is built as a highly polished, single-page application with **zero backend dependencies**, leveraging native, asynchronous browser cryptography:

1. **Dual-Signature Presentation Intake (`crypto-service.js`)**:
   * Computes **RFC 7638-compliant public key thumbprints** by alphabetically sorting EC JWK keys (`crv`, `kty`, `x`, `y`) and hashing them to Base64URL.
   * Performs dual-signature validation on the imported `MitchPresentationEnvelope`:
     - **Issuer Verification (Part A)**: Mathematically validates that an authorized trust anchor (e.g., Google or Government eID) signed the base identity claims.
     - **Holder Proof-of-Possession Binding (Part B)**: Verifies that the presenter controls the private key corresponding to the public key thumbprint using a live, transient, single-use nonce.
     - **Sequential, Fail-Closed Design**: The pipeline halts execution immediately at the first failed check, preventing processing of invalid proofs.

2. **Off-Chain / On-Chain Split Ledger (`blockchain.js`)**:
   * Enforces a zero-PII policy: **Zero readable claims** (no plaintext `jobTitle`, `duration`, `skills`, stable addresses, or raw coordinate keys) exist on-chain.
   * On-chain records only store salted **Claim Commitments** (`SHA-256(Claim + Salt)`), a scoped DID pseudonym, and cryptographic hash anchors.
   * Complete, readable credentials (claims and salts) reside off-chain in the exported SD-JWT-VC-style JSON files.

3. **Background Block Mining (`miner.worker.js` & `app.js`)**:
   * Delegates resource-intensive Proof-of-Work hashing to a multi-threaded **Web Worker** to avoid blocking the main UI thread.
   * Integrates an asynchronous `requestAnimationFrame` mining fallback loop to ensure a fluid 60 FPS UI on browsers that restrict workers under local file-origin policies.

4. **Interactive Security Abuse Sandbox**:
   * Simulates 5 critical cryptographic attacks and verification failures to demonstrate VeriCred's fail-closed architecture in real time.

---

## Step-by-Step Verification Walkthrough

Run your local development server (`npm run dev`), navigate to `http://localhost:3100` (where the gateway is configured), and follow this validation script:

### Step 1: EUDI Wallet & Presentation Generation (Worker View)
1. Select the **Worker Portfolio** tab. In the top-right header widget, note your generated browser-native **Public Key Thumbprint** (calculated using RFC 7638).
2. Look at your preloaded seed academic credential issued by Google LLC. Click **View JSON** to see the off-chain credential containing claims, salts, and the EUDI trust anchor signature.
3. In the right-hand panel, paste the active Challenge Nonce from the Gatekeeper (e.g. `nonce_9fbc12...`) and click **"Generate miTch Presentation Proof"**.
4. A purple code container will slide open displaying a complete, dual-signed `MitchPresentationEnvelope`. Click **Copy Envelope** to copy this secure payload.

---

### Step 2: Gatekeeper Challenge & Verification (Employer View)
1. Go to the **Employer Panel** tab. The professional claims form is locked under an obsidian glass overlay.
2. Observe the current active Gateway Nonce displayed in the gatekeeper card.
3. Paste your copied `MitchPresentationEnvelope` into the paste container and click **"Verify Presentation & Unlock Gateway"**.
4. The sequential, fail-closed verification pipeline executes:
   * The nonce is **atomically popped and consumed** from the memory cache (replay prevention).
   * Issuer trust and holder possession are mathematically validated.
   * A **Scoped Pairwise Pseudonym** is calculated using HMAC-SHA256:
     `did:vericred:pairwise:HMAC(secret, thumbprint | issuer | type | mitchProofHash)`.
5. Upon successful validation, a green success banner appears, the pseudonym is populated into the form, and the Professional Claims Form is **unlocked**.

---

### Step 3: PII-Minimized Issuance & Block Mining
1. In the unlocked claims form, input your professional details:
   * **Job Title**: `Lead Solidity Developer`
   * **Duration**: `2024 - 2026`
   * **Skills**: `Solidity, Web3, Smart Contracts`
2. Click **Sign & Queue Certificate**.
3. Cryptographic salts are randomly generated, claim commitments are computed, the transaction is signed with the Acme Gateway key, and the transaction is queued in the Mempool.
4. Set the **Mining Difficulty** to `3` and click **Mine Block & Secure Chain**.
5. The futuristic, spinning mining terminal slides open. Watch the background worker compute nonces until the Proof-of-Work is solved and block linkage is secured.

---

### Step 4: Triple-Checked Cryptographic Verification (Verifier View)
1. Go to the **Universal Verifier** tab.
2. Select your newly generated off-chain credential JSON file (which was automatically downloaded or can be copied) and drag-and-drop it into the verifier dropzone.
3. Click **Verify Credential**.
4. Observe the premium, glowing **5-Stage Horizontal Audit Pipeline** progress sequentially:
   * **Stage 1: miTch Wallet Presentation Verification**: Audits EUDI trust and holder possession.
   * **Stage 2: VeriCred Issuer Signature Audit**: Verifies Acme Gateway's digital signature.
   * **Stage 3: Ledger Anchor Validation**: Audits the cryptographic hash linkages of the blockchain.
   * **Stage 4: Revocation Status Audit**: Confirms the credential index has not been flagged on the StatusList.
   * **Stage 5: Metadata Budget Compliance**: Audits the block to ensure zero plaintext names or addresses are leaked.
5. Expand each stage to inspect the technical details, demonstrating how the off-chain claims precisely match the on-chain commitments using salts.

---

### Step 5: Test the Interactive Security Attack & Abuse Sandbox
Navigate to the bottom of the page and trigger the active attack simulators to see VeriCred's defenses in action:

1. **Replay Attack**:
   * Click **Trigger Replay Attack** in the sandbox, then paste and verify the same miTch presentation.
   * **Result**: The verifier immediately fails-closed, reporting: *Replay Protection: Challenge Nonce has already been consumed or has expired.*

2. **Fake EUDI Trust Anchor**:
   * Click **Trigger Fake Trust Anchor** in the sandbox and generate a new presentation proof.
   * **Result**: The presentation is signed by an unauthorized/rogue issuer key. The Gatekeeper rejects the proof instantly, raising a trust anchor violation.

3. **Credential Revocation**:
   * Click **Trigger Credential Revocation**.
   * **Result**: The EUDI wallet marks Alice's credentials as revoked on the StatusList. Stage 4 of the audit pipeline turns a vivid crimson red, rejecting the credential.

4. **Metadata Budget Leak**:
   * Click **Trigger PII Leak Attack** and issue a credential.
   * **Result**: The gateway attempts to leak plaintext names or raw worker keys onto the ledger. The ledger audit engine (`isChainValid()`) catches this during mining or consensus and quarantines the block, triggering a red alert.

5. **Block Link Corruption**:
   * Click **Trigger Link Corruption** inside the sandbox or tamper with block fields in the Ledger Explorer.
   * **Result**: Links are broken. The blockchain visualizer lights up in a warning red, and Stage 3 (Ledger Anchor Validation) halts and fails-closed.
   * Click **Restore Chain** to discard the tampered state and restore full cryptographic integrity from secure local storage!

---

### Step 6: Security Verification & Automated QA Harness (System Tests)
1. Select the newly introduced **Security & QA Harness** tab from the main navigation header.
2. Observe the glassmorphic **Security Verification Suite** dashboard which provides real-time system metrics and automated assertion tests:
   * **Operational Truth Pass System Diagnostics**:
     - **Database Health**: Shows `LOADED` if localStorage is healthy.
     - **Active Nonces**: Tracks the number of generated and active gatekeeper nonces.
     - **Gateway Secret**: Indicates `SECURED` using 256-bit cryptographically random local entropy.
     - **Quarantine Records**: Number of isolated broken ledger states.
     - **EUDI Trust Anchors**: Count of active cryptographic keys allowed to sign base presentations.
3. Click the glowing, high-contrast **"🚀 Run Security Tests"** button.
4. Watch the automated, browser-executable testing engine run all **10 precise cryptographic assertions** in sequence:
   * **Test 1: RFC 7638 Thumbprint Determinism**: Validates alphabetical coordinate sorting (`crv`, `kty`, `x`, `y`) and stable, deterministic SHA-256 Base64URL hashing.
   * **Test 2: HMAC Pairwise Pseudonym Stability & Scoping**: Proves the gateway's HMAC-SHA256 pairwise pseudonym calculation is stable for the same input, but diverges completely to protect privacy if any scope parameter (identity, issuer, type, or proof hash) is altered.
   * **Test 3: Atomic Nonce Lifecycle**: Proves that bad JSON or schema version errors fail *before* consuming nonces (preventing unauthorized nonce burning), while structurally valid submissions invalidate nonces immediately.
   * **Test 4: Strict Replay Rejection**: Proves that submitting a structurally valid EUDI presentation twice fails the second time as the single-use nonce is deleted instantly.
   * **Test 5: Fake EUDI Trust Anchor Rejection**: Proves that rogue presentation keys not registered in the EUDI Trust list fail-closed instantly with trust violations.
   * **Test 6: Holder Key Mismatch Rejection**: Proves that swapping the transient public key inside the presentation so that it doesn't match the thumbprint in the base credential triggers immediate rejection.
   * **Test 7: Zero-PII Ledger Compliance Audit**: Asserts that the blockchain validation scripts fail-closed if plaintext fields (`workerName`, `jobTitle`, stable keys/addresses) are written to transaction payloads instead of hashed commitments.
   * **Test 8: Preservative Ledger Reseed & Quarantine**: Proves that when database JSON is corrupted, the system isolates the broken chain to a timestamped file and reseeds cleanly while preserving worker and employer keys untouched.
   * **Test 9: Compact SD-JWT-VC Serialization Integrity**: Validates standard `[salt, claim_name, claim_value]` disclosure structures, hashes them using SHA-256 over the US-ASCII bytes of base64url disclosure strings, verifies key bindings via standard `cnf.jwk` claims, and validates ES256 signatures over the payload.
    * **Test 10: Strict Content Security Policy (CSP) & Robust Universal Verifier Parsing**: Programmatically asserts that the DOM's active CSP meta header restricts script origins by completely blocking `unsafe-eval` and `unsafe-inline` under `script-src` (conforming to our strict production policy); additionally tests that dragging/pasting malformed or incomplete JSON credentials does not crash the console, but is trapped elegantly by displaying a non-crashing inline alert (`#verifier-alert`). This is statically plausible and browser-verified.
    * **Test 11: Export Format Versioning & Strictest Schema Verification**: Asserts that (a) newly generated credentials contain `formatVersion: "1.1.0"` and `issuedAt` metadata, (b) `validateCredentialSchema()` rejects missing versions, rogue DID structures, or invalid hashes, and (c) valid credentials pass perfectly.
5. All tests should light up in a glowing emerald **PASS** with precise microsecond durations.
6. Click any of the test rows to **expand the accordion detail** and inspect real mathematical CSP directives, parsed tilde strings, stable pseudonyms, and graceful error traces.
7. Read the **Interactive Production vs. Simulation Boundary Matrix** grid to understand the critical boundaries between our browser-only sandbox simulator and a production eIDAS 2.0 architecture (Key Storage Enclaves, XML EUTL Trust Registries, Distributed DID Resolution, CDNs, and Governance ledgers).
8. Read the **Standards Gap Review & Static Hardening Guide** to see the differences between our educational simulator and production deployments (JSON envelopes vs. compact tilde-separated JWS, local DID lists vs. decentralized registries, local trust list vs. signed national EUTL lists).

---

## Step 7: Evidence Export, Interop Polish & Conformance Report (Sprint 9)
1. Select the **Universal Verifier** tab.
2. Observe the newly integrated **Quick Load Example** flex pill bar below the paste area:
   * **🟢 Valid Acme SD-JWT-VC**: Click this pill to generate a session-valid professional credential dynamically with correct version numbers, signatures, and timestamps. It automatically runs the 5-Stage Verification Pipeline, displaying 100% green compliance.
   * **🚫 Revoked Credential**: Click this to load a validly structured credential but flag its index/signature as revoked in our local status registers. Watch Stage 4 of the audit turn red instantly.
   * **⚠️ Tampered Signature**: Click this to load Alice's seed credential with a single tampered character in the signature or payload claims. The parser detects the change and Stage 2 turns red immediately due to mathematical validation failure.
   * **⚙️ Malformed Schema**: Click this to load a corrupted schema (missing mandatory attributes or incorrect version identifiers). The strong schema validation engine catches the structural error *prior* to parsing or crypto checks, gracefully blocking execution and displaying a high-contrast crimson `#verifier-alert` explaining the mismatch details.
3. Observe the newly appended **Visual Conformance & Interoperability Report** below the audit receipt:
   * **Standard Conformance (RFC 9901 Compliant)**: Outlines our standard-aligned tilde-separated compact JWS structures, SHA-256 over US-ASCII disclosure bytes, `_sd`/`_sd_alg` array layouts, and `cnf.jwk` holder bindings.
   * **Simulator Specifications (Mock Layers)**: Documents our in-memory challenge nonces, static local DID maps, and local Web Worker blockchain proof-of-work loops.
   * **Production Roadmap (EUDI Interop Path)**: Explains the necessary roadmap to transition this study to an institutional eIDAS 2.0 deployment (Hardware HSMs, national root-signed CA rosters, distributed DNSSEC DIDs, and CDN-cached revocation states).
4. Run the automated QA Harness on the **Security & QA Harness** tab, and confirm that all **11 automated assertions** are fully passing. This proves our format versioning, schema enforcement, and interop boundary are browser-verified and fully solid!

---

## Step 8: Developer Playground & Soft Warm-Light Aesthetics (Phase 5)

We have transformed VeriCred's user interface to present a stunning, warm-light premium glassmorphic aesthetic inspired by Apple and Claude (Anthropic) designs. We have also introduced a powerful browser-native developer sandbox:

### 1. Light Glassmorphism Design Theme (Claude + Apple style)
* **Warm Ivory Backgrounds**: Replaced cold dark background colors with a very gentle, friendly cream/ivory background (`#faf9f6`) featuring subtle glowing gradients (emerald and warm amber).
* **Translucent Overlays**: Integrated elegant frosted glass layers (`rgba(255, 255, 255, 0.75)` with a high `backdrop-filter: blur(20px)`) and delicate border lines to achieve an executive 3D look.
* **Friendly Typographic Accents**: Realigned active states and alerts to use soft organic highlights (e.g. rich warm-ivory, emerald-green, and muted slate tones).

### 2. Credential Packstation (`/dev/packstation`)
* **Step-by-Step Packaging Workspace**: Enter raw JSON attributes and click **Load Claim Schema** to dynamically parse claims into individual toggles.
* **Selective Disclosure Switches**: Individually toggle which claims should be protected behind SHA-256 selective disclosure arrays or displayed in plaintext.
* **Holder Key-Pair Binding**: Simulate generating an ECDSA P-256 key pair directly in-browser using Web Crypto API. The public key is bound securely into the credential's `cnf.jwk` claim.
* **Live Signed Payload & Compact SD-JWT-VC**: Watch the base payload dynamically rebuild and see the finished, standard-compliant compact tilde (`~`) separated token compiled for instant copying.

### 3. Interactive Presentation Sandbox (`/dev/presentation`)
* **"Who Knows What" Verifier**: Test standard compact tokens by pasting them directly. It parses all appended base64url disclosure statements.
* **Checklist Selectors**: Select exactly which claims you want to reveal to the verifier, demonstrating user-centric data minimization.
* **Challenge Proof Generation**: Generates a standard KB-JWT (Key-Binding JWT) signing proof dynamically with Web Crypto to demonstrate holder proof-of-possession.
* **5-Stage Verification Log**: Trace signature validation, expiration checking, KB-JWT proof audits, disclosure array mapping, and strict validation reporting.

---

## Step 9: Admin Operations & Gateway Management (Phase 6)

While the Developer Playground simulates the holder and verifier experience, the **Admin Console** (accessible at `/console`) provides the operational control plane for the VeriCred Gateway.

### 1. Zero-Config Onboarding (Setup Wizard)
*   **Automatic Detection**: If the gateway is started with a default configuration (e.g., "VeriCred Issuer"), it automatically redirects administrators to the **Setup Wizard** (`/console/setup`).
*   **Identity Provisioning**: Configure your organization's legal name and base URL. This dynamically updates your `did:web` identifier across all issued credentials.
*   **Connector Selection**: Choose your source of truth. VeriCred supports Local JSON, CSV, PostgreSQL, MySQL, and REST Intake APIs.

### 2. Dynamic Schema Introspection
*   **Live Database Mapping**: In the **Schema Mapping** tab (`/console/schema`), VeriCred now introspects your active data source in real-time.
*   **Field Discovery**: See actual columns from your database (e.g., `student_id`, `graduation_date`) and drag-and-drop them to map to standard SD-JWT-VC claim names.
*   **Validation**: Every mapping is validated against the selected Credential Template (Age, Employee, or Membership) to ensure required claims are never missing.

### 3. Enterprise Key Management & Rotation
*   **Security Control Plane**: The **Security & Keys** tab (`/console/security`) manages your cryptographic root of trust.
*   **Atomic Rotation**: Rotate your P-256 issuer keys with one click. VeriCred archives the old key to `key-history.json` and immediately generates a fresh pair.
*   **Backward Compatibility**: The gateway continues to serve historical public keys in its `did.json` document, ensuring that credentials issued *before* the rotation remain valid and verifiable by third parties.
*   **RFC 7638 Compliance**: View active key thumbprints to verify consistency with external trust registries.

---

## 🎨 Premium Navigation & Megamenus (User Experience)
To elevate the first impression of the public page (`index.astro`), we transformed the static header navigation into a highly interactive, responsive experience modeled on modern SaaS best practices:

1. **Stitch Screens -> Library Transition**:
   - Replaced all raw "Stitch Screens" terminology with "Library" to provide a more intuitive and professional developer-first library landing experience.
   - The link directs users straight to `/dev/navigator`, which serves as our central workspace hub.

2. **Solutions Mega-Dropdown**:
   - Built an interactive, zero-JS CSS-based hover dropdown that triggers an elegant **3-column menu panel** ($840\text{px}$ width).
   - Columns are logically mapped to VeriCred's identity domain:
     - **By Org Size**: Tailored routes for Startups & Devs, Medium Enterprises, Trust Anchors, and Enterprises.
     - **By Use Case**: Interactive links to Academic Degrees (`/dev/packstation`), Employment Proofs (`/dev/presentation`), Identity Verification, and Status Revocation.
     - **By Role**: Links tailored for Credential Issuers, Service Verifiers, and Developers.

3. **Resources Mega-Dropdown**:
   - Implements a secondary **3-column megamenu** following the same responsive, glassmorphic design system:
     - **Column 1**: Features a beautifully highlighted, emerald-tinted quick access container for the **Library** (`/dev/navigator`), followed by Case Studies and Community links.
     - **Column 2**: Links to **Templates / Slides** (`/dev/previewFront`), State of Identity reports, and the Help Center.
     - **Column 3**: Houses our Blog, Newsletter, and Publications sections.

4. **Warm-Light Claude/Apple Glassmorphism**:
   - The dropdowns utilize an ultra-premium aesthetic with high transparency (`bg-white/95`), heavy backdrop-blur (`backdrop-blur-xl`), razor-thin borders (`border-slate-200/50`), and soft deep-shadows (`shadow-2xl`).
   - Interactive elements include rotating chevrons (`group-hover:rotate-180`) and responsive state highlight gradients to optimize the UX.

---

## ⚡ Zukunfts-Roadmap & Identifizierte Gaps (The Path to Production)

Obwohl VeriCred als Demonstrator technisch hochgradig präzise arbeitet, existieren für den produktiven Einsatz im eIDAS 2.0 Rahmen folgende Gaps und Entwicklungsfelder:

### 1. Post-Quantum-Kryptografie (PQK) & Krypto-Agilität
*   **Aktueller Stand**: Wir nutzen primär **ECDSA P-256 (ES256)**. Dieses Verfahren ist zwar Industriestandard, aber nicht quantenresistent.
*   **Der Gap**: Quantencomputer könnten P-256 Signaturen in Zukunft brechen. eIDAS 2.0 fordert langfristig Krypto-Agilität.
*   **Roadmap**: Integration von Post-Quantum-Algorithmen wie **ML-DSA (Dilithium)** oder **SLH-DSA (SPHINCS+)**. Da PQ-Signaturen deutlich größer sind (Kilobytes statt Bytes), muss das Gateway auf "Large Payload Handling" vorbereitet werden.

### 2. Hardware-Level Assurance (LoA High)
*   **Aktueller Stand**: Schlüssel werden im Browser (Web Crypto) oder als JSON auf Disk (Issuer) gespeichert.
*   **Der Gap**: Für das Vertrauensniveau "Hoch" (LoA High) schreibt die EU die Nutzung von **Hardware Secure Enclaves** (Smartphone) und **Qualified Signature Creation Devices (QSCD/HSM)** auf Issuer-Seite vor.
*   **Roadmap**: Anbindung von Cloud-HSMs (AWS CloudHSM, Azure Dedicated HSM) für die Signaturerzeugung und Nutzung von Android Keystore / iOS CryptoKit für die Holder-Bindung.

### 3. Skalierbarkeit der Widerrufslogik (Revocation)
*   **Aktueller Stand**: Wir nutzen eine einzelne **StatusList2021** Bitstring-Datei (16KB für ~131k Slots).
*   **Der Gap**: Bei Millionen von ausgestellten Credentials wird ein einzelner Bitstring zu groß für den Download durch Wallets.
*   **Roadmap**: Implementierung von **StatusList-Sharding** (Aufteilung in hunderte kleinere Listen) und Nutzung von **Bloom-Filtern** für hocheffiziente Revocation-Checks.

### 4. Dynamisches Trust-Management (EUTL)
*   **Aktueller Stand**: Die Liste der vertrauenswürdigen Aussteller (DIDs) ist lokal hinterlegt.
*   **Der Gap**: In der Realität muss das Gateway die **European Union Trusted Lists (EUTL)** dynamisch parsen (XML/XAdES) und Signaturen gegen nationale Root-CAs prüfen.
*   **Roadmap**: Implementierung eines EUTL-Service-Connectors, der täglich die offiziellen Vertrauenslisten der EU-Mitgliedstaaten synchronisiert.

---

## 🚀 Fazit des Walkthroughs

Das System ist von Schritt 1 (Presentation Generation) bis Schritt 9 (Admin Operations) logisch, lückenlos und mathematisch rigoros dokumentiert. Die 11 automatisierten QA-Assertion-Tests im Harness garantieren, dass die kryptografische Kette im Browser stabil bleibt und Fehlerzustände deterministisch abgefangen werden.

VeriCred ist damit der ideale Ausgangspunkt für eine Migration von zentralisierten Identitätssystemen hin zu einem dezentralen, eIDAS-konformen Ökosystem.




