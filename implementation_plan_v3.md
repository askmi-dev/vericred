# Implementation Plan: Phase 5 — Dev-Front Workspace & Aesthetic Alignment

This plan outlines the architectural alignment of VeriCred's color design system to match its emerald/slate marketing identity, relocating development components, and establishing a robust, interactive developer environment (`devFront`) consisting of a **Credential Packstation** and a **Presentation Sandbox** ("Who Knows What").

---

## 1. Aesthetic Realignment: Brand Consistency

### Color Palette Refactoring
Currently, the prototype uses an aggressive cyber-neon palette (obsidian backgrounds, purple-blue neon weights) which is detached from the premium, professional, and friendly brand of our **emerald-green landing page** (`#10b981`).

#### [MODIFY] [index.css](file:///C:/Users/Admin/Documents/antigravity/kind-bose/index.css)
*   **Backgrounds:** Transition from deep obsidian `#050811` to the lighter, cleaner slate-base `#0f172a` or `#090d1a`, matching the marketing page's depth.
*   **Accents:** Remove neon-blue (`--accent-blue`) and purple weights, standardizing on **Emerald-Green** (`--accent-emerald: #10b981`) and soft slate-borders.
*   **Glows:** Restructure `--accent-teal-glow` to soft emerald transparency (`rgba(16, 185, 129, 0.15)`) to feel friendlier, cleaner, and less aggressive.

#### [MODIFY] [AdminLayout.astro](file:///C:/Users/Admin/Documents/antigravity/kind-bose/stitch-out/src/layouts/AdminLayout.astro)
*   Update active state highlight borders and nav buttons from purple highlights to clean, focused emerald-green outlines.
*   Increase background card contrasts to ensure full AAA accessibility and a modern, premium workspace feel.

---

## 2. Dev-Front Reorganization: Stitch Slides

The active Google Stitch slide overlays and presentation mocks currently reside inside the admin/issuer pages where they clutter the core administration flows.

#### [NEW] [previewFront.astro](file:///C:/Users/Admin/Documents/antigravity/kind-bose/stitch-out/src/pages/dev/previewFront.astro)
*   Relocate all educational slides, interactive presentation decks, and mockup canvases from the admin area to `/dev/previewFront`.
*   Maintain full capability to toggle slide states, demonstrating VeriCred's concepts inside a sandbox that does not interfere with the active admin instance.

---

## 3. Developer Front ("devFront") & "Packstation"

To enable developers to see exactly how secure, privacy-preserving systems operate, we will build a comprehensive playground at `/dev/navigator` and `/dev/packstation`.

```
                  ┌────────────────────────────────────────┐
                  │          Developer Workspace           │
                  └───────────────────┬────────────────────┘
                                      │
           ┌──────────────────────────┴──────────────────────────┐
           ▼                                                     ▼
┌────────────────────────────────────┐                ┌────────────────────────────────────┐
│      Packstation (Issuer Side)     │                │     Proof Presenter (Holder Side)  │
│                                    │                │                                    │
│  1. Input Raw JSON Claims          │                │  1. Load Issued SD-JWT-VC          │
│  2. Toggle SD Flag per Key         │  ────────────► │  2. Select Disclosed Keys          │
│  3. Select Holder Public Key       │                │  3. Attach Holder Possession Proof │
│  4. Real-time Hashing Flow         │                │  4. View Redacted Payload          │
└────────────────────────────────────┘                └────────────────────────────────────┘
```

### Component A: The Credential "Packstation" (Packaging workbench)
#### [NEW] [packstation.astro](file:///C:/Users/Admin/Documents/antigravity/kind-bose/stitch-out/src/pages/dev/packstation.astro)
This interactive workstation lets developers visually build an SD-JWT-VC from raw scratch:
1.  **JSON Input Workspace:** An editable editor panel pre-filled with standard identity schemas (e.g. name, date of birth, degree, nationality).
2.  **Selective Disclosure Matrix:** Beside each JSON key, render a toggle switch.
    *   *If Enabled (Hidden):* Show the live step-by-step cryptographic transformations in the right-hand panel:
        *   `Raw claim: { "nationality": "DE" }`
        *   `Salt generation: "Xy49Az92..."`
        *   `Disclosure string: ["Xy49Az92...", "nationality", "DE"]`
        *   `Base64URL representation: "WyJYeTQ5QXo5Mi4uLiIsICJuYXRpb25hbGl0eSIsICJERSJd"`
        *   `SHA-256 Digest: "a2d4b9... (stored in issuer base payload)"`
3.  **Holder Binding Config:** Generate or paste an EC JWK key pair. Automatically configure the `cnf.jwk` parameter inside the signed payload to mathematically bind this credential to the holder's key.
4.  **Live Signed Export:** Output the final compact JWS format with its corresponding disclosures:
    `eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ...~WyJYe...~WyJY...~`

### Component B: Presentation Sandbox ("Was kann ich mitbringen / beweisen / wer darf was wissen")
#### [NEW] [presentation.astro](file:///C:/Users/Admin/Documents/antigravity/kind-bose/stitch-out/src/pages/dev/presentation.astro)
This workbench teaches developers the "Fail-Closed" presentation lifecycle:
1.  **Ingestion:** The developer pastes any issued SD-JWT-VC.
2.  **Selective Disclosure Checklist ("Wer darf was wissen"):**
    *   The UI decodes and displays all salt-disclosed claims.
    *   The developer can check/uncheck keys they want to share with the verifier (e.g., sharing ONLY `degree` and `date_of_birth_over_18` while concealing their name and email).
3.  **Holder Proof of Possession ("Was muss ich beweisen"):**
    *   The sandbox displays a live challenge nonce from the Verifier.
    *   The developer clicks **"Generate Holder Binding Proof"**, which signs the challenge nonce + verifier aud/exp parameters using the holder's private key to build a standard KB-JWT.
4.  **Redacted Export Generation:** Assembles the standard presentation containing:
    *   The modified SD-JWT-VC.
    *   The exact subset of disclosures necessary to resolve the selected claims.
    *   The Holder's Key Binding JWT (KB-JWT).
5.  **Fail-Closed Verification Pipeline Trace:**
    *   Submit the presentation to a live, non-interactive audit loop.
    *   Show detailed logs of why the verifier rejects or accepts the submission (e.g. "Signature valid but Holder Binding Proof used expired nonce", or "Selective disclosure hashes are valid, but disclosure array signature is broken").

---

## 4. Verification Plan

### Automated Verification
*   Create `src/dev/__tests__/packstation.test.ts` to programmatically assert:
    *   Correct generation of salt strings per claim.
    *   Perfect correspondence between the disclosures appended to the token and the hashes embedded in the main payload.
    *   Holder binding validation via standard KB-JWT proofs.
*   Run the test suite using `vitest run` and confirm all assertions are green.

### Manual Verification
*   Compile the Astro pages via `npm run build` to verify standard syntax check.
*   Deploy the dev workspace and run tests directly in the browser across different disclosure combinations.

---

## 5. Complex Open Questions & Hard Edge Cases

These represent deep architectural questions we must address without assuming simple shortcuts:

1.  **Nested & Recursive Selective Disclosure:**
    *   *The Problem:* Real-world schemas often contain nested objects (e.g., `address: { street: "123 Main St", city: "Aachen", country: "DE" }`). If `address` is selectively disclosable, how do we support disclosure of individual child properties (e.g. disclosing ONLY `country`) without exposing the sibling fields?
    *   *The Solution:* We must implement a standard-compliant recursive hashing parser in our Packstation that supports both object-level hashing and child-level hash lists, demonstrating recursive tree disclosures.
2.  **Holder Binding vs. Private Key Isolation:**
    *   *The Problem:* The browser environment should never store the Holder's private key in a way that is accessible to untrusted page scripts. In our Packstation, how do we demonstrate a secure key-binding flow while maintaining appropriate architectural isolation?
    *   *The Solution:* We will use **Web Crypto API (CryptoKey)** with `extractable: false`. This ensures the private key is isolated inside the browser's cryptographic sandbox and cannot be leaked via XSS, demonstrating a robust "Secure-Enclave" equivalent design.
3.  **Blind Verifier Assertions (Zero-Knowledge Range Proofs):**
    *   *The Problem:* Under the "Fail closed, don't trust the verifier" principle, can we prove an attribute (e.g. `age > 18`) *without* revealing the actual birth date claim or its salt?
    *   *The Solution:* Standard SD-JWT-VC uses pre-computed boolean claims (e.g. `age_over_18: true`). We must demonstrate this exact pattern in our Packstation, highlighting why pre-computed verification flags represent the most portable and robust path for eIDAS 2.0 without requiring complex ZKP cryptographic runtimes.
