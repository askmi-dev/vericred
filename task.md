# Task Checklist: VeriCred Phase 1 (Astro + Express Gateway MVP)

- [x] **Task 1: Secure Route Partitioning & Guard Registration**
  - [x] Intercept all `/console/*` routes in Express before registering any static folders (`express.static`)
  - [x] Bind `requireAdmin` session-checking middleware to all intercepted `/console/*` endpoints
  - [x] Create route-specific handlers to serve protected static files directly via `res.sendFile()` from `stitch-out/dist/console/`
  - [x] Add robust automated tests attempting unauthorized fetches to `/console/dashboard`, `/console/schema`, and `/console/monitor` to verify they block and redirect cleanly
  - [x] Verify that accessing files under direct paths like `/console/dashboard/index.html` is strictly intercepted and blocked if unauthorized

- [x] **Task 2: Session-Bound CSRF Handshake Integration**
  - [x] Refactor the CSRF token store to bind active tokens strictly to the `admin_session` cookie (or Express session store) rather than global token mappings
  - [x] Create the authenticated, session-bound `GET /admin/api/csrf-handshake` endpoint protected by `requireAdmin`
  - [x] Configure `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` headers on the handshake endpoint
  - [x] Integrate subsequent state-changing APIs (e.g. revoke, save mapping) to fetch this token and submit it in the `x-csrf-token` header
  - [x] Add tests validating that mutating calls fail closed with `403 Forbidden` if the session-bound token is missing or mismatched

- [x] **Task 3: Default PII-Masking for Admin JSON APIs**
  - [x] Refactor `/admin/api/holders` endpoint to mask names and emails (e.g. `al***@gmail.com`) in default responses
  - [x] Refactor `/admin/api/credentials` endpoint to mask user names, emails, and credentials-associated claims by default
  - [x] Bind the unmasking behavior strictly to the environment override `PII_ADMIN_MODE === 'true'`
  - [x] Update relevant backend test assertions to ensure default output remains masked and safe from accidental leaks

- [x] **Task 4: Offer API Contract Expansion & Validation**
  - [x] Refactor the payload parser for `POST /offer` in the Express router
  - [x] Support both `{ "identifier": "..." }` and the expanded `{ "holderId": "...", "credentialType": "..." }` payload structure
  - [x] Implement strict validation on the backend to verify that the Holder exists, the Template exists, and the Template Mapping is valid (no DID-prefix requirement for internal UUIDs)
  - [x] Bind the selected `credentialType` and `holderId` to the generated offer/token state (either in-memory or in the database store) upon generating the offer
  - [x] Refactor the `/credentials` endpoint logic to retrieve the bound `credentialType` and `holderId` from the active token state during issuance, ensuring dynamic consistency even if the global configuration varies
  - [x] Write integration test cases verifying the correct creation of credential offers under the expanded contract and dynamic, consistent token-bound issuance

- [x] **Task 5: Dynamic Console Pages & Multi-Template UI**
  - [x] Integrate real-time stats fetching (`GET /admin/api/stats`) into `/console/dashboard` and bind metrics dynamically
  - [x] Connect `/console/schema` to fetch available templates from `GET /admin/templates` (AgeCredential, EmployeeCredential, MembershipCredential)
  - [x] Implement dynamic layout mapping of template schemas instead of static mock inputs
  - [x] Build the dynamic OID4VCI Offer Flow on `/console/monitor`: select a holder, select a template, trigger generation, and render live QR code with the standard offer URI
  - [x] Implement defensive Dry-Run and syntax checks on schema mapping configurations before executing atomic storage updates

- [x] **Task 6: Legacy Lab Relocation & Cleanup**
  - [x] Relocate the Web3 Proof-of-Work/mining simulation widget and related client assets to `/console/legacy/blockchain`
  - [x] Strip any blockchain or mining terminology from the main administration pages and dashboards to keep the focus strictly on modern REST APIs and OID4VCI standards

- [x] **Task 7: Regression Tests & Build Verification**
  - [x] Build the Astro frontend project via `npm run build` inside `stitch-out/` to verify compiler integrity
  - [x] Run the complete backend test suite (`npm run test`) to ensure all 81 cryptographic and routing unit tests remain 100% green
  - [x] Perform a manual auth-bypass and security audit in the browser to prove that the MVP is robustly secured

# Task Checklist: VeriCred Phase 2 (Sprint 2 & EUDI Interoperability)

- [x] **Task 8: DB Connector Layer Mock-Based Unit Tests**
  - [x] Write mock-based tests for `loadPostgresConnector` querying and row matching
  - [x] Write mock-based tests for `loadMySQLConnector` querying and row matching
  - [x] Write mock-based tests for `loadRestConnector` querying, URL replacement, and auth headers

- [x] **Task 9: CSV & Manual Entry Connectors**
  - [x] Create `src/connectors/csv.ts` implementing standard file-based lookups
  - [x] Create `src/connectors/manual.ts` implementing a structured in-memory lookup
  - [x] Update `src/connectors/index.ts` factory to support `csv` and `manual` types
  - [x] Write unit tests verifying CSV parsing and query lookups
  - [x] Write unit tests verifying Manual entry storage, search, and retrieval

- [x] **Task 10: EUDI-Wallet Interoperability Validation Test Suite**
  - [x] Create `src/oid4vci/__tests__/eudi-interop.test.ts`
  - [x] Retrieve issued SD-JWT-VC from VeriCred `/credentials` using pre-authorized code flow
  - [x] Verify Issuer's P-256 signature mathematically
  - [x] Validate selective disclosure arrays and SHA-256 disclosure hashes
  - [x] Simulate selective disclosure and sign a Holder Key Binding proof using holder's P-256 private key
  - [x] Validate presentation: verify JWS signature, decoded disclosures, hidden claims, and holder's proof-of-possession signature
  - [x] Confirm all tests compile and pass cleanly as part of the main `npm run test` suite

# Task Checklist: VeriCred Phase 3 (Sprint 3 — StatusList & Revocation)

- [x] **Task 11: StatusList2021 Cryptographic Implementation**
  - [x] Verify `src/revocation/statuslist.ts` implementation of bitstring generation
  - [x] Implement robust error handling for full lists (128k limit)
  - [x] Write unit tests for `buildBitstring` with sparse and dense revocation maps
  - [x] Write integration test verifying `/status/:listId` returns a valid, signed JWT VC

- [x] **Task 12: Revocation Workflow & Admin Integration**
  - [x] Verify `POST /admin/revoke` consumes the CSRF token and correctly updates the `statuslist.json` store
  - [x] Add audit logging for revocation events (who, when, why)
  - [x] Update Admin UI to show real-time "Revoked" status in the credentials list without page refresh (AJAX update)
  - [x] Write integration test simulating: Issue VC -> Verify Active -> Revoke -> Verify Revoked via StatusList fetch

- [x] **Task 13: SD-JWT-VC Status Embedding Validation**
  - [x] Ensure all issued credentials (Age, Employee, Membership) correctly embed the `credentialStatus` block
  - [x] Verify the fragment reference (`#index`) in the status ID matches the assigned bitstring position
  - [x] Add a regression test to `eudi-interop.test.ts` that specifically checks the `credentialStatus` field format

# Task Checklist: VeriCred Phase 4 (Sprint 4 — Admin UX & Production Hardening)

- [x] **Task 14: Dynamic Connector & Schema Introspection**
  - [x] Implement `getSchema()` for all connectors (JSON, SQL, REST, CSV, Manual) to return available columns/fields
  - [x] Add `GET /admin/api/source-schema` endpoint to expose active connector's fields
  - [x] Update `schema.astro` to fetch and render real source fields instead of mocks
  - [x] Update `dashboard.astro` to display the actual active connector and its health status

- [x] **Task 15: Setup Wizard & Guided Onboarding**
  - [x] Create `/console/setup` page in Astro for first-time configuration
  - [x] Implement backend check to redirect to setup if critical config (Issuer Name/URL) is default/missing
  - [x] Build wizard steps: Organization Identity -> Data Source Connection -> Field Mapping Preview
  - [x] Add atomic "Save & Go Live" action that updates `vericred.config.json` and restarts services if needed

- [x] **Task 16: Key Management & Rotation UI**
  - [x] Create `src/admin/__tests__/key-rotation.test.ts` verifying that rotating keys updates `did.json` correctly
  - [x] Add "Security" panel to Admin Console showing current P-256 public key thumbprint (RFC 7638)
  - [x] Implement "Rotate Keys" action with a confirmation modal and safety checks
  - [x] Ensure `did:web` document supports multiple keys if needed for transition periods

- [x] **Task 17: Production Hardening & Packaging**
  - [x] Refactor all file paths to be strictly relative to `DATA_DIR` for Docker/SaaS portability
  - [x] Implement robust error boundaries for the Admin API to prevent system crashes on invalid user input
  - [x] Final audit of all `express.static` guards to ensure zero-bypass for admin assets

# Task Checklist: VeriCred Phase 5 (Developer Playground & Aesthetic Realignment)

- [x] **Task 18: Warm-Light Aesthetic Realignment**
  - [x] Realign Admin Console (`AdminLayout.astro`) to a soft warm-light theme (light glassmorphism) with warm-ivory backgrounds, soft shadows, and translucent white overlays
  - [x] Refactor public landing page (`index.astro`) to remove dark styling, converting it to a stunning warm-light Claude/Apple glassmorphism experience
  - [x] Harmonize all highlights using organic green, slate, and amber tones instead of stark, cold dark modes
- [x] **Task 19: Developer Sandbox Environment (`devFront`)**
  - [x] Relocate Google Stitch slides to `/dev/previewFront` with a clean, light presentation style
  - [x] Implement **Credential Packstation** (`/dev/packstation`) for selective disclosure toggles, live salting & hashing, and compact token previews
  - [x] Implement **Presentation Sandbox** (`/dev/presentation`) demonstrating "Who Knows What" user-centric disclosures and P-256 validation pipelines
- [x] **Task 20: Astro Compiler Troubleshooting & Verification**
  - [x] Resolve unescaped curly brace syntax failures inside raw claims `<textarea>` of `packstation.astro`
  - [x] Resolve unescaped curly brace syntax failures inside mock JSON preview `<pre>` of `packstation.astro`
  - [x] Resolve unescaped curly brace syntax failures inside code sample `index.astro`
  - [x] Confirm that `npm run build` compiles 100% cleanly without errors



