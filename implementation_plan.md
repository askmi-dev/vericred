# Implementation Plan - VeriCred: Astro + Express Gateway Migration

This plan transforms VeriCred into a production-ready, compliance-first, self-hosted/edge Issuer Gateway. It replaces the legacy client-side browser simulator with a clean Astro + Express dual-architecture, securely partitioning internal Work-In-Progress (WIP) assets, isolating legacy components, and integrating with the real TypeScript OID4VCI/SD-JWT-VC backend.

---

## [WARNING] Architectural Critique & Warnings

An analytical audit of the previous browser-simulator architecture and standard static builds revealed critical security vulnerabilities that are addressed in this plan:

### 1. Static File Authorization Bypass (Severe Risk)
* **The Vulnerability**: Serving the entire Astro static build output directly via Express `express.static('stitch-out/dist')` means the browser compiles `/dashboard/index.html`, `/schema/index.html`, and `/monitor/index.html` as public static assets. Any unauthenticated user could bypass the `requireAdmin` session checks entirely and load the administration layout, structures, and metadata.
* **The Solution**: We establish a strict partition. All `/console/*` routes must be explicitly intercepted by Express and served only after the `requireAdmin` session cookie check is validated. These guards must be registered before any `express.static` handling of those subdirectories/files (including direct paths like `/console/dashboard/index.html`) to prevent any static bypass.

### 2. Missing CSRF Token Bridge
* **The Vulnerability**: State-changing endpoints like `/admin/revoke` require a valid `x-csrf-token` header. Client-side fetches from static Astro routes would fail closed due to missing or mismatched tokens.
* **The Solution**: We introduce an authenticated, session-bound CSRF Handshake endpoint to bridge session CSRF tokens to Astro's client-side scripting.

### 3. Namespace Pollution by Stitch Imports
* **The Vulnerability**: Dropping raw Google Stitch files directly into Astro's `src/pages/` folder compiles them into public production routes (e.g. `/screen1`), exposing unfinished code, mock interfaces, and notes.
* **The Solution**: Stitch raw imports are strictly housed in `stitch-out/src/stitch-imports/` and served exclusively in development mode under a custom `/dev/navigator` flag.

### 4. Global Configurations & Multi-Tenancy Roadblocks
* **The Vulnerability**: Accessing global configuration files and singletons directly prevents future multi-tenant or SaaS adaptations.
* **The Solution**: All database connector structures and active templates are wrapped in a scoped context interface (`TenantContext`), isolating database queries and schema definitions per tenant.

---

## Target Architecture & Route Schema

```
                                  [ Client Request ]
                                          |
                  +-----------------------+-----------------------+
                  |                                               |
                  v                                               v
         [ Public Endpoint? ]                           [ Console / Admin? ]
                  |                                               |
      +-----------+-----------+                         [ Express Middleware ]
      v                       v                                   |
[ Static Files ]     [ OID4VCI & DIDs ]                           +--> requireAdmin (Cookie Validate)
 - / (Landing Page)  - /.well-known/did.json                      +--> requireCsrf (Verify Token)
 - _astro/           - /.well-known/openid-...                    v
 - favicon.ico       - /token                               [ Protected Console ]
                     - /credentials (SD-JWT-VC)             - /console/dashboard
                     - /console/schema
                     - /console/monitor
                     - /console/legacy/blockchain (Lab)
```

### 1. Core Routing Table

| Route | Access | Purpose | Express Router Strategy |
| :--- | :--- | :--- | :--- |
| `/` | Public | Product Landing Page (Claims, SD-JWT Codeblock, CTA) | Served statically from `stitch-out/dist` |
| `/health` | Public | Health Status (Returns issuer DID, no PII) | Dynamic JSON route, no credentials required |
| `/.well-known/*` | Public | OID4VCI Issuer Metadata & DID Documents | Handled by backend `metadata.ts` & `publisher.ts` |
| `/token` | Public | Token issuance endpoint (OAuth 2.0 / OID4VCI) | Handled by backend `token.ts` |
| `/credentials` | Public | ES256 SD-JWT-VC credential issuance | Handled by backend `issuer.ts` |
| `/status/*` | Public | W3C / StatusList2021 revocation lists | Handled by backend `statuslist.ts` |
| `/admin/login` | Public | Login portal with administrative auth challenge | Express direct HTML rendering / session establishment |
| `/console/dashboard`| Admin Only | Real-time gateway stats, active connections | Intercepted by `requireAdmin`, serves guarded index |
| `/console/schema` | Admin Only | Dynamic multi-template field mapping workspace | Intercepted by `requireAdmin`, serves guarded index |
| `/console/monitor`| Admin Only | Requests log, Revocation actions, OID4VCI Offer QR generator | Intercepted by `requireAdmin`, serves guarded index |
| `/console/legacy/blockchain` | Admin Only | Isolated PoW Mining Lab (Legacy Simulator) | Intercepted by `requireAdmin`, serves guarded index |
| `/dev/navigator` | Dev Only | Raw Stitch imports directory and benchmark navigator | Only compiled/routed when `process.env.NODE_ENV === 'development'` |

---

## Security & Privacy Integration Specifications

### 1. Secure Session-Bound CSRF Handshake Specification
To allow client-side scripts inside the guarded Astro console pages to make mutating API requests (e.g. revoking credentials, saving mappings), we implement a secure handshake.
The CSRF mechanism must be session-bound:
* **The Current Mechanism**: The existing `createCsrfToken()` implementation in the code is global token-based.
* **The Phase 1 Upgrade**: We must update the backend's CSRF implementation so that tokens are bound strictly to the active `admin_session` cookie (e.g. storing tokens mapped to the `sessionId` in-memory, or in Express session storage) and securely validated against it.
* **Route**: `GET /admin/api/csrf-handshake`
* **Access Control**: Strictly guarded by `requireAdmin`.
* **State & Scope**: Session-bound. Returns a fresh CSRF token.
* **Privacy**: Returns zero PII (Plaintext Identifiable Information) or system metrics.
* **HTTP Headers**: Must set `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` to prevent downstream browser or CDN caching.

```typescript
router.get('/admin/api/csrf-handshake', requireAdmin, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.json({ csrfToken: getSessionCsrfToken(req) }); // Session-bound lookup
});
```

### 2. Multi-Template Compliance & Offer API Contract Alignments
VeriCred supports multiple core W3C Credential Templates loaded dynamically from the backend rather than hardcoded in the frontend. This includes:
* **`AgeCredential`**: Over 18/21 proofing.
* **`EmployeeCredential`**: Corporate access and credentials.
* **`MembershipCredential`**: Association / organization registries.

The Astro UI will fetch available active templates from the existing endpoint `GET /admin/templates` and dynamically render appropriate schema fields and mapping layouts.

#### [IMPORTANT] Offer Contract Expansion & State Binding
* **The Current Code**: The existing backend endpoint `POST /offer` expects `{ "identifier": "..." }`.
* **The Phase 1 Design Decision**: We will explicitly expand the contract for `POST /offer` to support:
  ```json
  {
    "holderId": "urn:uuid:...",
    "credentialType": "AgeCredential"
  }
  ```
  * **Payload Validation**: The backend will validate that the Holder exists in `holders.json`, the Template exists, and the Template Mapping is fully valid. No raw DID-prefix validation is required for the internal UUID/URN `holderId`.
  * **Offer State Binding**: To ensure that the subsequent credential issuance at `/credentials` remains consistent, we must bind the generated Offer Code / Token state to the selected `credentialType` and `holderId` (either stored in-memory or in the database store). When the wallet requests the credential using the issued token, the `/credentials` endpoint will retrieve this bound state and serve the correct credential type, ensuring consistency.

### 3. PII & Audit Masking for Admin JSON APIs (Required for MVP)
To ensure compliance and privacy-first standards, all administrative JSON endpoints must mask personally identifiable information by default:
* **Target endpoints**: `/admin/api/holders` and `/admin/api/credentials`.
* **Default behavior**: User emails and names must be masked (e.g., `al***@gmail.com`, `Al*** Va***`) in the JSON payload returned to the browser.
* **PII Admin Mode**: Unmasked data is only returned when `PII_ADMIN_MODE === 'true'` is explicitly configured in the environment variables.

---

## API Integration Contracts

The console frontend integrates with the existing Express endpoints (defined in `src/admin/router.ts` and `src/oid4vci/`):

1. **Stats**: `GET /admin/api/stats` *(Requires session)*
   - Returns live issuer system statistics (Uptime, Restarts, Total Holders, Credentials status).
2. **Templates**: `GET /admin/templates` *(Requires session)*
   - Returns JSON schema representation of active and registered templates (AgeCredential, EmployeeCredential, MembershipCredential).
3. **Credentials**: `GET /admin/api/credentials` *(Requires session)*
   - Exposes list of issued credentials with masked emails/names by default.
4. **Holders**: `GET /admin/api/holders` *(Requires session)*
   - Returns registered holder records with masked emails by default to power the OID4VCI Offer Flow.
5. **Revocation**: `POST /admin/revoke` *(Requires session + CSRF token)*
   - Revokes an issued credential on the dynamic StatusList2021 registry.
6. **Offer Generation**: `POST /offer` *(Requires session + CSRF token)*
   - Payload: `{ "holderId": "urn:uuid:...", "credentialType": "AgeCredential" }`
   - Response: Generates a standard-compliant OID4VCI Credential Offer URI.

---

## OID4VCI Offer Flow (Production Grade)

The OID4VCI Offer Generator inside `/console/monitor` will operate with full holder context:

```
[ Console Monitor ] ---> Select Holder ---> Choose Template ---> [ Click Generate ]
                                                                        |
  [ Valid OID4VCI QR Code & Deep Link ] <--- Return Offer URI <---------+
```

1. **Holder Selection**: Admin selects an actual holder record (retrieved from `GET /admin/api/holders`).
2. **Template Selection**: Admin selects a registered credential template (AgeCredential, EmployeeCredential, MembershipCredential).
3. **Offer Request**: Triggering "Generate" posts the selection to `/offer`, returning a valid, standard-compliant `openid-credential-offer://` URI and optional short PIN.
4. **QR Generation**: The console renders an authentic QR code and deep-link of the offer URI.
5. **Interoperability**: The admin can scan the QR code using any compliant wallet (like `miTch`) to execute a full, authenticated, holder-bound ES256 SD-JWT-VC issuance workflow.

---

## WIP Stitch Pipeline & Legacy Lab Isolation

### 1. Stitch Import Sandbox (Development Only)
- **Directory**: `stitch-out/src/stitch-imports/`
- **Rule**: All raw HTML screens from Google Stitch projects are imported here to keep the active production source tree unpolluted.
- **Navigator Routing**: `/dev/navigator` indexes these imports solely when `process.env.NODE_ENV === 'development'`. The navigator and raw imports are entirely omitted from production builds.

### 2. Legacy Blockchain Lab Isolation
- **Directory**: `stitch-out/src/pages/console/legacy/blockchain.astro`
- **Rule**: All Web3/Blockchain/Proof-of-Work mining simulator widgets are isolated into this protected console sub-route. The core dashboards use modern, standard REST APIs and OAuth flow terminology.

---

## Roadmap & Prioritization

### Phase 1: MVP (Edge / Self-Hosted) - Primary Focus
- **Express Authentication Guards**: Protect all `/console/*` pages behind the `requireAdmin` session cookie validator middleware. Block direct static directory serving for admin HTML pages.
- **Console Dashboard Integration**: Connect dynamic stats fetching (`/admin/api/stats`) and credential lists into `/console/dashboard`.
- **Schema Mapping Integration**: Integrate dynamic schema loading with Multi-Template Support (`GET /admin/templates`) into `/console/schema`.
- **Pragmatic Persistence Guards**: Implement dry-run checks and syntax validations before overwriting configurations, ensuring malformed edits never render the system unbootable.
- **Secure Handshake Endpoint**: Set up `GET /admin/api/csrf-handshake` with required caching and access headers.
- **Holder-Contextual Offer Flow**: Integrate full OID4VCI Offer Flow on `/console/monitor` with a dropdown to select a genuine holder, post to `/offer`, and render live standard-conforming QR codes.
- **Legacy Lab Relocation**: Isolate the Proof-of-Work simulation under `/console/legacy/blockchain`.

### Phase 2: Stitch Pipeline (WIP Environments)
- Place raw mockup assets under `stitch-out/src/stitch-imports/` and restrict the `/dev/navigator` route to dev environments.

### Phase 3: SaaS Readiness
- Prepare for multi-tenant SaaS scaling by wrapping file storage operations, configurations, and database connector instances inside a scoped `TenantContext`.

---

## Verification & Testing Plan

### 1. Automated Integration Tests
- **Auth Bypass Prevention Test**:
  - Run automatic integration test attempting to fetch `/console/dashboard`, `/console/schema`, or `/console/monitor` without valid session cookies. Ensure the server redirects `302` to `/admin/login` or yields a `401 Unauthorized` instead of serving the static index file.
- **CSRF Token Guard Test**:
  - Attempt to POST to mutating endpoints like `/admin/revoke` or `/offer` without a valid `x-csrf-token` header. Verify that the request is strictly blocked with a `403 Forbidden` response.
- **Backend Cryptographic Regression Tests**:
  - Run the existing backend test suite (`npm run test`) to verify that all 81 unit tests (covering SD-JWT VC generation, signature verification, token routing) remain completely green.
- **Frontend Astro Compilation Test**:
  - Run `npm run build` inside the Astro workspace `stitch-out/` to ensure flawless generation of the public static and private assets.

### 2. Manual Conformance Audits
- Verify that a standard compliant wallet (such as `miTch`) successfully scans the generated OID4VCI Offer QR code, finishes the token exchange, and downloads a mathematically valid SD-JWT-VC.
- Verify that `/dev/navigator` returns a `404 Not Found` in production-compiled environments.
