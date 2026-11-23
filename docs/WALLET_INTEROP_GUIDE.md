# Wallet Interoperability Guide

VeriCred is designed to be fully compliant with the **OpenID for Verifiable Credential Issuance (OID4VCI)** specification (draft-13+) and the **SD-JWT-VC** format (draft-ietf-oauth-sd-jwt-vc).

This guide helps you connect real-world mobile wallets to your VeriCred instance.

## 1. Supported Formats & Protocols

| Component | Standard | Note |
|-----------|----------|------|
| **Issuance Protocol** | OID4VCI (draft-13+ / 1.0 batch) | Supports Pre-Authorized Code Flow. |
| **Credential Format** | `dc+sd-jwt` | Modern SD-JWT-VC (Digital Credentials); JWT header `typ` matches. |
| **Batch Issuance** | OID4VCI 1.0 `proofs.jwt` | Up to `batch_credential_issuance.batch_size` copies, one per holder key, for unlinkable presentations. |
| **Revocation** | IETF Token Status List | `status.status_list` reference; list served as `application/statuslist+jwt`. |
| **Issuer Trust** | `did:web`, or X.509 `x5c` (HAIP 1.0) | `x5c` when `issuer.certificateChain` is set; see below. |
| **Key Binding** | JWK Thumbprint | Proof-of-possession via KB-JWT. |
| **Crypto** | ECDSA P-256 (ES256) | NIST P-256 curve support. |

## 2. Tested Wallets

| Wallet App | Platform | Compatibility | Note |
|------------|----------|---------------|------|
| **EUDI Wallet (Ref App)** | iOS / Android | ✅ Full | Best for testing EU-wide interoperability. |
| **Lissi Wallet** | iOS / Android | ✅ Full | Robust OID4VCI support. |
| **Sphereon Wallet** | iOS / Android | ✅ Full | Excellent debugging tools for OID4VCI. |
| **walt.id Wallet** | Web / Mobile | ⚠️ Partial | Ensure `dc+sd-jwt` is enabled in settings. |

## 3. How to Issue to a Real Wallet

1.  **Configure Issuer URL**: Ensure your `vericred.config.json` has a public-facing `issuer.url` (or use a tunnel like `ngrok`).
2.  **Open Admin Console**: Navigate to the **Issuance Monitor** (`/console/monitor`).
3.  **Generate Offer**:
    *   Select a **Holder** (Subject) from your database.
    *   Select a **Credential Profile** (e.g., `EmployeeCredential`).
    *   Click the **QR Code box**.
4.  **Scan with Wallet**: Open your mobile wallet app and scan the generated QR code.
5.  **Complete Flow**: The wallet will request the credential using the Pre-Authorized code. Since VeriCred currently defaults to `user_pin_required: false`, the issuance should happen instantly.

## 4. X.509 Certificate Chain (`x5c`)

EUDI wallets trust issuers through certificates from a registrar's CA, not through DIDs. HAIP 1.0 requires the chain in the `x5c` header of SD-JWT VCs and Status List Tokens.

1. Get a certificate for VeriCred's **current issuer public key**. Its subjectAltName must contain `URI:<issuer.url>` or `DNS:<host of issuer.url>`. If the registrar accepts a CSR, create one on the issuer machine:

    ```sh
    ISSUER_URL=https://issuer.yourcompany.com npm run csr -- --org "Your Company GmbH" --country DE
    ```

    It first checks that the deployment at `issuer.url` names itself as `credential_issuer` and publishes this key in its `did.json`, and refuses otherwise. A certificate binds the key to the URL, so it must be the same deployment. (`--skip-url-check` bypasses this, for example when deliberately offline.) It then writes `issuer.csr.pem` for the existing key (it never creates one) with both SANs set from `issuer.url`. It contains no secret. The private key never leaves the process. Use the same `DATA_DIR` as the server. After a production build, `node dist/cli/csr.js` does the same.
2. Save the chain as PEM: issuer certificate first, then intermediates. **Leave the root out**, because wallets already have it as a trust anchor.
3. Set `"issuer": { "certificateChain": "/path/to/chain.pem" }` in `vericred.config.json`.

With a chain configured, `iss` becomes `issuer.url` (it must match the certificate), and every credential and status list carries `x5c`. The private key stays with you. The certificate only vouches for it.

VeriCred checks the chain on every signature and **refuses to sign** if wallets would reject it. Issuance then returns `500 server_error` and `/status` returns `503`. Causes are a key mismatch (for example after key rotation, when you need a new certificate), expiry, wrong order, an included root, or a SAN that doesn't name `issuer.url`. The server log says which one.

## 5. Issuer URL Self-Check

Every URL a wallet uses (credential endpoint, status lists, the certificate SAN) comes from `issuer.url`. OID4VCI requires the metadata's `credential_issuer` to be **identical** to the URL the wallet fetched it from. A deployment with the wrong `ISSUER_URL` fails confusingly. A strict wallet rejects it, and a lenient one sends issuance to the other deployment.

VeriCred checks this and **warns** (it never blocks):
- **On every metadata request:** it compares the requested origin (`X-Forwarded-Host`/`Host`, `X-Forwarded-Proto`) with `issuer.url`. It logs a mismatch and reports it on `/health`:
  `"issuerUrl": { "status": "ok" | "unchecked" | "mismatch", "configured": ..., "observed": ... }`.
  `/health` stays HTTP 200 so platform healthchecks don't restart the service.
- **At startup on Railway:** it compares `RAILWAY_PUBLIC_DOMAIN` with `issuer.url`.

**Railway PR environments** inherit production's variables, including `ISSUER_URL`. Give them their own value and their own volume (own `DATA_DIR`, own issuer key):

```text
ISSUER_URL=https://${{RAILWAY_PUBLIC_DOMAIN}}
```

For registrar certificates, use a **persistent** sandbox hostname, not a temporary PR environment. The certificate is tied to both the key and the URL.

## 6. Common Interoperability Issues

### "Invalid Format" or "Unsupported Type"
Some older wallets expect `vc+sd-jwt` instead of the modern `dc+sd-jwt`.
*   **Fix**: Update `vericred.config.json` setting `"credential": { "format": "vc+sd-jwt" }` and restart the server.

### "Unable to resolve DID"
Real wallets need to resolve your `did:web` identifier to verify your signature.
*   **Fix**: Ensure your `/.well-known/did.json` is reachable from the public internet and served over HTTPS. If testing locally, use `ngrok` and update the `issuer.url` in config.

### "Proof Validation Failed"
The wallet sends a proof-of-possession JWT. If it fails:
*   Check the **Issuance Monitor** logs.
*   Ensure the wallet is using `ES256` for its proof.
*   Verify that the `nonce` in the wallet's proof matches the one issued in the offer.

## 7. Debugging Tools

*   **OID4VCI Trace**: Check the server console logs for `[proof]` and `[issuer]` messages.
*   **SD-JWT Tool**: Use [sd-jwt.js](https://sd-jwt.js.org/) to deconstruct and verify the tokens issued by VeriCred.
*   **JWT.io**: Use [jwt.io](https://jwt.io) to check the headers and payload of the issued SD-JWT (note: it won't handle the disclosures automatically).
