# Wallet Interoperability Guide

VeriCred is designed to be fully compliant with the **OpenID for Verifiable Credential Issuance (OID4VCI)** specification (draft-13+) and the **SD-JWT-VC** format (draft-ietf-oauth-sd-jwt-vc).

This guide helps you connect real-world mobile wallets to your VeriCred instance.

## 1. Supported Formats & Protocols

| Component | Standard | Note |
|-----------|----------|------|
| **Issuance Protocol** | OID4VCI (draft-13+) | Supports Pre-Authorized Code Flow. |
| **Credential Format** | `dc+sd-jwt` | Modern SD-JWT-VC (Digital Credentials). |
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

## 4. Common Interoperability Issues

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

## 5. Debugging Tools

*   **OID4VCI Trace**: Check the server console logs for `[proof]` and `[issuer]` messages.
*   **SD-JWT Tool**: Use [sd-jwt.js](https://sd-jwt.js.org/) to deconstruct and verify the tokens issued by VeriCred.
*   **JWT.io**: Use [jwt.io](https://jwt.io) to check the headers and payload of the issued SD-JWT (note: it won't handle the disclosures automatically).
