# Wallet Interoperability Log - Troubleshooting

This log is captured dynamically by the VeriCred Gateway. Below are common categories of interoperability alerts and how to resolve them.

## Category: `proof` (Holder Proof of Possession)

These errors occur when the wallet's proof-of-possession JWT (sent to the `/credentials` endpoint) fails validation.

| Message | Potential Cause | Fix |
|---------|-----------------|-----|
| `Proof JWT typ must be "openid4vci-proof+jwt", got "..."` | Wallet is using an older or incorrect `typ` header value. | Ensure the wallet is OID4VCI draft-13 compliant. |
| `Proof JWT verification failed: ...` | Cryptographic signature validation failed. | Check if the wallet used a different key than the one in the `jwk` header. |
| `Proof JWT nonce does not match c_nonce` | Replay protection triggered or wallet used an expired nonce. | The wallet must use the `c_nonce` received from the `/token` response. |

## Category: `token` (Access Token Request)

These alerts occur at the `/token` endpoint.

| Message | Potential Cause | Fix |
|---------|-----------------|-----|
| `Unsupported grant type` | Wallet tried to use Authorization Code or another grant type. | VeriCred currently defaults to `urn:ietf:params:oauth:grant-type:pre-authorized_code`. |
| `Invalid or expired pre-authorized code` | The QR code was scanned twice or the code timed out (10 min). | Generate a fresh Credential Offer in the Issuance Monitor. |

## Category: `issuance` (Mapping & Building)

These alerts occur after proof validation, during the assembly of the SD-JWT-VC.

| Message | Potential Cause | Fix |
|---------|-----------------|-----|
| `Field mapping failed` | The data source is missing a required field (e.g., `dateOfBirth`). | Check the **Schema Mapping** tab and ensure all required fields are mapped to existing database columns. |
| `Issued ...` | **Success!** | No action needed. |

---

*Note: For real-time debugging, use the **Issuance Monitor** in the Admin Console.*
