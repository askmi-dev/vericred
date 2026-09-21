# Wallet key-attestation policy

Updated 2026-09-19. Implemented candidate for the pinned Android core0.30.2 / VCI0.13.1 contract.
Independent Android, iOS and miTch acceptance remains NOT RUN.

## Implemented path

EUDI mode requires a JWT proof with ES256, `typ=openid4vci-proof+jwt`, `kid="0"` and
`key_attestation`. It rejects embedded JWK proofs and conflicting key selectors. Custom mode retains
its separate embedded-JWK adapter; its successful tests do not establish EUDI compatibility.

The gateway authenticates the `key-attestation+jwt` against an explicitly configured provider leaf
certificate fingerprint before using `attested_keys[0]`. All supplied keys must be public P-256 keys.
The outer proof must verify with that key and the expected issuer audience, fresh timestamp and nonce.
An optional attestation nonce must agree with the outer nonce. Nonce/grant consumption remains one-use.

Provider assurance arrays and certification URI must match deployment policy. The attestation needs
valid `iat`/`exp` and a `key_storage_status` maintenance period covering the credential lifetime.
Credential expiry is capped at that maintenance end. Before issuing, the gateway fetches and validates
the signed key-storage status list; optional attestation-level status is checked too. Only status 0 is
accepted. Missing, stale, unavailable, suspended, revoked or invalid status fails closed.

Status requests occur only after the attestation and outer proof authenticate. URLs must match that
provider's configured HTTPS origin/path prefixes. Redirects, userinfo, query strings, fragments,
backslashes and percent-encoded paths are not accepted. TLS verification cannot be disabled.
Requests have a 10-second timeout and 128 KiB response limit; bitmap inflation is bounded to 1 MiB.
Token Status List widths 1, 2, 4 and 8 use LSB-first decoding. Signer pins are separate for attestation
and status roles. Policy changes, attestation expiry/max-age or any previously checked status becoming stale during
subsequent status retrieval reject the request. Status JWT expiry, TTL, configured max-age and signer
certificate expiry are all rechecked when the complete status check finishes.

No cross-request status cache or automatic trust discovery is used. No arbitrary incoming JWT key URLs
are followed. Network failures return generic errors without tokens, private paths or provider details.

## Provisioning

Set `EUDI_WALLET_ATTESTATION_POLICY_PATH` to a read-only JSON policy file. The prepared acceptance
Compose mounts it as `/run/eudi/wallet-attestation-policy.json`. Missing/invalid policy blocks EUDI
startup and readiness; it does not affect the custom local walkthrough.

This illustrative shape deliberately contains invalid placeholder fingerprints. It cannot be used
until the deployment operator supplies and independently verifies the actual material and agreements:

```json
{
  "version": 1,
  "maxAttestationAgeSeconds": 300,
  "maxStatusAgeSeconds": 120,
  "providers": [{
    "id": "agreed-test-wallet-provider",
    "signingCertificateSha256": ["REPLACE_WITH_VERIFIED_LEAF_DER_SHA256"],
    "statusSigningCertificateSha256": ["REPLACE_WITH_VERIFIED_STATUS_LEAF_DER_SHA256"],
    "statusListPrefixes": ["https://agreed-status-host.example/lists/"],
    "keyStorage": ["iso_18045_high"],
    "userAuthentication": ["iso_18045_high"],
    "certifications": ["https://agreed-provider.example/certification/profile"]
  }]
}
```

- Pins are SHA-256 of leaf certificate DER, 64 hexadecimal characters, without colons. Multiple pins
  support an explicitly reviewed signer rotation. Duplicate provider signing pins are rejected.
- `statusListPrefixes` must end in `/`. Use the narrowest agreed paths. The signed status JWT's subject
  must equal the requested URL. Its signature needs an approved status signer and valid x5c/time.
- `maxAttestationAgeSeconds`: 60..604800; `maxStatusAgeSeconds`: 1..86400. Status token expiry and its
  optional TTL additionally restrict acceptance. Agree actual provider token refresh behavior.
- Assurance values are `iso_18045_high`, `iso_18045_moderate`, `iso_18045_enhanced-basic`,
  `iso_18045_basic`. Every claimed value must be allowed for its provider. These are declarations by
  the authenticated provider, not a local hardware-certification assessment.
- Every advertised credential uses the policy's allowed assurance values and
  `preferred_key_storage_status_period` equal to its configured lifetime. The gateway requires that
  maintenance period; verify the wallet provider can meet it before the device run.
- `certifications` is an exact allowlist. URLs are compared, not fetched. No provider, status URL,
  certification or real signer has been approved or provisioned by this implementation.

## Trust boundary and remaining acceptance

This implementation uses **explicitly provisioned leaf pins**, not automatic ETSI Trusted List / LoTE
validation. It checks supplied chain signatures/validity but does not infer ecosystem authorization
from x5c. Obtain the leaf pins from independently authenticated operator material, verify role and
certificate profile against the agreed trust lists, and maintain rotation/removal operationally.
A matching pin is proof of configured local trust, not proof that the provider is listed or certified.

The pinned app config names `https://wallet-provider.eudiw.dev`; that hostname alone is not a signer
trust anchor. Its actual signer/status pins, assurance declarations, certification URI and status
paths still need agreement. Do not extract pins from an unauthenticated incoming proof and approve them.
miTch can use another explicitly agreed provider entry under the same constraints.

Registration ON remains a separate gate: issuer/verifier registration trust, identity binding,
custom VCT entitlement/scope and live registration status must pass on the actual wallet. WIA client
attestation, automatic trusted-list refresh, PID certification and ongoing wallet-revocation monitoring
are not implemented. VeriCred's custom EAA candidate must not be represented as a qualified/PID service.

Policy, signing/registration certificates and deployment secrets live outside DATA_DIR; recover and
verify them separately during a deployment restoration drill. Existing application-volume restoration
evidence does not recover or approve these materials.

## Primary sources and local evidence

- [Pinned proof signer](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt/blob/v0.13.1/src/main/kotlin/eu/europa/ec/eudi/openid4vci/internal/JwtProofSigners.kt)
  and [attestation model](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt/blob/v0.13.1/src/main/kotlin/eu/europa/ec/eudi/openid4vci/KeyAttestationJWT.kt).
- [Reference issuer verification at 13cffc06](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/blob/13cffc06c60235ab764c0cfab1f33a640098f8b6/src/main/kotlin/eu/europa/ec/eudi/pidissuer/adapter/out/proof/VerifyKeyAttestation.kt)
  and [index-zero JWT proof validation](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/blob/13cffc06c60235ab764c0cfab1f33a640098f8b6/src/main/kotlin/eu/europa/ec/eudi/pidissuer/adapter/out/proof/ValidateJwtProofWithKeyAttestation.kt).
- [OID4VCI 1.0 Appendix D](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D)
  and [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md).

`src/wallet/__tests__/attestation.test.ts` covers synthetic trusted/untrusted signers, assurance,
key binding, expiry, status, malformed data and network failures. `tests/wallet-contract.test.ts`
uses attested proofs through real encrypted local HTTP issuance and replay checks; its remote status
response is synthetic. `tests/attestation-https.test.ts` exercises actual loopback TLS retrieval and
rejects untrusted TLS. None of these installs or operates the reference wallet.
