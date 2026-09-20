# Wallet contract and acceptance

**Independent wallet execution is NOT RUN.** Synthetic route tests, even when using real signatures,
encryption and certificates, do not establish EUDI or miTch acceptance.

The current authoritative protocol table, exact Android pin, schema/trust decisions and operator steps are
in [EUDI_ACCEPTANCE_CONTRACT.md](EUDI_ACCEPTANCE_CONTRACT.md). Android comes first; iOS and miTch must each
complete independent acceptance.

## Runtime profiles

- `WALLET_PROFILE=eudi-android`: certificate-signed metadata and x509_hash presentation requests;
  encrypted final VCI requests/responses; encrypted direct_post.jwt; Token Status List.
  Startup needs matching issuer/verifier certificate material and HTTPS. The configured certificates
  still need wallet-ecosystem trust/entitlement acceptance.
- Default `custom`: existing JSON metadata, inline redirect_uri/direct_post and StatusList2021.
  This is a custom integration profile, not proof that a reference wallet supports it.
- `protocol: "legacy-draft"` is explicit and available only in custom mode. Final sessions do not accept
  a legacy typ/VCT. No wallet may bypass disclosure commitments, holder binding, audience/nonce, replay
  checks or revocation.

## Shared flow

1. Authenticated admin creates POST /offer with the connector's lookup identifier. A stale source/configuration
   change rejects the lookup. Deliver the bearer grant privately; QR generation stays local.
2. Wallet discovers metadata, redeems the code at POST /token and obtains POST /nonce.
3. Wallet signs an ES256 openid4vci-proof+jwt with public P-256 JWK, current iat, exact issuer audience and nonce.
4. Submit final credential_configuration_id plus proofs.jwt with one proof. In EUDI mode encrypt the entire
   request to an advertised encryption key and include the wallet response-encryption JWK/enc inside it.
   Decrypt the application/jwt response and read credentials[0].credential.
5. Initiate a presentation session. In EUDI mode fetch/verify the signed Request Object using request_uri.
   Verify x5c trust and x509_hash client identity; select disclosures matching DCQL.
6. Bind the SD-JWT using kb+jwt with the exact client_id audience, session nonce and sd_hash including the
   trailing tilde. Encrypt the DCQL response/state to the session key and POST it as form parameter response.
7. Result reads require the separate readToken capability. Successful presentation submissions are one-use.
   Check status according to the selected profile and reject retired/revoked/unknown credentials.

## Release evidence

Record pinned wallet build/digest, OS/device, trust/registration settings, custom VCT/profile, issuer origin,
image digest and redacted success/negative results. Never publish raw credentials, access tokens, grants
or private keys in acceptance logs. A missing/consumed nonce requires a new nonce; a consumed grant requires
a fresh offer.

Run [live connectors](connector-acceptance.md), [offline restoration](BACKUP_RESTORE.md) and the HTTPS
preflight before device release acceptance. Restoration deliberately invalidates all old credentials and
temporary authorization; holders need fresh issuance.

miTch uses the same public protocol and checks. Wallet UI/transport adapters stay outside claim mapping,
signing and validation. This work does not modify the miTch repository or claim cross-repository acceptance.
