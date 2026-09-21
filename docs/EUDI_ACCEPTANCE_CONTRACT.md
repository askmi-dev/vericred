# EUDI and miTch acceptance contract

Status: implemented candidate, not independent wallet acceptance. Updated 2026-09-18.

**Attested-key proof support is implemented in the candidate**, with explicit provider/status signer
pins and assurance/status policy. Real provider provisioning and independent wallet acceptance remain
open. See [wallet attestation](WALLET_ATTESTATION.md) and [registration](EUDI_REGISTRATION.md).

## First target and shared contract

Start with Android reference wallet **2026.08.41-Demo / build 41**, app commit
`50828c2ca1e273cb552ce8f66b556b4a6d7b2b2f`, wallet core **v0.30.2**.
Record the installed APK digest, Android version/device, registration switch, trust-list versions and
certificate fingerprints in the acceptance log. iOS is the second target: pin its exact release and
configuration before claiming parity. miTch must consume the same messages and satisfy the same validation;
it does not get a relaxed trust, status, encryption or replay bypass.

Official pinned sources:
- [Android Demo configuration](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/50828c2ca1e273cb552ce8f66b556b4a6d7b2b2f/core-logic/src/demo/java/eu/europa/ec/corelogic/config/WalletCoreConfigImpl.kt)
- [Wallet core v0.30.2](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/tree/v0.30.2)
- [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Token Status List draft 16](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html)

| Item | Implemented candidate contract |
| --- | --- |
| Runtime selection | `WALLET_PROFILE=eudi-android`; unset remains `custom` for existing installations. Unknown values fail closed. |
| Credential | ES256, `dc+sd-jwt`, HTTPS issuer, P-256 holder JWK binding, SHA-256 disclosure commitments. |
| Custom VCT | `urn:vericred:credential:AgeCredential:1`, `urn:vericred:credential:EmployeeCredential:1`, `urn:vericred:credential:MembershipCredential:1`. These are custom EAA candidates, not PID or qualified attestations. |
| Issuance | Pre-authorized code; public one-use nonce; one attested-key JWT proof per EUDI request (kid=0); final `credential_configuration_id` / `proofs.jwt` / `credentials` shapes. |
| Metadata | JSON or signed JWT selected through Accept; `openidvci-issuer-metadata+jwt`, x5c, sub=HTTPS issuer, iat/exp. |
| VCI encryption | Both request and response required; ECDH-ES/P-256; A128GCM or A256GCM; no compression. Separate persistent request-encryption key. |
| Presentation | Final DCQL, signed `oauth-authz-req+jwt` fetched with GET request_uri; x509_hash client identity; direct_post.jwt; per-session encryption key. |
| Status | `status.status_list.idx/uri`; signed `statuslist+jwt` served as application/statuslist+jwt; one-bit, LSB-first, zlib-compressed list; 60-second cache TTL, five-minute JWT expiry. |
| Local verification | Only this issuer's retained public keys/issued registry; strict requested VCT/format, nonce/audience/sd_hash, disclosure commitments, active and non-retired status. This is not a general cross-issuer federation verifier. |
| Existing adapter | Custom mode retains StatusList2021 and explicit legacy sessions. It is not EUDI acceptance evidence. |

Age normally emits age_over_18/age_over_21 plus age_attested_at and optional jurisdiction;
options may configure thresholds. Default presentation requests age_over_18=true.
Employee requests given_name/family_name/organization/role.
Membership requests organization/membership_type.
The exact configured metadata and sample disclosed claims must be approved by the wallet ecosystem before
device acceptance: the custom VCT entitlement, classification, rendering, and status behavior are still unverified.

## Recommended acceptance environment

Use one stable hostname, e.g. **vericred-test.<a domain you control>**, for issuer and verifier.
Keep production and test data/keys separate. Use a small single-instance Docker host, persistent application
volume, and Caddy for HTTPS. Start with Android; then repeat the identical acceptance cases on pinned iOS
and miTch builds.

`compose.acceptance.yaml` and `deploy/Caddyfile.acceptance` are a prepared configuration, not a deployment.
The application has no published port in this configuration. Only Caddy is trusted at its fixed container
IP, and Caddy overwrites forwarding headers. Verify the chosen Docker subnet does not conflict with the host.
The Caddy image tag is based on [official v2.11.4](https://github.com/caddyserver/caddy/releases/tag/v2.11.4);
record the actual image digest when pulling/testing it.

### Provisioning still needed

1. Choose/control the hostname and point DNS to the authorized test host. Public TLS needs a valid certificate;
   Caddy can manage that after deployment is authorized. Public TLS certificates do **not** grant EUDI issuer/verifier trust.
2. Request test ecosystem onboarding for the custom credential VCTs and the required issuer/verifier roles.
   Obtain certificate chains and any registration evidence accepted by the pinned wallet's LoTE configuration.
   Do not disable its issuer ENFORCE policy or signed-metadata requirement to mark acceptance passed.
3. The issuer certificate must match the managed P-256 private key in the selected isolated
   DATA_DIR/issuer-key.json. Generate its CSR offline using that key; do not replace it with a random unrelated
   certificate or rotate the key through the console. The verifier uses its own P-256 PKCS8 PEM key and
   matching chain. The issuing authority determines certificate profiles/entitlements.
4. Seed a dedicated persistent data volume with the reviewed issuer config, synthetic holders and its signing
   key. Supply the issuer/verifier chains and verifier key through a read-only material directory, readable
   by container UID 1000. Keep private key material out of Git, images and logs.
5. Set ACCEPTANCE_HOST, ACCEPTANCE_DATA_VOLUME, EUDI_MATERIAL_DIR, ADMIN_API_KEY and PSEUDO_SECRET.
   Material filenames: issuer-chain.pem, verifier-chain.pem, verifier-key.pem, issuer-registration.jwt, verifier-registration.jwt, issuer-registrar-dataset.json, verifier-registrar-dataset.json and wallet-attestation-policy.json.
   The prepared acceptance Compose requires both registration JWTs and role-specific datasets; see [registration provisioning](EUDI_REGISTRATION.md).
   Provisioning/startup validates key matching and certificate validity, but does not establish wallet trust.
6. Confirm external trust registration and certificate recovery separately. Backup of the DATA_DIR cannot
   recover externally mounted certificate material or deployment secrets.

Before startup, run the read-only [offline material preflight](EUDI_MATERIAL_PREFLIGHT.md) against
the supplied deployment settings. Its local pass does not establish registration or wallet acceptance.

The isolated [Caddy/local TLS acceptance](CADDY_LOCAL_ACCEPTANCE.md) has passed with synthetic material.
Public HTTPS and independent phone/wallet acceptance remain separate.

After explicit deployment authorization and startup, run:

```sh
EUDI_ISSUER_CERT_SHA256=<independently-verified-leaf-DER-SHA256> \
  node scripts/https-preflight.mjs https://vericred-test.your-domain
```

The script verifies normal TLS validation, HSTS, the pinned signed metadata, matching JSON metadata,
required encryption advertisement, unauthorized credential rejection and nonce cache policy.
It creates one temporary public nonce. It does not prove trust-list registration or wallet acceptance.
Never set NODE_TLS_REJECT_UNAUTHORIZED=0 to obtain a pass.

## Acceptance gates

1. **Android:** accept the signed metadata and issuer entitlement; issue and render each agreed custom type;
   selectively present to the certificate-authenticated verifier; confirm encrypted messages.
2. **Negative cases:** wrong issuer/verifier trust, wrong VCT, wrong audience/nonce, altered disclosure,
   missing holder binding, replay, revoked credentials, unavailable/expired status and certificate expiry.
3. **HTTPS:** real phone reachability, public TLS chain/hostname, secure admin cookie, redirects and proxy
   rate limits; run HTTPS preflight and retain redacted results.
4. **Live connectors:** run `npm run test:connectors:live`; see [connector-acceptance.md](connector-acceptance.md).
   This needs a working Docker engine and actual temporary PostgreSQL/MySQL containers.
5. **Restoration:** run `npm run test:restore`; then repeat the offline recovery drill with separate Docker
   volumes and restored certificate/secret material. [Recovery policy](BACKUP_RESTORE.md) invalidates
   every old credential and temporary authorization; credential reissuance is required.
6. **iOS and miTch:** pin builds and repeat the shared success/negative cases. Android success is not proof
   for another wallet/platform.
7. Record candidate commit/diff identity, image digest, test time, wallet build, trust/settings fingerprints,
   redacted traces, and evidence owner. Commit/push/deploy still require the user's instruction.

## Evidence so far

Synthetic certificate and local route tests exercise signed metadata, encrypted VCI requests/responses,
certificate-authenticated encrypted VP, selective disclosure, replay and signed revocation.
They are automated protocol evidence only. No independent Android/iOS/miTch run has occurred.


## Device registration policy

The pinned Demo app's Check Registration Certificates setting ships OFF. Record its effective value and restart after a change. OFF interoperability does not establish ON acceptance. The candidate has signed metadata and authenticated VP requests, and carries provisioned registration certificates. External trust, identity binding, registration status, custom VCT entitlement and independent attested-key issuance acceptance remain unresolved. See [the verified device and onboarding guide](LIVE_WALLET_WALKTHROUGH.md) for the exact APK, official registration/trust-list links and the production registration requirements. Do not disable an enabled check to obtain a pass.

For the runnable synthetic preview and observed data flow, use [LOCAL_WALKTHROUGH.md](LOCAL_WALKTHROUGH.md). Its local HTTP/custom profile remains separate evidence.
