# EUDI registration transport and wallet acceptance

Updated 2026-09-21. This is an implementation contract, not independent wallet acceptance.
Target: Android 2026.08.41-Demo build 41, core v0.30.2
(`6533dd10ae838df35037c02f1fde0679647e5839`). miTch uses the same reviewed contract.

## Registration transport implemented

Provision registrar-issued compact JWS files outside Git and the image:

| Setting | Purpose |
| --- | --- |
| `EUDI_REGISTRATION_POLICY=required` | Refuse EUDI startup without both locally valid registration JWTs and registrar datasets |
| `EUDI_ISSUER_REGISTRATION_CERT_PATH` | Issuer registration JWT file |
| `EUDI_VERIFIER_REGISTRATION_CERT_PATH` | Verifier registration JWT file |

`compose.acceptance.yaml` requires the policy and reads `/run/eudi/issuer-registration.jwt`
and `/run/eudi/verifier-registration.jwt` from the existing read-only material mount.
The default `optional` preserves existing synthetic fixtures; configured invalid material fails even
under that policy. This gateway setting does not change the Android registration switch.
Custom mode does not publish registration information.

The gateway publishes exactly one `registration_cert` entry per configured role and a separate
`registrar_dataset` entry from the supplied role-specific JSON file. Required policy requires both.
See [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md) for migration, shape checks and boundaries.

Certificate transport:

- `issuer_info` in issuer metadata (including its signed JWT representation).
- `verifier_info` in the signed OpenID4VP Request Object, without `credential_ids`.
- Each entry's `data` is base64url of the original compact JWT bytes. The gateway does not issue,
  re-sign, rewrite or add entitlement claims to the registrar's certificate.

The [pinned issuer resolver](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/registration/issuer/IssuerRegistrationResolver.kt)
and [verifier extractor](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/registration/relyingparty/VerifierInfoRegistration.kt)
require a single matching entry. [Its decoder](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/registration/SerializedRegistrationCertificate.kt)
accepts both compact JWT and base64url serialization; the latter follows
[ETSI TS 119 472-2 v1.2.1, section 6.3.2.2](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf).

### Local validation boundaries

The loader bounds each file to 128 KiB and accepts compact JWS only. It checks `typ=rc-wrp+jwt`,
an allowed asymmetric signature against the embedded x5c leaf, certificate validity, chain signatures, parent CA constraints and child/parent issuer identity,
JWT `sub`/`iat`/`exp`, and an HTTPS `status.status_list` reference with index 0..2147483647.
Unreadable, malformed, tampered and expired material fails closed. Checks repeat when messages are
prepared, so an expired/replaced-invalid file is not served from a stale cache.

**An embedded signing certificate is not a trust anchor.** These checks do not establish trusted-list
membership, organization binding, live registration status, provider entitlement or requested/issued
scope. No status URLs are fetched by this loader or by the observational readiness API. The Admin
page reports transport checks separately and keeps registration-enabled wallet acceptance unverified.

The wallet checks registration identity against the access certificate's organization identifier
(or serial number), including intermediary rules. Issuer scope uses `provides_attestations`, verifier
scope uses `credentials`; registration credential entries use `claim`, while DCQL uses `claims`.
Registration status has its own provider trust requirements. Obtain approved custom VCT scope and
provider entitlements from the registrar. See the
[pinned registration guide](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/REGISTRATION_CERTIFICATE.md).
Registrar dataset transport is now implemented for both roles. See [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md).
The prior [profile review](REGISTRATION_PROFILE_REVIEW.md) remains historical evidence of the gap.

## Pinned Android attested-key proof follow-up

The 2026-09-18 source review found that the pinned wallet requires key_attestations_required metadata
and kid=0/key_attestation proofs. The 2026-09-19 candidate now implements this path with explicit
provider and status signer pins, assurance checks and signed key-storage status validation. See
[WALLET_ATTESTATION.md](WALLET_ATTESTATION.md) for provisioning, primary sources and exact boundaries.

The original embedded-JWK incompatibility is addressed in code and synthetic integration tests.
Actual wallet-provider trust/assurance/status configuration and independent device acceptance remain
open. Registration ON trust, binding, live status, custom VCT entitlement/scope and independently agreed registrar dataset contents
remain separate requirements; neither successful local validation nor the Demo OFF setting closes them.
