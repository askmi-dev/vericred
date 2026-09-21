# Registration profile review — 2026-09-20

Historical review: these transport gaps were implemented on 2026-09-21; see [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md). Independent wallet acceptance remains open. This review does not change the wire contract or provision registrar material.

## Finding

The current `registrationInfo()` in `src/wallet/registration.ts` emits only a `registration_cert` entry. Both `src/oid4vci/metadata.ts` and `src/oid4vp/router.ts` use it. Neither role transports a `registrar_dataset`. The earlier handover named only the issuer-side review; the verifier side is also missing.

| Role | Published profile requirement | Candidate reviewed on 2026-09-20 |
| --- | --- | --- |
| Issuer | ETSI TS 119 472-3 V1.1.1 §4.2.3 requires a nonempty registrar dataset in `issuer_info`, with `identifier`, `srvDescription`, `registryURI` and `providesAttestations`. | Registration JWT only; dataset absent. |
| Verifier | ETSI TS 119 472-2 V1.2.1 §6.3.2.2 requires a nonempty dataset in `verifier_info`, with `identifier`, `srvDescription`, `registryURI`, `intendedUseIdentifier`, `purpose` and `policyURI`; `credential` is optional. The containing entry excludes `credential_ids`. | Registration JWT only; dataset absent. |

Primary sources: [ETSI issuance profile](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf), [ETSI presentation profile](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf).

Do not conflate dataset field names with registration JWT claims: the pinned certificate evaluation uses `provides_attestations`; the issuer dataset uses `providesAttestations`. Copying decoded JWT claims into a dataset is not a valid implementation strategy.

## Pinned wallet source check

The pinned Android [issuer resolver](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/registration/issuer/IssuerRegistrationResolver.kt) filters entries to `registration_cert` before rejecting duplicates. The [verifier extractor](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/6533dd10ae838df35037c02f1fde0679647e5839/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/registration/relyingparty/VerifierInfoRegistration.kt) likewise selects a single matching certificate entry. They do not impose a one-element limit on the complete array.

This resolves the certificate-extraction question only. It does not establish successful metadata deserialization, dataset validation/rendering, registration trust or an actual device run. The existing wording “single matching entry” means one matching certificate, not a prohibition on a separately formatted dataset.

## Prioritized implementation and acceptance work

1. Read the referenced ETSI TS 119 475 and pinned TS05 data models before defining nested-field validation. Record exact types, locale rules and permitted attestation/claim shapes; top-level names alone are insufficient.
2. Add separate issuer/verifier registrar dataset files to the protected deployment-material contract. Load bounded JSON, reject malformed configured material, preserve registrar-provided fields and keep identities/purposes out of diagnostic logs. Do not manufacture records from synthetic holders, the registration JWT or local configuration.
3. Emit a separate dataset entry alongside the unchanged registration certificate in signed issuer metadata and signed verifier requests. Compare JSON/signed metadata, verify role separation and prohibit `credential_ids` on the verifier dataset entry. Add negative tests and pinned parser compatibility checks.
4. Extend provisioning/readiness, Compose mounts and material-recovery coverage. Report dataset presence/structure separately from trusted provenance, organization binding, registered scope and live status. A local pass must retain `releaseAccepted=false`.
5. Obtain independently authenticated registrar datasets and agree their identity, intended use and exact custom VCT scope. Run the pinned Android registration-ON flow, then the shared miTch contract and pinned iOS flow. Continue to record OFF separately.

The candidate is not claimed to conform fully to either ETSI profile. This was a targeted registration review, not an exhaustive profile audit. Existing synthetic, local TLS and Docker restoration results remain valid within their recorded scope; none proves this missing transport or external registration approval.
