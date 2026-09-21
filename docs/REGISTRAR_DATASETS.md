# Registrar dataset transport

Implemented 2026-09-21 for the Android-first EUDI candidate and shared miTch contract. These are local transport-shape checks, not registrar authentication or full ETSI conformance.

## Provisioning and migration

Supply the registrar's JSON objects as two separate files outside Git and the image:

| Environment setting | Acceptance mount |
| --- | --- |
| `EUDI_ISSUER_REGISTRAR_DATASET_PATH` | `/run/eudi/issuer-registrar-dataset.json` |
| `EUDI_VERIFIER_REGISTRAR_DATASET_PATH` | `/run/eudi/verifier-registrar-dataset.json` |

**Migration:** `EUDI_REGISTRATION_POLICY=required` now requires both datasets as well as both registration JWTs. Existing required-policy deployments must provision the two additional files before updating. The acceptance Compose supplies both paths. Optional mode omits absent material, but any configured invalid dataset fails closed. Custom mode does not publish or inspect these EUDI datasets.

The loader reads at most 128 KiB per file, rejects non-object roots and excessive nesting, and checks the role-specific structure. It preserves supplied fields, including extensions, without deriving registered information from issuer settings or rewriting the registrar's registration certificate. A replacement-invalid file is rejected on the next message preparation. URLs are inspected locally; they are never fetched by this loader or readiness.

## Supported local shape

Common fields are a nonempty `identifier` array of `{type, identifier}` objects, a nonempty flat `srvDescription` array of `{lang, content}` objects, and an HTTPS `registryURI`. Identifier types must be absolute URIs; identifiers and text must be nonblank. Language tags use a two-lowercase-letter shape check, not a language-registry lookup.

Issuer data additionally requires nonempty `providesAttestations`, each with nonblank `format` and absolute URI `type`. Verifier data requires `intendedUseIdentifier`, a flat localized `purpose` array and HTTPS `policyURI`. Optional `credential` entries need `format` and a nonempty `meta` object; optional `claim` entries are bounded nonempty objects. Nested claim semantics, entitlement and requested VCT coverage are not validated by these shape checks. The containing transport entry has no `credential_ids`.

This intentionally supports the flat localized structure of the published transport profiles. Newer TS05 common-model examples use nested service-description arrays; those are rejected rather than silently converted. The registrar and pinned wallets must agree the actual payload shape before acceptance. `providesAttestations` in the dataset is distinct from `provides_attestations` in the registration JWT.

References: [ETSI issuance profile §4.2.3](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf), [ETSI presentation profile §6.3.2.2](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf), [ETSI data model Annex B](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf), [TS05 common model](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/api/ts5-json-common-rp-data-model.json).

## Message and admin behavior

Each configured role adds one `{format: "registrar_dataset", data: <supplied object>}` entry alongside its unchanged `registration_cert`. Issuer data appears in both JSON and signed issuer metadata; verifier data appears in the signed request object. The same transport applies to miTch. The pinned Android certificate extractors select matching certificate entries by format, but device/parser acceptance of a real dataset remains untested.

The Admin readiness endpoint exposes issuer/verifier dataset checks separately from certificate checks. Required missing or configured-invalid material blocks configuration readiness. The offline preflight includes both checks and performs no network access. Neither endpoint returns dataset contents, identities, purposes or source paths, and `releaseAccepted` remains false.

Recover these files separately with the deployment certificate/policy material, then run the offline preflight. The EUDI restore harness includes both datasets in its simulated encrypted material store and checks the exact issuer dataset in signed metadata before and after restoration. This is synthetic recovery evidence, not authentication of an actual registrar or recovery from a production vault.

## Remaining external gates

Obtain authenticated registrar material, verify organization/access-certificate binding, agree intended use and custom VCT scope, validate live registration status and provider trust, and complete the pinned Android registration-ON run. Record OFF separately; repeat the agreed contract on iOS and miTch. Synthetic fixtures must not be provisioned as trusted production records.
