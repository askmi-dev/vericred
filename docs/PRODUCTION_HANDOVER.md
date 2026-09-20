# VeriCred production handover

Updated 2026-09-21. This file is the current implementation and evidence record.

## Baseline and scope

Local branch: codex/Production-readyImplementation. HEAD and GitHub agent/add-oid4vp-flow
were initially verified at f7db672df3937f7d24247b600cdfe8e079952aea. The implementation candidate
adds the seven workstreams on that baseline. The September 21 request advances it to a draft PR;
inspect current Git/PR state for publication status. No production deployment occurred.

Downloads/Übergabe.md is historical background. Its examples, monorepo proposal and compatibility claims
are not instructions or evidence for the current implementation.

The user authorized implementing the seven recommended steps, including live connector acceptance and
backup restoration. Target: Android EUDI reference wallet first, iOS second, a single Docker instance with
persistent storage, and the same protocol contract for miTch.

## Current wallet candidate and provisioning gates

The candidate now implements the pinned attested-key JWT proof path: kid=0, authenticated key_attestation,
explicit provider/status signer leaf pins, assurance/certification checks, signed key-storage status,
nonce/holder binding and matching metadata. See [WALLET_ATTESTATION.md](WALLET_ATTESTATION.md).
Actual wallet-provider trust and status policy material has not been provisioned or independently accepted.

Registration transport is implemented: externally supplied rc-wrp+jwt files are checked for local
integrity/expiry and sent in issuer_info / verifier_info with base64url data. The acceptance Compose
requires both registration JWTs, issuer/verifier registrar datasets and wallet-attestation-policy.json. Registration ON trust, binding,
status and entitlement/scope remain explicit gaps. No local check establishes ecosystem approval.

## Seven workstreams

| Step | Implemented candidate | Remaining acceptance |
| --- | --- | --- |
| 1. Wallet contract/trust | Pinned Android proposal 2026.08.41-Demo build41, core0.30.2; explicit eudi-android profile, certificate/key/validity checks; shared miTch contract | Domain ownership, issuer/verifier onboarding, accepted certificate profiles/entitlements and exact custom-schema agreement; actual attestation-provider provisioning and external registration ON entitlement/status/binding |
| 2. Correctness/security | Configuration CAS revisions; stale source lookup rejection; frozen grant policy; matching discovery options; strict DCQL format/VCT; issuer migration and EUDI key-rotation guards; restricted proxy trust | Review complete uncommitted candidate and deployed proxy behavior |
| 3. Protocol | Signed issuer metadata; role-specific registrar datasets; signed x509_hash VP requests; encrypted VCI request/response and direct_post.jwt; Token Status List; custom/legacy adapter kept explicit | Independent device issuance/rendering/presentation/status with unchanged wallet trust policy |
| 4. Live connectors | Lookup identifier separate from stable ID; SQL DATE-only strings; awaited pool shutdown; isolated real PostgreSQL/MySQL acceptance harness and CI job | Target deployment source/schema/TLS validation; isolated live PostgreSQL and MySQL acceptance passed |
| 5. Docker/HTTPS | Persistent non-root runtime; backup CLI included; prepared Caddy acceptance Compose; HTTPS preflight and forwarding-header regression tests | Public HTTPS/phone reachability; isolated Caddy/local TLS runtime checks passed; Docker storage is on D: |
| 6. Restoration | Encrypted offline backup; authenticated manifest/checksums; source writer lease; restore into separate absent directory; retire old lists, fresh list identity and discard temporary authorization; custom and EUDI separate-volume Docker drills passed | Production secret-store/certificate and external database recovery, operator RPO/RTO; EUDI drill includes separately recovered synthetic material from a simulated protected store |
| 7. Cross-wallet/handover | Authenticated readiness API, responsive admin dashboard and QR walkthrough, repeatable localhost flow, current guides and tests | Android then pinned iOS and miTch runs; hosted CI after user-authorized commit/push |

See [EUDI_ACCEPTANCE_CONTRACT.md](EUDI_ACCEPTANCE_CONTRACT.md),
[connector-acceptance.md](connector-acceptance.md) and [BACKUP_RESTORE.md](BACKUP_RESTORE.md).

## Runnable local app

Run `npm run walkthrough` after building, then open **http://127.0.0.1:3310/admin/login**.
The active preview is bound only to loopback and uses persistent synthetic data in
`.validation-artifacts/local-walkthrough`. Its separate admin key is in that directory's
`secrets.json`; it is not printed or placed in Git. Existing issuer data and the project .env are not used.
Run `npm run walkthrough:flow` in a second terminal to create the visible active/revoked records.
[Local instructions](LOCAL_WALKTHROUGH.md) · [real wallet instructions](LIVE_WALLET_WALKTHROUGH.md).

## Verification through 2026-09-20

- Frontend/backend build: PASS, 12 static pages.
- Full source suite: PASS, 35 files / 382 tests. Includes 39 authenticated readiness tests and 10 offline provisioning tests, 54 wallet-attestation tests,
  19 registration-integrity tests and 9 signing-chain consistency tests,
  7 synthetic-certificate wallet tests, 10 filesystem restoration tests, 4 proxy tests, 8 metadata HTTPS tests and 2 actual local TLS attestation-status tests.
- Actual PostgreSQL 16 Alpine and MySQL 8.4: PASS. DATE, lookup/list identifiers, schema, missing record
  and live service-outage checks passed; generated containers were removed. Digests are in [connector evidence](connector-acceptance.md).
- Local synthetic HTTP flow: PASS, including holder lookup, signed holder-bound issuance, one-claim
  presentation, replay rejection, signed status/revocation refusal and active replacement issuance.
  Redacted result: `.validation-artifacts/local-walkthrough/flow-result.json`.
- Real headless Edge browser: PASS for login, readiness, records, offer/presentation QR controls,
  status endpoint, restored-page refresh, mobile navigation and non-overlapping headers/no overflow.
  No console/page errors. Screenshots retained in the local walkthrough directory.
- Docker relocation: COMPLETE after explicit user authorization. Active WSL storage is
  `D:\DockerDesktopData`; engine 29.3.0. Both VHDX backups were SHA-256 verified in
  `D:\DockerDesktopBackup\20260917-vericred-migration`. Existing 4 miTch containers and 7 images were retained.
- Docker runtime/restoration evidence image: BUILT and tested, `vericred:acceptance-20260919-review`.
  Image ID: `sha256:d6d9a4539dcb41b7824be5a75c3e4ad741b2d073a4c297b15731d3837c74e670`.
- Docker startup, protected routes, non-root runtime, restart, crash recovery, single-writer exclusion
  and encrypted restore into a separate volume: PASS, complete run exited 0 including cleanup. It proves
  key continuity, invalidated old authorization, every old status bit revoked, and fresh issuance.
  Initial helper auto-removal races were corrected with bounded existence/ownership-checked cleanup.
- Acceptance Compose parsing and CLI syntax checks: PASS. Isolated Caddy/local TLS proxy checks: PASS. Public Caddy/TLS deployment is not tested.
- EUDI Docker-volume restoration with local TLS and synthetic provider status: PASS on 2026-09-20.
  The provisioning image completed encrypted issuance, snapshot/post-snapshot changes, restoration to a
  separate volume with separately recovered test certificates/policy/secrets, old authorization/list
  invalidation and encrypted replacement issuance. The external material store is simulated, not a
  production vault recovery implementation. See [EUDI_RESTORE_ACCEPTANCE.md](EUDI_RESTORE_ACCEPTANCE.md).
- Independent Android, iOS and miTch acceptance: NOT RUN. Stock Demo registration OFF and production
  registration ON are distinct acceptance conditions; registration transport is implemented; external registration material and actual attestation-provider provisioning remain open.
- Hosted CI: NOT RUN. No commit, push or public deployment occurred.
- Earlier locked-dependency audits reported zero vulnerabilities; they were not rerun in this follow-up.

Synthetic/local tests remain distinct from actual wallet and public HTTPS acceptance.

## Important operation and recovery limits

- One writer per DATA_DIR; no HA or replicated transaction store. Abrupt termination can leave a lease
  for 30 seconds. Separate restored volumes must never run concurrently under the same issuer identity.
- Offline restore deliberately revokes every pre-recovery list (including indices absent from an older
  snapshot), creates a fresh list ID and discards grants/tokens/nonces/admin/VP sessions. **Credentials must
  be reissued after restoration.** Unknown lists created after a snapshot are unavailable and must fail closed.
- File atomicity does not make issuance one transaction. A crash can leave unused status entries or require
  a fresh nonce/offer. Exactly-once business issuance is not guaranteed.
- Runtime signing/encryption keys, configuration and source/status data are not all encrypted at rest.
  Protect the volume. Backup files are AES-GCM encrypted and the manifest authenticated; keep PSEUDO_SECRET
  stable and separately recoverable. External databases, mounted certificates and deployment secrets need
  separate backup/recovery procedures.
- EUDI mode validates configured certificate/key matching and validity; this does not establish LoTE
  membership, registration or entitlement. Custom VCTs are not PID or qualified credentials.
  mdoc, auth-code, DPoP, batch/deferred issuance and WIA client attestation are not implemented. Key-attested JWT proof support uses explicit leaf pins; automatic LoTE trust validation is not implemented.
- Custom mode allows managed key rotation and retains public history. EUDI console rotation is blocked
  until certificate replacement can be coordinated. Handle historic backups containing previous private keys.
- TRUSTED_PROXY_CIDRS accepts only explicit IPs/CIDRs. Configure actual proxy peers and overwrite incoming
  forwarding headers there. Do not trust arbitrary forwarded client values or proxy hop counts.
- Audit JSONL remains local and not tamper-evident. Retention, monitoring and external audit delivery remain
  operational work. CSP retains unsafe-eval for the browser Tailwind runtime.
- Employment/membership business dates do not independently constrain JWT expiry; agree validity policy
  before releasing those profiles. The verifier is limited to this issuer and its local issued registry.
- Desktop and mobile admin rendering was inspected with isolated Edge/Playwright. The Codex computer-use
  runtime failed to initialize; the bundled browser-testing library was used instead.

## HTTPS preflight follow-up (2026-09-19)

The preflight now compares every discovery field between signed and JSON metadata, including
registration transport and encryption settings. It rejects missing credential configurations,
missing/invalid attestation assurance requirements, invalid storage periods, stale/future metadata,
and responses larger than 1 MiB. Its report explicitly leaves wallet, registration-policy ON and
provider trust acceptance as NOT RUN; a local TLS pass is not public-host acceptance.

The full regression suite passed (33 files, 342 tests), and the backend build passed.
Eight local TLS preflight tests passed, including endpoint/registration disagreement, missing
attestation requirements, empty configurations, future timestamps, oversized responses and a wrong
signer pin. These checks establish local contract shape/consistency, not independently agreed
provider pins, certification, assurance or custom VCT/schema acceptance. The earlier attestation image was not rebuilt for that tooling-only follow-up. A new image was
built and tested for the subsequent correctness fixes below.

## Local correctness review follow-up (2026-09-19)

Three defects found during the local review were corrected:

- Signing-chain validation now checks parent CA constraints and child/parent issuer identity, in
  addition to signatures and validity. Registration-chain validation also checks issuer identity.
  A same-key certificate with an unrelated subject no longer passes as a supplied parent. These
  checks establish local chain consistency only, not PKIX path validation or ecosystem trust.
- Attestation verification retains every status result's expiry, TTL, maximum-age and certificate
  deadline and rechecks them after all status requests. Attestation age is rechecked too. A slow
  second request can no longer allow an earlier status result to become stale before issuance.
- Offline recovery uses the manual connector's actual default registry when its path is omitted,
  preserving the holder dataset instead of selecting the JSON connector's default file.

The complete suite passed: 34 files / 358 tests. Frontend (12 pages) and backend builds passed.
The new image `vericred:acceptance-20260919-review` passed the full disposable Docker runtime, crash
recovery and separate-volume backup/restore drill (exit 0 including cleanup). This remains custom-profile
container evidence; it does not establish independent wallet, public HTTPS or external-material recovery
acceptance. Redacted results: `.validation-artifacts/correctness-followup-result.json`.

## Offline provisioning follow-up (2026-09-20)

`node scripts/eudi-material-preflight.mjs --offline` validates existing EUDI configuration, signing
material, registration transport and attestation policy without initializing data, loading .env,
creating keys or contacting a network service. Explicit eudi-android / required registration settings
and environment-supplied deployment secrets are required. The report is redacted and every independent
acceptance field remains NOT RUN. See [EUDI_MATERIAL_PREFLIGHT.md](EUDI_MATERIAL_PREFLIGHT.md).

Admin readiness now applies the same parent CA/issuer-identity constraints as the runtime signing path.
It also validates the stored issuer public key and nonblank key ID; a local signature challenge verifies
that issuer and verifier private keys actually sign for their certified public keys. This catches
malformed EC keys whose stored public coordinates disguise an inconsistent private scalar.

Validation: 35 files / 382 tests passed; frontend (12 pages) and backend builds passed. The compiled CLI
rejects missing configuration without creating files and rejects incorrect arguments. Secret presence
and length do not prove entropy, decryption continuity or successful recovery. External materials,
provider trust, registration ON, public HTTPS and independent wallets remain acceptance gates.

The new local image `vericred:acceptance-20260920-provisioning` was built with the offline CLI.
Image ID: `sha256:cd2d5e8ce4ab02a5f7eab6b876bb880d145e05d5e78709304bbeca67f5f56380`.
The packaged CLI passed its missing-config/fail-closed check with network disabled and a read-only
empty fixture; the disposable container was removed. The full Docker runtime/restoration drill remains
the separately recorded 2026-09-19 image evidence and was not rerun for this image.
Redacted report: `.validation-artifacts/provisioning-followup-result.json`.

## Local Caddy/TLS follow-up (2026-09-20)

`scripts/caddy-acceptance.mjs` passed against `vericred:acceptance-20260920-provisioning` and
`caddy:2.11.4-alpine` (Caddy image ID
`sha256:de23def33b17fb5d1290b0f6c2add1d70780e52341896c00a4c8a2a2fe9d355e`).
The harness preserves the prepared reverse-proxy directives in an isolated copy, supplies synthetic
TLS/signing/registration/attestation material, and binds only random loopback host ports.

Observed checks passed: replacement/removal of spoofed forwarding headers; unrelated Host isolation;
trusted and rejected-untrusted TLS; HTTP redirect; full pinned signed-metadata preflight; secure
HttpOnly/SameSite admin cookie; authenticated non-cacheable readiness; and login rate-limit enforcement
while the client rotates forged forwarding addresses. The EUDI gateway used registration required;
independent registration-policy ON/provider/wallet acceptance remained NOT RUN.

An initial internal-only proxy network did not expose the test host port. The completed harness uses
a separate proxy network and an internal backend network, and passed after that fixture correction.
All owned containers/networks were removed. Synthetic fixture files remain ignored locally; the
redacted report is `.validation-artifacts/caddy-acceptance-result.json` and includes image/template/
harness hashes. See [CADDY_LOCAL_ACCEPTANCE.md](CADDY_LOCAL_ACCEPTANCE.md).

This is actual local Caddy/TLS evidence, not public DNS/certificate/phone acceptance, an independent
wallet run, a live customer source test or a new Docker-volume restoration drill. Application source
was unchanged in this follow-up; the prior 382-test/build evidence remains separately recorded.
The local custom-profile preview was restarted with its existing fixture and keys after its health
check found it unreachable; no fixture reset or key rotation occurred.

## EUDI restoration follow-up (2026-09-20)

The new `scripts/eudi-restore-acceptance.mjs` passed the complete disposable Docker drill using
`vericred:acceptance-20260920-provisioning` and Caddy 2.11.4 Alpine. A synthetic client verifies pinned
signed metadata, encrypts the attested-key credential request, decrypts the response and verifies the
issuer signature, holder binding, disclosure digests and signed EUDI Token Status List. The synthetic
provider serves its signed status over actual TLS on the isolated container network.

Three distinct volumes hold source state, the encrypted application backup and recovered state.
The source is stopped and removed before the recovered gateway starts. Externally mounted deployment
certificates, registration files, verifier key, attestation policy and environment secrets are recovered
into a different path from an AES-GCM protected fixture store; tampering is rejected. Its recovery key
exists only in test-process memory. This proves the fixture's material continuity and use by the
recovered application; it is not a production secret-manager backup, retention or recovery procedure.

The final run confirms successful post-snapshot revocation and unseen issuance, read-only recovered
material preflight, public-key continuity, rejection of previously working admin/VP sessions and an
access token before natural expiry, rejection of the pending grant, every bit of the old status list
retired, and new encrypted issuance on a fresh list. The provider's private signing keys are never
mounted into the gateway. All resources carrying the run's ownership label were removed.

Result: `.validation-artifacts/eudi-restore-acceptance-result.json`, checked at
`2026-09-20T13:30:41.492Z`, includes image IDs and hashes of the harness, helpers and Caddy template.
See [EUDI_RESTORE_ACCEPTANCE.md](EUDI_RESTORE_ACCEPTANCE.md) for the repeatable command and limits.
Only host-side harnesses and documentation changed; the earlier 382-test/build evidence was not rerun.
The existing loopback preview remains healthy with its existing data and keys.

Independent wallet, registration-policy ON, public HTTPS, customer database recovery and production
secret-store recovery remain NOT RUN. Local required-registration configuration is not the wallet's
registration ON acceptance. Operator RPO/RTO evidence remains outstanding.

## Registration profile review (2026-09-20)

The missing registrar dataset is a confirmed implementation gap for both issuer and verifier, not
only an issuer-side question. The published ETSI issuance and presentation profiles require separate
registrar data. Current `registrationInfo()` transports only the certificate for either role.
The exact pinned Android certificate extractors select by format; a single matching certificate
requirement does not itself prohibit an additional dataset entry. End-to-end parser/device acceptance
of datasets remains untested. See [REGISTRATION_PROFILE_REVIEW.md](REGISTRATION_PROFILE_REVIEW.md)
for primary sources, field-name distinctions and the ordered implementation/acceptance steps.

This follow-up changes documentation only. It does not provision or implement registrar datasets,
change runtime behavior or extend the existing 382-test/build, local TLS or restoration evidence.
Registration-policy ON remains open. No commit, push or deployment occurred.

## Delivered registrar datasets and PR validation (2026-09-21)

Registrar dataset transport is implemented for issuer and verifier. Required registration policy now
requires both registrar JSON files as well as the two JWT files; configured invalid datasets also fail
under optional policy. Bounded local role/shape checks preserve supplied fields and reject malformed,
oversized or excessively nested input. They do not authenticate a registrar, establish scope or infer
organization binding. The supported flat localized shape and migration are documented in
[REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md). Newer nested TS05 shapes require explicit agreement.

JSON/signed issuer metadata and signed verifier requests carry separate dataset entries. Admin
readiness and offline preflight expose each role's dataset result without identities, purposes or
paths. Acceptance Compose requires the files. The synthetic material generator and EUDI restore drill
recover both datasets separately; the client checks the exact issuer dataset in signed metadata.

Validation completed:

- Full source regression: 36 files / 406 tests passed after the registrar implementation.
- Additional HTTPS diagnostic fix: 9 focused local TLS preflight tests passed, including a new test
  proving metadata mismatch errors do not print registration material. This replaced the former
  structural-diff error output with a generic comparison failure.
- Backend build and frontend build (12 pages) passed. The frontend was rebuilt after updating the
  single transitive devalue dependency from 5.8.1 to 5.9.4; both dependency audits now report zero
  vulnerabilities. The initial audit found GHSA-9rgm-9g3h-6x36 in the old version.
- New image vericred:acceptance-20260921-registrar built successfully, image ID
  sha256:a7baab025884e86470359980baba12ae4c4b7ef0a0d90ee0ab853629728f1579.
- Complete custom-profile Docker smoke, crash recovery, writer exclusion and separate-volume restore:
  PASS, exit 0 including cleanup.
- Isolated Caddy/local TLS, signed metadata, admin cookie and forwarding/rate-limit boundaries:
  PASS, exit 0 including cleanup; report checkedAt 2026-09-20T23:00:08.531Z (September 21 in Vienna).
- EUDI Docker-volume restore with registrar datasets, synthetic provider HTTPS status, encrypted
  issuance and recovered authorization/list invalidation: PASS, exit 0 including cleanup;
  report checkedAt 2026-09-20T23:00:51.488Z (September 21 in Vienna).

All seven workstreams have implemented candidate components; this is not completed independent release
acceptance. Actual wallet/registration-ON, public-host TLS/phone reachability, authenticated provider and
registrar material, customer database recovery and production secret-store recovery remain external
gates. Isolated real PostgreSQL/MySQL evidence remains the separately recorded earlier run.

PR baseline review: GitHub agent/add-oid4vp-flow still points to f7db672. Its PR #1 remains open against
main. The next candidate PR should therefore be stacked on that branch to isolate these changes.
No production deployment or live trust registration has been performed.

## Next implementation and external actions

1. Provision independently verified wallet-provider/status signer pins and agree assurance, certification,
   status paths and maintenance periods. Run real Android issuance with the implemented attested-key path.
2. Complete issuer/verifier onboarding and exact custom VCT/schema/status agreement, registration
   identity binding, entitlements and live status. Provision authenticated registrar datasets for both roles and validate the agreed field/scope contracts.
3. Choose a controlled test hostname (suggested pattern: vericred-test.<your-domain>); provision accepted
   signing and registration material, deployment secrets and a dedicated persistent volume.
4. After explicit deployment instruction, validate Caddy/public HTTPS and phone reachability, then run
   the pinned Android APK. Record registration OFF and ON separately; repeat on pinned iOS and miTch builds.
5. Validate the actual customer database connection, schema and TLS; isolated PostgreSQL/MySQL evidence
   already passed and does not establish a customer's integration.
6. Recover certificates/secrets from the actual protected store and restore any external database;
   record operator RPO/RTO. Custom and EUDI Docker-volume drills passed; the EUDI drill uses a simulated
   external material store. Recovery requires credential reissuance.
7. Review the next draft PR and its hosted CI under the September 21 PR instruction. Merging or
   deploying still requires user instruction; independent release acceptance remains open.

## Earlier test-isolation incident

The Vitest upgrade initially discovered old compiled tests in dist. One stale test wrote a synthetic
admin-session file and a restart entry to ignored local data. The exact introduced artifacts were removed
from active data, with recovery copies under .validation-artifacts/test-isolation-recovery-20260916.
Holder, issuer-key, config and status files had unchanged timestamps. Source-only test discovery now
prevents generated tests from running.

## Handover prompt

> Treat Übergabe.md as historical background and docs/PRODUCTION_HANDOVER.md as the current record.
> Continue the production candidate on codex/Production-readyImplementation based on f7db672.
> Inspect current Git status and the draft PR before editing; do not assume the candidate is uncommitted.
> Use docs/EUDI_ACCEPTANCE_CONTRACT.md for Android-first EUDI and the shared miTch contract.
> Preserve the distinction between automated synthetic/local TLS/restoration evidence and independent
> wallet, public HTTPS, live database and Docker-volume acceptance. Do not commit, push or deploy without
> user instruction. Docker relocation is authorized and complete at D:\DockerDesktopData.
> Use docs/LOCAL_WALKTHROUGH.md for the running synthetic local app and docs/LIVE_WALLET_WALKTHROUGH.md
> for real Android onboarding. Registration-policy ON acceptance remains an explicit gap. Read docs/EUDI_REGISTRATION.md for the
> implemented registration transport; use docs/WALLET_ATTESTATION.md for the implemented attested-key path
> and outstanding provider trust/assurance/status provisioning.
> Registrar dataset transport is implemented: read docs/REGISTRAR_DATASETS.md for the required files,
> supported shape and migration. Use the latest validation section above; synthetic material and
> local Docker/TLS/restoration passes do not establish independent release acceptance.
