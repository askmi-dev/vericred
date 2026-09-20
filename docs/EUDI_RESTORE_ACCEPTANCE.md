# EUDI Docker restoration acceptance harness

This host-side harness exercises the EUDI protocol profile against disposable Docker volumes, local HTTPS and a running synthetic attestation-status provider. It also simulates recovery of separately stored deployment material. It is local automated evidence; it does not establish independent wallet or production secret-store acceptance.

The current implementation/status record remains [PRODUCTION_HANDOVER.md](PRODUCTION_HANDOVER.md). Protocol and external acceptance requirements remain in [EUDI_ACCEPTANCE_CONTRACT.md](EUDI_ACCEPTANCE_CONTRACT.md), [EUDI_REGISTRATION.md](EUDI_REGISTRATION.md) and [WALLET_ATTESTATION.md](WALLET_ATTESTATION.md).

## Run

Run from the repository root:

```powershell
Set-Location -LiteralPath 'D:\Mensch\VeriCred'
node scripts/eudi-restore-acceptance.mjs vericred:acceptance-20260920-provisioning
```

The optional image argument selects an existing VeriCred runtime image. Omitting it uses `vericred:acceptance-20260920-provisioning`. The harness inspects both that image and `caddy:2.11.4-alpine` before creating Docker resources; both must already be present locally. It does not build or pull images.

Prerequisites:

- Node.js with the checkout's installed dependencies, including `jose`.
- A running Docker engine in Linux-container mode, with access to bind mounts beneath this checkout and space for three fresh named volumes. Docker storage at `D:\DockerDesktopData` is used through the existing Docker setup; the harness does not relocate it.
- A VeriCred runtime image containing the current application, `scripts/backup-restore.mjs` and `scripts/eudi-material-preflight.mjs`.
- OpenSSL. The helper uses `OPENSSL_BIN` when provided, otherwise Git for Windows' `C:/Program Files/Git/usr/bin/openssl.exe` when present, otherwise `openssl` on PATH.
- Permission to create and remove the run's disposable containers, volumes and networks, and to bind one dynamically allocated HTTPS port on `127.0.0.1`.

Each invocation generates fresh synthetic keys, certificates, registration JWTs, policy, holder data and admin/pseudonym secrets. It does not require production credentials. The existing preview on port 3310 is separate from this drill.

## Isolation and material layout

Every run uses a random UUID in its Docker resource names and the ownership label `com.vericred.eudi-restore=<run UUID>`.

| Named volume | Purpose | Mount during the relevant operation |
| --- | --- | --- |
| `vericred-eudi-restore-<UUID>-source` | Original application state | `/app/data` |
| `vericred-eudi-restore-<UUID>-backup` | Encrypted offline application snapshot | `/backup` |
| `vericred-eudi-restore-<UUID>-restored` | Recovered application state | `/recovery`, with `DATA_DIR=/recovery/data` |

The recovered application never mounts the source volume. The offline restore writes into a new destination. Backup and restore jobs have no network, and the material preflight mounts recovered data read-only. The runtime image can also create anonymous volumes through its Dockerfile volume declaration; these are removed with their owned containers.

An internal backend network connects the gateway, Caddy and a synthetic status provider. Caddy also joins a separate frontend network and publishes HTTPS only on a random loopback port. The gateway trusts the proxy's exact backend address. Source and recovered applications use the same loopback origin; the source container is stopped and removed before the recovered application starts.

Caddy uses a freshly generated local TLS certificate. The host client explicitly trusts that fixture certificate and keeps TLS verification enabled. The gateway separately trusts the synthetic provider's TLS certificate through `NODE_EXTRA_CA_CERTS`. The provider serves fresh signed Token Status List JWTs at `https://wallet-status:9443/lists/storage` over an actual HTTPS connection. Its records and signers are synthetic; it is not an external EUDI provider.

### Simulated separate material recovery

The application backup contains issuer key/state files. Deployment material is handled separately:

- Issuer and verifier certificate chains, plus the verifier private key.
- Both registration JWTs.
- Wallet attestation policy and the provider TLS certificate.
- Generated admin and pseudonym secrets.

The harness encrypts this material with AES-256-GCM, a random 32-byte recovery key, a random IV and fixed associated data. It writes the authenticated envelope to `synthetic-material-store.json` and verifies that an altered authentication tag is rejected. The recovery key stays only in the running host process's memory.

After the application snapshot, the harness decrypts the envelope and writes a new `recovered-material` directory. Every recovered named file must equal the original bytes. The recovered gateway mounts this new directory read-only at `/run/eudi`; it receives the recovered secrets through environment variables. Provider signing keys are not mounted into the gateway.

This models separation of application backup and deployment material during one process execution. It is not an operator vault design: the envelope cannot independently recover the materials after the memory-only key is lost. Original plaintext synthetic fixture material remains on the host for inspection.

## Assertions in the drill

1. Start the source application with `WALLET_PROFILE=eudi-android` and `EUDI_REGISTRATION_POLICY=required`, using synthetic material for both registration roles.
2. Issue an encrypted AgeCredential with a locally generated attested holder key. The helper verifies signed issuer metadata against the fixture issuer certificate, decrypts the credential response, checks the SD-JWT signature and disclosure digests, confirms holder-key binding, and verifies its signed Token Status List entry is active.
3. Create a pending pre-authorized grant, a separate access token, a VP session and an admin browser session. Confirm the cookie and VP read token work. Confirm the access token passes authentication by observing the expected encryption-parameter error for an intentionally unencrypted credential request.
4. Stop the source application and create an encrypted, authenticated application backup in the backup volume.
5. Restart the source. Require successful revocation of the first credential, redeem the pending grant, and issue another encrypted credential at a higher index on the old list. These changes happen after the snapshot.
6. Stop and remove the source container. Recover the separate simulated material store, restore the application snapshot into the fresh recovery volume, and require the offline material preflight to pass with `releaseAccepted=false`.
7. Start the recovered gateway. Require unchanged issuer JWKS, rejected old admin/VP sessions, rejected pending grant and rejected old access token. The access-token rejection must occur before its natural expiry, so elapsed time alone cannot satisfy the assertion.
8. Verify the signature and every bit of the old Token Status List: all indices must be revoked, including indices unknown to the snapshot. Issue a fresh encrypted replacement credential and require a different list identifier with index zero.
9. Require Admin readiness to report `configurationReady=true` and `releaseAccepted=false`, then remove the run's Docker resources.

The credential issuance and status checks are synthetic protocol tests. The harness initiates and invalidates a VP session; it does not complete a wallet presentation flow.

## Cleanup and retained evidence

Cleanup runs after success or failure. Before removing a named container, volume or network, the harness inspects it and requires the exact run ownership label. Containers are removed before named volumes and networks; their anonymous volumes are removed with them. It does not prune unrelated Docker resources. Any cleanup failure makes the invocation fail and identifies the owned resources requiring inspection.

Host fixtures remain in `.validation-artifacts/eudi-restore-*`, which is ignored by Git. These directories include synthetic private keys and recovered material as well as the encrypted simulated store. They are test fixtures, not a public evidence bundle.

Only a successful run with successful cleanup writes both:

- The invocation's `.validation-artifacts/eudi-restore-*/result.json`.
- `.validation-artifacts/eudi-restore-acceptance-result.json` as the latest successful summary.

Reports contain the check timestamp, image names and IDs, hashes of the harness/helpers/Caddy template, checked behaviors and explicit acceptance exclusions. They do not contain credentials, tokens or private keys. A failed run does not replace the latest successful summary; match its time and source hashes to the invocation being assessed.

## Limits of this evidence

| Area | What this harness establishes |
| --- | --- |
| Docker storage | Actual application snapshot and separate-volume restoration in the local Docker engine. |
| TLS and provider status | Actual local TLS connections using synthetic certificates, provider policy and signed status responses. |
| EUDI registration | Required registration material passes the local transport/configuration path. Independent wallet registration-policy ON acceptance remains **NOT RUN**. |
| Wallets | Independent Android, iOS and miTch acceptance remains **NOT RUN**. No reference-wallet device participates. |
| Public HTTPS | Public hostname, DNS, public certificate chain and phone reachability remain **NOT RUN**. |
| Customer databases | The data source is a synthetic JSON fixture. Live customer database recovery remains **NOT RUN**. |
| Production secret recovery | Production secret-store recovery remains **NOT RUN**. No vault, external key custody, backup retention policy or recovery-time objective is validated. |

Caddy and the synthetic provider continue running across the application restoration. These services are not rebuilt from recovered material; their running keys and configuration remain in place. This drill therefore does not establish recovery after loss of the entire host or Docker storage, proxy certificate recovery, external provider availability, or real provider trust/assurance/status provisioning.

## Final-run evidence

The final strengthened invocation on **2026-09-20** completed with **PASS**, exit code 0 and **cleanup PASS**. Its report records `checkedAt=2026-09-20T13:30:41.492Z`.

- Application image: `vericred:acceptance-20260920-provisioning`.
- Application image ID: `sha256:cd2d5e8ce4ab02a5f7eab6b876bb880d145e05d5e78709304bbeca67f5f56380`.
- Proxy image: `caddy:2.11.4-alpine`.
- Proxy image ID: `sha256:de23def33b17fb5d1290b0f6c2add1d70780e52341896c00a4c8a2a2fe9d355e`.
- Redacted report: `.validation-artifacts/eudi-restore-acceptance-result.json`, including SHA-256 hashes for the harness, both synthetic helpers and `deploy/Caddyfile.acceptance`.

This run includes the positive admin/VP/token baselines, successful post-snapshot revocation assertion, and token rejection before natural expiry. The prior 382-test and build evidence is unchanged; this addition changes host acceptance scripts and documentation. The external acceptance exclusions above remain open.

## Registrar dataset follow-up (2026-09-21)

The updated image `vericred:acceptance-20260921-registrar` passed the local Docker validation
recorded in [PRODUCTION_HANDOVER.md](PRODUCTION_HANDOVER.md). Required registration now includes
both role-specific registrar JSON files; see [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md).
The EUDI restoration drill includes these files in the separately recovered synthetic material store.
All prior independent-acceptance and production-secret-store limitations remain.
