# Offline encrypted backup and restoration

## Recovery policy

Restoring an old status registry cannot prove which credentials were revoked or issued after the snapshot. The supported recovery policy therefore **revokes every index of every pre-recovery status list**, including indices absent from the snapshot, and starts a new random list identity at index zero. Credentials issued on a later list absent from the backup receive an unknown-list response and must fail status validation. Reissue credentials after recovery.

This deliberately sacrifices availability of previously issued credentials to prevent a revoked credential becoming valid again. There is no supported switch to preserve their validity from an old snapshot. A future reconciliation mode would require independently durable, authenticated post-snapshot revocation and issuance records.

Recovery deletes pre-authorized codes, access tokens, credential nonces, admin sessions, CSRF tokens and presentation sessions from the **new target only**. A code consumed after the backup cannot be replayed after restore. Users must restart login, issuance and presentation flows.

Existing cached status responses cannot be remotely erased by a restore. Before resuming relying-party traffic, expire/purge caches under your control and enforce the agreed status freshness policy at each verifier. Unknown, unavailable or expired status must fail closed. Recovery cannot guarantee rejection by independent verifiers that ignore status or keep stale status indefinitely.

## Scope and storage

`src/storage/recovery.ts` and `scripts/backup-restore.mjs` provide the offline tool. Build the backend before using it:

```sh
npm run build:backend
```

Each data file is encrypted with AES-256-GCM; file paths are authenticated as additional data. A manifest records plaintext SHA-256 and size and is authenticated with HMAC-SHA-256. Separate file and manifest keys are derived using HKDF from the separately supplied `PSEUDO_SECRET` and a random backup ID. File names, sizes, hashes and backup dates remain visible in the manifest. Restrict access to backup directories and use durable encrypted storage with tested retention.

The snapshot includes configuration, in-volume source files, issuer keys/public-key history, status registry, audit and operational state. It excludes the writer lease, `secrets.json`, `.env` and `.env.*` files. Back up the existing deployment secrets independently; the tool never stores or prints them. The same `PSEUDO_SECRET` is required for restoration. If encrypted state exists, backup creation authenticates it first to catch a wrongly supplied secret. An empty issuer with no encrypted state has no independent secret verifier; obtain its original secret from the secret manager.

External PostgreSQL/MySQL/REST source data is **not** backed up by this tool. Use each source system's backup and recovery procedure. Local JSON/manual/CSV data must be inside `DATA_DIR`; the tool refuses a partial backup when the configured source is outside it. Upon restore, that source path is rebased to the new target directory. For a manual connector with no
explicit path, backup uses the same working-directory-relative `./data/manual_holders.json` default as
the running connector. It does not substitute the JSON connector's holder file. Also recover separately supplied certificate chains/private keys, reverse-proxy TLS configuration and deployment environment settings from their protected stores.

## Operator procedure

1. Stop the single issuer instance and prevent automatic restart for the maintenance window. The tool acquires the normal writer lease and refuses an active issuer. Do not manually remove a live lease. After a crash, allow its 30-second stale interval.
2. Make a **new, absent** backup destination under an existing directory. Supply `PSEUDO_SECRET` through the process environment from the secret manager; do not paste it into command-line arguments or shared logs.
3. Run the backup with explicit offline acknowledgement:

```sh
node scripts/backup-restore.mjs backup /app/data /backups/issuer-2026-09-17 --offline
```

4. Store the backup ID and secure retention location. The command reports excluded secret-file names, never their contents. Resume the original issuer only after backup completion if this was scheduled maintenance.
5. For disaster recovery, keep the original instance stopped and traffic disabled. Mount the selected backup and a **different, empty recovery volume**. Restore into an absent subdirectory of that volume:

```sh
node scripts/backup-restore.mjs restore /backups/issuer-2026-09-17 /recovery/data --offline
```

6. Keep the restored directory at that same path in the recovered container (`DATA_DIR=/recovery/data`), or explicitly validate and update the local source path before startup. Supply the original `PSEUDO_SECRET`, a recovered admin secret and the same issuer hostname. The restore tool does not start a process or switch traffic.
7. Inspect `recovery.json`, verify key/public-history continuity, revoked status responses, holder-source readability and fresh issuance. Confirm old tokens, offers and sessions are rejected. Reissue credentials and complete independent wallet acceptance before resuming traffic.

Both commands refuse existing destinations, nested source/destination directories, symlinks, corrupted files and altered manifests. A wrong secret fails before a restored directory is published. Incomplete work is staged under a unique sibling directory and removed on an ordinary error; a machine crash can leave that staging directory, which is not a published backup or restored `DATA_DIR`. The original data directory is never rewritten by restoration. Backup briefly adds/removes the lease while reading it.

### Docker execution

Run the CLI in a one-off container using the exact built application image, with the service stopped, its data volume mounted at its usual path, and separate backup/recovery mounts. The image must contain `scripts/backup-restore.mjs` as well as `dist/storage/recovery.js`; if the image does not include the script, invoke the exported functions from `dist/storage/recovery.js` using a separately reviewed operator command. Use container UID 1000 and ensure only the intended backup/recovery locations are writable. Never mount a production volume into the automated test fixtures.

This guide does not authorize Docker Desktop storage relocation, a deployment or a traffic switch. Filesystem-level proof below is distinct from proof of the deployment's Docker volume permissions, storage durability, certificate/secret recovery and wallet behavior.

## Repeatable proof

Run the isolated acceptance suite:

```sh
npx vitest run src/storage/__tests__/recovery.test.ts
```

On 2026-09-17, **8 tests passed** on Windows with fixtures under `D:/Mensch/VeriCred/.validation-artifacts/recovery-tests` and temporary files on D:. The suite:

- Backs up a synthetic issuer with rotated keys, holder data, signed status state and six authorization/session stores.
- Subsequently revokes a credential, consumes its pre-authorized code through the real HTTP token route, allocates an unseen status index and rolls over to an unseen list.
- Restores to a different directory and checks unchanged original data, identical private-key material, both public keys, correctly rebased holder data and normal writer-lease acquisition.
- Independently verifies/decompresses the signed restored status list: every bit is revoked, including the post-backup allocation. New issuance uses a new list ID; unseen later lists remain unknown.
- Calls the token and presentation-session routes to prove consumed codes and restored sessions cannot be reused.
- Rejects an active writer, wrong backup/restore secrets, modified manifest, corrupt ciphertext, existing/nested destinations and external local source files.

The tests use the real local cryptography, filesystem and HTTP routes with synthetic data. They do not establish external wallet acceptance, live database recovery, a Docker-volume restore, power-loss guarantees or a production disaster-recovery drill.
### Separate-volume Docker gate: PASS, 2026-09-19

`scripts/docker-smoke.mjs` now includes an isolated backup/restore gate in addition to restart and crash recovery. It creates three uniquely labelled volumes (source, encrypted backup, recovery) and initializes ownership with the application image. It seeds synthetic holder data while the issuer is stopped, then obtains all credentials and state transitions through HTTP with real proof signatures.

The gate stops the source before running the offline backup CLI, restarts it to revoke a credential and consume a pending grant after the snapshot, and issues another credential at a status index absent from the snapshot. It stops the source again, restores to `/recovery/data` in a different volume and starts exactly one recovered instance. It checks public-key continuity, rejected old admin/presentation sessions and grants/access tokens, independently verifies and GZIP-decompresses the signed old list (all bits revoked), and completes new issuance under a fresh list identity. Cleanup removes only containers and volumes whose labels match that run.

On 2026-09-19 the full gate passed against `vericred:acceptance-20260919-attestation`, image ID `sha256:334144803f53e8503ae181cf0b31de37e4cec495fb4318d44affc23759d1d6fd`. The process exited 0, including ownership-checked cleanup. Initial auto-removal cleanup races were fixed before this complete run. The separate-volume drill is now executed container recovery evidence, alongside the eight filesystem/HTTP tests and the Token Status List restoration case. It uses the custom profile and synthetic data; externally mounted certificates/secrets, external databases and independent wallet recovery still require their own operational drill.
### Manual-source recovery regression (2026-09-19)

The focused filesystem/HTTP recovery suite now passes 10 tests. Two additional isolated subprocess
cases prove that an omitted manual path preserves the manual registry after restoration, both when a
different JSON registry exists and when no JSON registry exists. They verify the restored connector
reads the manual holder and leaves the original source configuration unchanged.

The full custom-profile Docker runtime and separate-volume restoration drill was also rerun after
these fixes against `vericred:acceptance-20260919-review` (image ID `sha256:d6d9a4539dcb41b7824be5a75c3e4ad741b2d073a4c297b15731d3837c74e670`).
It passed with exit 0, including cleanup. This does not extend the drill to external certificates,
deployment secrets, customer databases or independent wallet recovery.

### Offline recovered-material check

Use [EUDI_MATERIAL_PREFLIGHT.md](EUDI_MATERIAL_PREFLIGHT.md) to inspect recovered EUDI configuration,
signing/registration files and attestation policy before startup. This command does not generate files
or access the network. A pass establishes local consistency only; secret continuity, backup provenance,
external database recovery and the actual recovery/reissuance drill still require independent evidence.

### EUDI separate-volume and synthetic material recovery: PASS, 2026-09-20

The [EUDI restoration acceptance harness](EUDI_RESTORE_ACCEPTANCE.md) now passes against
`vericred:acceptance-20260920-provisioning` (image ID
`sha256:cd2d5e8ce4ab02a5f7eab6b876bb880d145e05d5e78709304bbeca67f5f56380`).
It extends the earlier custom-profile Docker evidence to actual local TLS, encrypted EUDI issuance,
attested holder keys with a synthetic provider's live signed HTTPS status, and EUDI Token Status List
verification after restoring into a distinct Docker volume.

The drill separately encrypts/retrieves deployment material and secrets through a simulated AES-GCM
fixture store, mounts only the recovered material into the restored gateway, and runs the read-only
material preflight. It checks positive session/token baselines before backup, post-snapshot revocation
and issuance, then rejects old authorization before the token's natural expiry, retires every old
status bit and issues a fresh encrypted credential. Source and recovered instances never run together.
Ownership-checked cleanup passed; the redacted report is
`.validation-artifacts/eudi-restore-acceptance-result.json`.

The material store is test code with an in-memory recovery key, not a shipped production vault or a
durable key-recovery procedure. Real protected-store/certificate recovery, customer database recovery,
independent wallet behavior, public HTTPS and operator RPO/RTO remain separate open gates.

## Registrar dataset follow-up (2026-09-21)

The updated image `vericred:acceptance-20260921-registrar` passed the local Docker validation
recorded in [PRODUCTION_HANDOVER.md](PRODUCTION_HANDOVER.md). Required registration now includes
both role-specific registrar JSON files; see [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md).
The EUDI restoration drill includes these files in the separately recovered synthetic material store.
All prior independent-acceptance and production-secret-store limitations remain.
