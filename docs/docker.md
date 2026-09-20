# Docker deployment and acceptance

VeriCred supports **one Node process per persistent data volume**. A filesystem lease rejects a second writer. This is a single-instance deployment, not a replicated database architecture.

## Build and run

Use Docker Engine/Desktop with Linux containers and Docker Compose v2. Set these values in your secret manager or a local, gitignored `.env` file:

```dotenv
ISSUER_URL=https://credentials.example.org
ADMIN_API_KEY=<persistent random secret, at least 32 bytes>
PSEUDO_SECRET=<different persistent random secret, at least 32 bytes>
```

Generate each secret independently using a cryptographically secure generator. Keep `PSEUDO_SECRET` stable: it protects durable encrypted state and derives holder pseudonyms. Store it separately from the data-volume backup; losing it makes encrypted state unreadable. Do not include real values in tickets, build arguments or images.

```sh
docker compose build
docker compose up -d
docker compose ps
```

The service listens on `127.0.0.1:3100` on the Docker host. Put an HTTPS reverse proxy on that host and forward the configured public hostname to this address. The wallet must reach the public `ISSUER_URL`; loopback addresses do not work from a phone. VeriCred derives protocol URLs from configuration, not caller-supplied forwarded headers. Production admin cookies require HTTPS.

Compose runs the image as its unprivileged `node` user, drops Linux capabilities, applies a read-only root filesystem, and gives the process a writable `/tmp` and `/app/data`. A Docker-managed named volume initializes `/app/data` ownership from the image. Existing bind mounts need write permission for container UID/GID 1000; validate permissions on a copied test volume before adopting existing data.

## Persistence and lifecycle

The `issuer-data` volume contains issuer keys/public-key history, configuration, status lists, holder data when applicable, audit records, encrypted authorization state, admin sessions and presentation sessions. PostgreSQL/MySQL connectors are source adapters; these operational files remain on the volume.

- Use `docker compose stop` / `docker compose start` for ordinary restarts.
- `docker compose down` removes containers while retaining the named volume. Keep the same Compose project name and volume when recreating the service.
- Do not use `docker compose down --volumes` against data that must be retained.
- Do not scale above one replica against the same volume. The writer lease fails startup for competing processes.
- An abrupt crash can leave a lease for up to 30 seconds. Allow that recovery interval before retrying. Do not remove a lease while another process may still hold the volume.
- The image health check queries `/health`. It proves process responsiveness; it does not certify a live external connector or wallet compatibility. A Docker health failure alone does not restart a running process; monitor health and investigate it.

For backups, stop the service and take a consistent snapshot of the entire named volume using your Docker/storage provider. Back up deployment secrets separately. Use the authenticated offline tool described in [BACKUP_RESTORE.md](BACKUP_RESTORE.md) to restore into a new isolated volume with the same issuer hostname and separately recovered secrets. Recovery deliberately retires every old status list and discards sessions/grants; holders must receive new credentials. Verify that old credentials and authorization state remain rejected before switching traffic. Encrypt and access-control backups: the active issuer key is stored as a private JWK in a mode-0600 file. A KMS/HSM is still a separate production integration decision.

## Reproducible container smoke test

After building an image, run:

```sh
node scripts/docker-smoke.mjs vericred:local
```

The script creates randomly named, labelled containers and three disposable volumes for source data, encrypted backup and restoration. It checks non-root execution, built landing-page serving, protected admin routes, production development-route exclusion, encrypted session and token continuity, key rotation/history across restart, rejection of a second writer, and replacement-container recovery after an abrupt stop. It also backs up the stopped issuer, changes source state through HTTP, restores the older snapshot into a separate volume, and checks revoked old status lists, rejected authorization and fresh issuance. See [the recovery policy and evidence](BACKUP_RESTORE.md). Only synthetic holder data is used. Cleanup targets only resources bearing that run's label; existing application volumes are never mounted.

The script does not publish an image or deploy a service. It does not contact an EUDI wallet or prove protocol certification. CI first audits both dependency trees and builds static pages, then runs isolated regression tests, builds a local image, and executes this smoke test.

## Release gates

The current credential types are custom VeriCred SD-JWT test profiles, not EUDI PID or qualified attestations. Pin the EUDI reference-wallet application/library version and the credential type/trust profile. Record a real-device issuance, selective presentation and revocation result over HTTPS. Exercise the miTch adapter against the same cryptographic invariants. Confirm the external connector, reverse proxy, secret recovery and backup restoration in the deployment environment before release.

Docker reference: [named-volume lifecycle and initialization](https://docs.docker.com/engine/storage/volumes/), [Compose service settings](https://docs.docker.com/reference/compose-file/services/).

## Local acceptance blocker and inspected relocation (2026-09-16)

The local image build installed the locked dependencies, then BuildKit failed to commit its metadata because Docker storage became read-only. C: had run out of space. No smoke containers or volumes were created; Docker acceptance has not passed.

Read-only inspection found Docker Desktop 4.66.0.222299, using:
- Data VHDX: C:\Users\Admin\AppData\Local\Docker\wsl\disk\docker_data.vhdx (10,497,294,336 bytes, about 9.78 GiB).
- Boot VHDX: C:\Users\Admin\AppData\Local\Docker\wsl\main\ext4.vhdx (104 MiB).
- D: is NTFS with about 595 GB free; D:\DockerDesktopData does not exist.
- Docker processes and both WSL distributions were stopped at inspection. There is no docker-desktop-data distribution.

At that inspection, authorization covered inspection only. On 2026-09-18 the user explicitly authorized relocation; the completed move is recorded below.

Original migration procedure:
1. While Docker is stopped, back up the data VHDX and Docker settings to a separate D: backup directory; verify file size and SHA-256.
2. Use Docker Desktop > Settings > Resources > Advanced > Disk image location to select D:\DockerDesktopData. Record the destination chosen by Desktop.
3. Restart and verify engine health, image/volume inventory, writable storage and recovered C: space.
4. Rebuild VeriCred and run scripts/docker-smoke.mjs; retain the backup until successful.
5. If recovery is needed, restore only while Docker is stopped and the chosen destination has sufficient free space.

C: may first need limited cleanup to let Desktop write settings/logs. Select any cleanup explicitly; do not prune unrelated Docker data or use old export/unregister instructions for a nonexistent docker-desktop-data distribution.

Official guidance: [WSL storage location](https://docs.docker.com/desktop/features/wsl/#turn-on-docker-desktop-wsl-2) and [back up Docker Desktop](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/).

## Authorized relocation completed, 2026-09-18

Docker Desktop now reports `D:\DockerDesktopData` as its WSL data directory. The Linux engine reports version 29.3.0. Docker performed the relocation through the same local settings API used by its installed UI; direct disk/settings edits, WSL unregister and broad pruning were not used.

Before the change, Docker was stopped and both data and boot VHDX files plus settings were copied to `D:\DockerDesktopBackup\20260917-vericred-migration`. SHA-256 checks matched both originals; the manifest is `verified-backup.json`. Retain this rollback backup. The migration preserved all 4 existing miTch containers and all 7 prior image IDs; the pre-move inventory contained no named volumes. Existing miTch containers remained stopped.

After migration C: had about 10.24 GiB free and D: about 535.42 GiB (before subsequent build caches). Live PostgreSQL/MySQL acceptance passed. The approved move does not authorize a public VeriCred deployment.

## Current container acceptance

On 2026-09-19, `node scripts/docker-smoke.mjs vericred:acceptance-20260919-attestation` exited 0, including cleanup. Image ID: `sha256:334144803f53e8503ae181cf0b31de37e4cec495fb4318d44affc23759d1d6fd`. Startup, protected routes, non-root execution, persistence, crash recovery, single-writer exclusion and encrypted restoration into a distinct volume passed. This is isolated custom-profile container evidence, not public Caddy/HTTPS or independent wallet acceptance.
