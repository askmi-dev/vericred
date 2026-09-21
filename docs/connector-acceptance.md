# Live SQL connector acceptance

From the repository root, with Node 22, locked root dependencies installed (`npm ci`), and an already running Docker daemon configured for Linux containers:

```sh
node scripts/connector-acceptance.mjs
```

The supervisor starts disposable `postgres:16-alpine` and `mysql:8.4` containers. It loads the repository's TypeScript connector code in child processes using the installed `tsx` loader; no backend or frontend build is required. The image tags select the acceptance versions, not a claim about the latest versions. Each run prints the actual image ID for evidence.

## Isolation and resource use

- Every container gets a random name and a run-specific ownership label. Cleanup checks this label before stopping/removing a container.
- Both databases use tmpfs storage, with limits of 256 MiB for PostgreSQL and 1 GiB for MySQL. No existing data volume or host directory is mounted, and no persistent database volume is created.
- Published database ports bind only to `127.0.0.1`, using random host ports. Database passwords and the fixture pseudonym secret are generated per run. Secrets are passed through child-process environment or IPC, not shell interpolation or command arguments, and diagnostics redact them.
- The script accepts no external connection strings and cannot accidentally select a production source from local configuration. It does not start Docker Desktop, relocate storage, or prune Docker resources.
- Missing images may be downloaded by Docker and retained in its image cache. Ensure the Docker host has enough free storage and memory before running. The databases run sequentially.
- Child-process crashes still return control to the supervisor for cleanup. A forced kill of the supervisor/host can interrupt cleanup; inspect any remaining `vericred-connector-<run-id>-*` containers and their `com.vericred.connector-acceptance` label before removing that run's containers. Never use a broad prune to clean up this test.

## Assertions

For each actual database engine, the harness checks:

1. Source health and schema discovery.
2. Lookup by configured `email` when the source has a separate `id` column. The original `id` stays unchanged and `_lookupIdentifier` round-trips a listed record back into lookup.
3. SQL `DATE` values remain exactly `YYYY-MM-DD` with the Node process in `Pacific/Kiritimati` (UTC+14). January 1 and leap-day fixtures expose date-to-timestamp timezone drift.
4. Listing, pagination, and empty pages.
5. A nonexistent holder returns `null` while the service is healthy.
6. After the disposable database is stopped, health, lookup, and listing reject; outages must not become “holder not found” or empty results. Unhandled pool errors fail the worker and the supervisor still cleans up.

The harness uses synthetic records only. It does not establish acceptance for a customer's schema, TLS settings, database permissions, performance, or backups. It does not exercise wallet issuance or presentation. Record those separately against the deployment source and pinned wallet profile.

## Current evidence

On 2026-09-18, both live database engines passed all assertions on Docker Desktop after the authorized storage relocation to D:. The harness exited successfully and removed its generated containers. These are actual driver/database results with synthetic fixtures; customer source/schema/TLS acceptance remains separate.

- PostgreSQL 16 Alpine image: `sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`.
- MySQL 8.4 image: `sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a`.
- Passed health, schema, DATE preservation, separate ID/lookup identifier, listing, missing record and real service-outage handling.