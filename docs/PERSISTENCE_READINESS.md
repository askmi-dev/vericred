# Persistence verification and deployment boundary

This candidate composes #35's production/demo guard with #38's provenance
and offer-store integration (#36 + #37). Keep #31 open until Railway staging
has passed the deployment checks below. Green unit tests or an image build
alone do not establish deployed persistence.

## Implemented boundary

- One gateway process owns the file store. A nonblocking OS advisory lock
  (`fs-ext`/`flock`) on `offer-state.lock` excludes other writers. The lock
  inode is never removed; process death releases ownership without PID
  inspection, stale-file deletion or heartbeat timeouts. Old unlocked PID
  lock files are harmless. Do not delete a live lock file or mix old and new
  application versions on the volume.
- Writes use exclusive owner-only temporary files, file fsync, rename and
  directory fsync. Success is conditional on those operations succeeding.
  The filesystem must support these operations and local advisory locking;
  shared/network filesystems and multi-host operation are unsupported.
- Nonce consumption is persisted before status allocation/signing, with a
  comparison against the nonce verified by the request. A failed commit or
  concurrent stale proof returns no credential. A later signing/response
  failure can consume a nonce without delivering a credential; this is
  fail-closed, not exactly-once delivery or transparent retry recovery.
- `DATA_DIR` contains plaintext bearer credentials and holder data. Keep it
  private, outside static hosting/log export, with controlled backup access.
  The container entrypoint enforces directory mode 0700; offer snapshots
  use mode 0600. Whole-snapshot synchronous writes remain unsuitable for
  unbounded load; capacity/load limits remain separate work.
- Provenance append is still best-effort. A passing successful-path test
  does not mean every successful issuance has a durable provenance record.
- The demo guard recognizes exactly `NODE_ENV=production`. Missing/unknown
  environment values are not a validated deployment policy. Set
  `NODE_ENV=production`, `DEMO_MODE=false`, `OFFER_STORE=file`, and a stable
  `PROVENANCE_HASH_KEY` in staging and production.

## Repeatable gates

After installing dependencies and building the frontend:

```bash
npm run test:persistence
npm test
docker build -t vericred/gateway:test .
sudo "$(command -v node)" scripts/verify-persistence.mjs --image vericred/gateway:test
```

The native module requires a compiler/Python during installation (already
present in the Docker builder). The supported deployment target is Linux /
Node 22. The container gate is also wired into CI and runs the image's real
entrypoint as its normal non-root runtime user. Elevated harness access is
only for inspection/cleanup of disposable synthetic bind-mount data owned
by the container user. Never point it at an existing data directory.

`scripts/verify-persistence.mjs` creates its own temporary directory. It
asserts pending-offer recovery after SIGKILL, token recovery after another
kill, consumed-code replay rejection, exact approved claims despite a changed
source, holder binding/signature validity, provenance lookup time/hash/jti
joins, old-proof rejection after a further restart, nonce-write failure
without issuance, one successful request per concurrent nonce, three rounds
of competing writers and repeated demo/production startup refusal with exit
1, unavailable readiness endpoint and remediation diagnostics.

The original `provenance-restart-integration.test.ts` now inspects the disk
snapshot without an unlocked mutating store. It is component evidence only.
The lifecycle gate uses real child processes; container mode additionally
uses separate containers and their PID namespaces over a retained bind mount.

These gates do not simulate abrupt host power loss, storage rollback,
filesystem faults during every write instruction, or Railway's scheduler.
Passing them is not evidence for those failure models.

## Railway staging sign-off still required

1. Record the tested Git SHA/image and verify the actual service has exactly
   one gateway worker, a persistent volume mounted at effective `DATA_DIR`,
   private permissions and the production variables above. Do not infer a
   working mount from `railway.toml` alone.
2. With synthetic data, approve an offer, force a service restart, then redeem
   it through the new server. Restart after token redemption; reject the old
   code, issue with the saved token/proof, and compare approved claims plus
   the persisted provenance record. Restart after issuance and reject the old
   proof. Confirm the issuer key remained unchanged.
3. In an isolated staging service, verify the production/demo mismatch exits
   with code 1, readiness never succeeds, retries stop according to the
   configured policy and logs explain how to remove the misconfiguration.
   Do not disable the guard to restore availability.
4. Record readiness timings, restart events and results without bearer codes,
   access tokens, private keys or raw holder data. Attach that evidence to
   #31 before marking the persistence deployment ready.

Railway documents that volume-backed services cannot use replicas and that
deployments sharing a volume do not overlap:
https://docs.railway.com/volumes/reference . Horizontal/multi-process issuance
requires a transactional shared-store adapter and its own concurrency tests;
the file backend deliberately refuses a second writer.
