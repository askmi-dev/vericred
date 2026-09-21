# VeriCred

A self-hosted credential issuer and verifier with an Express/TypeScript backend and an Astro admin console.

**Status: release candidate; independent EUDI reference-wallet and miTch acceptance remain open.** Credentials use custom VeriCred profiles, not EUDI PID or qualified attestations.

- [Current handover and remaining work](docs/PRODUCTION_HANDOVER.md)
- [Docker deployment and persistence checks](docs/docker.md)
- [Wallet contract and acceptance procedure](docs/WALLET_INTEROP_GUIDE.md)

## Development

Use Node.js 22.12 or newer. CI and Docker use Node 22.

```sh
npm ci
npm --prefix stitch-out ci
npm run build
npm test
npm run dev
```

Build before tests: HTTP integration checks serve generated frontend files. Tests use temporary storage and synthetic secrets.

Production requires one process, persistent storage, stable independent secrets and an externally reachable HTTPS issuer origin. See the Docker guide.

Historical demo documents and the supplied Übergabe.md contain earlier claims and proposals; use the current handover for implementation status.

## Local operator walkthrough

Run `npm run build`, then `npm run walkthrough` and open http://127.0.0.1:3310/admin/login. The launcher creates a separate persistent synthetic fixture and tells you where its local admin key is stored. In a second terminal run `npm run walkthrough:flow` to exercise issuance, selective presentation, replay rejection, revocation and replacement issuance.

See [the local walkthrough](docs/LOCAL_WALKTHROUGH.md), [real Android wallet guide](docs/LIVE_WALLET_WALKTHROUGH.md) and [current implementation evidence](docs/PRODUCTION_HANDOVER.md). Local simulations do not establish independent wallet acceptance.
