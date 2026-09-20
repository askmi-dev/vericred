# Isolated Caddy and local HTTPS acceptance

Run from the repository root with Docker Desktop available and the reviewed application image built:

```sh
node scripts/caddy-acceptance.mjs vericred:acceptance-20260920-provisioning
```

The host harness requires the installed project dependencies and OpenSSL (`OPENSSL_BIN` may select
its executable). It uses `caddy:2.11.4-alpine`, pulling that image if it is absent. Image identities
are recorded in the successful result. This is a disposable local test, not a deployment.

## Isolation and checks

- Creates new, labelled Docker networks and test containers: an internal backend network and a
  separate proxy network. Only the proxy publishes ports,
  bound to `127.0.0.1` with automatically assigned ports. Port 3310 and existing volumes remain untouched.
- Creates fresh synthetic issuer, verifier, registration, attestation-policy and TLS material under a
  unique `.validation-artifacts/caddy-test-*` directory. It does not read project `.env` or real keys.
- Copies `deploy/Caddyfile.acceptance`, preserving its reverse-proxy directives. The copy adds explicit
  fixture TLS files and disables Caddy's admin listener. It does not request public certificates or
  install a CA into the operating system's trust store.
- Uses a temporary upstream probe to verify removal/replacement of `Forwarded` and `X-Forwarded-*`
  headers and rejection of an unrelated Host. Then it replaces that probe with the actual EUDI gateway,
  trusting only the test proxy's exact container address. The prepared deployment uses a fixed proxy IP;
  this isolated test uses the address assigned in its new network.
- Checks trusted and untrusted local TLS, HTTP-to-HTTPS redirection, pinned signed metadata and JSON
  agreement, required encryption/attestation advertisements, admin authentication/cookie flags,
  observational readiness and rejection of login-limit bypass using forged forwarding addresses.
- Removes only containers and networks carrying the current run's ownership label. Successful
  evidence is written after cleanup; failed cleanup makes the command fail.

The test temporarily replaces the upstream and creates an admin session/public nonce in its own
fixture. Failed-login checks intentionally exhaust that fixture's login limit. Synthetic private
material remains under the ignored artifact directory for local inspection; do not publish the
fixture directory. The result JSON contains no private key, admin key, registration JWT or bearer token.

## Evidence boundaries

A successful result is **actual local Caddy/TLS/container evidence with synthetic EUDI material**.
It is not independent wallet acceptance, registration-policy ON acceptance, real provider onboarding,
public certificate issuance, public DNS/phone reachability, a live customer database test or a new
Docker-volume restoration drill. Gateway registration `required` only establishes local transport
requirements; it does not operate the reference wallet's registration switch.

Docker maps random host ports to the proxy's normal HTTP/HTTPS ports for this fixture. The redirect
check verifies scheme, host, path and query; it does not prove a publicly deployed port mapping.
No credential is issued to a wallet by this harness. Continue with
[LIVE_WALLET_WALKTHROUGH.md](LIVE_WALLET_WALKTHROUGH.md) only after the external material, hostname and
explicit deployment authorization are available.

Caddy's documented proxy defaults ignore untrusted incoming forwarded values:
[reverse_proxy defaults](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#defaults).
The runtime checks observe that behavior for the pinned test image.

## Recorded local run

PASS on 2026-09-20 against `vericred:acceptance-20260920-provisioning` and Caddy 2.11.4 Alpine.
The final run completed every check and ownership-checked cleanup. The first fixture attempt could
not expose its host port on an internal-only network; the tested topology uses a separate proxy
network plus the internal backend. No prepared deployment file was changed.

Redacted result: `.validation-artifacts/caddy-acceptance-result.json`. The existing 382-test source
suite/build evidence was not rerun for these host-side harness/documentation additions.

## Registrar dataset follow-up (2026-09-21)

The updated image `vericred:acceptance-20260921-registrar` passed the local Docker validation
recorded in [PRODUCTION_HANDOVER.md](PRODUCTION_HANDOVER.md). Required registration now includes
both role-specific registrar JSON files; see [REGISTRAR_DATASETS.md](REGISTRAR_DATASETS.md).
The EUDI restoration drill includes these files in the separately recovered synthetic material store.
All prior independent-acceptance and production-secret-store limitations remain.
