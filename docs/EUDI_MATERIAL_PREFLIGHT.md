# Offline EUDI material preflight

This read-only command checks the existing issuer configuration and locally supplied signing,
registration and wallet-attestation material before an EUDI start, or after material has been
recovered separately. It does not start VeriCred, create keys/configuration, read holder records,
connect to a database, fetch status or contact a trust service.

## Run locally

Build the backend, supply the deployment's environment from its protected store, then run:

```sh
npm run build:backend
node scripts/eudi-material-preflight.mjs --offline
```

The command does not load `.env` or fall back to generated secrets. Required inputs:

| Environment setting | Required value |
| --- | --- |
| `DATA_DIR` | Absolute path to existing data with `vericred.config.json` and `issuer-key.json` |
| `WALLET_PROFILE` | `eudi-android` |
| `EUDI_REGISTRATION_POLICY` | `required` |
| `ADMIN_API_KEY`, `PSEUDO_SECRET` | Deployment secrets, at least 32 characters each |
| `EUDI_ISSUER_CERT_CHAIN_PATH` | Issuer signing certificate chain matching the retained issuer key |
| `EUDI_VERIFIER_CERT_CHAIN_PATH`, `EUDI_VERIFIER_KEY_PATH` | Verifier signing chain and matching private key |
| `EUDI_ISSUER_REGISTRATION_CERT_PATH`, `EUDI_VERIFIER_REGISTRATION_CERT_PATH` | Registrar-issued compact JWT files |
| `EUDI_ISSUER_REGISTRAR_DATASET_PATH`, `EUDI_VERIFIER_REGISTRAR_DATASET_PATH` | Separate registrar JSON objects; see [supported shape](REGISTRAR_DATASETS.md) |
| `EUDI_WALLET_ATTESTATION_POLICY_PATH` | Reviewed provider/status signer policy JSON |

`ISSUER_URL`, when supplied, overrides the persisted origin just as at runtime. An HTTPS issuer
origin and a valid active credential configuration are required. The command produces a redacted
JSON report, with exit **0** for local `PASS`, **1** for `BLOCKED` or failure, and **2** for incorrect
CLI arguments. It does not print private keys, registration JWTs, secret values, material paths or
provider pins. Certificate expiry dates are public metadata included in the underlying Admin checks.

A pass validates local chain/key consistency, registration transport integrity and attestation-policy
shape. A local signing challenge checks that the private key can sign for the certified public key.
The issuer's stored public key and key ID are checked as well. Admin readiness uses those same checks.

## After recovery

Keep the old instance stopped and traffic disabled. Restore application data using
[BACKUP_RESTORE.md](BACKUP_RESTORE.md), recover external certificate/policy files and deployment secrets
from their protected stores, and run this preflight against those recovered paths. Mount data and
material read-only for the check. The current runtime image includes the command; with the deployment
settings supplied, a one-off container can run `node scripts/eudi-material-preflight.mjs --offline`
with `--network none`, no published ports, and read-only data/material mounts. It does not need the
application running. Do not use a backup directory in place of the restored DATA_DIR.

**This is a consistency check, not restoration acceptance.** Secret presence/length cannot prove
entropy, that the recovered PSEUDO_SECRET is the original, or that it decrypts historical state.
The command does not verify external backup provenance, signing-key history, customer database
recovery, cache expiry, RPO/RTO, or successful reissuance. Complete the separate recovery drill.

A local `PASS` always retains `releaseAccepted=false`; independent wallet, registration-policy ON,
provider trust, public HTTPS, live source and external-material recovery acceptance remain `NOT RUN`.
Provider onboarding, assurance/certification/status agreement and custom VCT/schema approval remain
external requirements. No test material is an approved production trust anchor.
