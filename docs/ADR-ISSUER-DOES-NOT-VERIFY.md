# ADR: Issuer does not verify presentations

Decision date: 2026-10-30

## Context
The issuer registered five public OID4VP endpoints unconditionally, despite its
issuer-only scope. They persist presentation data and share issuer configuration,
secrets and key-manager access. Security findings #46, #47 and #48 remain open.

## Decision
Disable registration and module import by default. Only the exact value
ENABLE_HOSTED_VERIFIER=true enables the legacy router. In production, also require
ENABLE_HOSTED_VERIFIER_CONFIRM=yes or abort startup before listening.
Keep the code and direct router tests. Do not fix or extract the verifier here.

## Consequences
OID4VCI is unchanged. Legacy verifier clients receive 404 while disabled.
External clients and deployed traffic have not been inspected. Before deployment,
the operator must review hosting logs for genuine /api/oid4vp/* usage.
The old DATA_DIR/oid4vp_sessions.json is neither read by the disabled verifier nor
deleted. It can contain claims and raw vpToken disclosures. The operator must
assess retention and remove residual deployment data after the rollout; backups
and old replicas require separate consideration. This PR does not perform deletion.

The response handler actually calls getAllPublicKeys(), which reads key files
containing private and public fields but returns public keys for verification.
Session encryption calls loadSecrets() and derives a key from pseudonymSecret.
This establishes coupling, not a demonstrated private-key exfiltration exploit.

## Future hosted verifier
A separate self-hosted SDK/service may be considered after role separation and
security remediation. The production confirmation variable is only an operational
interlock: it does not repair unsafe verification, session exposure or proxy trust.
Before any re-enable, resolve and independently review the security backlog and
run negative verification/privacy tests. SDK extraction is a separate change.

Backlog: #52 (re-enable gate), #53 (issuer-key/secret coupling), #54 (retention).
