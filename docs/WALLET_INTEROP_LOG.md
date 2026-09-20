# Wallet acceptance record

Independent Android, iOS and miTch execution: **NOT RUN**.

Attested-key issuance is implemented and tested with synthetic provider/status certificates.
Actual provider policy material and independent Android acceptance remain **NOT RUN**.
[Attestation implementation and trust boundaries](WALLET_ATTESTATION.md).
Registration ON trust/status/binding/scope remains unverified.

| Field | Current evidence, 2026-09-19 |
| --- | --- |
| Proposed first wallet | Android 2026.08.41-Demo build41, app50828c2, core0.30.2; installed binary digest not yet recorded |
| Second platforms | iOS and miTch; exact builds and runs pending |
| Public issuer/image digest | Not deployed |
| Credential/trust/status | Custom VCT proposal and implemented EUDI transport/status profile; ecosystem agreement and certificates pending |
| Automated protocol | 7 synthetic-certificate tests, 49 wallet-attestation tests and 19 registration-integrity tests passed, including encrypted issuance/presentation, revocation and Token Status List recovery |
| HTTPS preflight | 2 metadata TLS tests and 2 attestation-status TLS tests passed; public endpoint not tested |
| Backup/restoration | 8 filesystem/HTTP/crypto tests plus Token Status List recovery passed; separate-volume Docker drill passed, including cleanup |
| Live connectors | Actual PostgreSQL 16 Alpine and MySQL 8.4 passed, including service-outage checks; hosted CI remains unrun |
| Local app/browser | Synthetic HTTP flow and actual desktop/mobile Edge browser checks passed; no independent wallet claim |
| Independent issuance/presentation/revocation | Not run |

Follow [the contract and acceptance gates](EUDI_ACCEPTANCE_CONTRACT.md).
Record PASS/FAIL/BLOCKED with redacted evidence per actual wallet run.
Custom simulations and synthetic-certificate tests cannot change the independent acceptance status.
