# STATE.md — Current Operating State

> Health snapshot in the style of the miTch repo. For phase task-tracking see `task.md`; for architecture rationale see `implementation_plan_v2.md`. Update this file on every merged phase.

**Date:** 2026-10-10
**Branch:** `main`
**Version:** 0.1.0 (pre-release)
**Deployment reference:** Railway (`railway.toml`, see `docs/RAILWAY_DEPLOY.md`); Docker image build verified in CI.

## Canonical references

| Topic | Authority |
|---|---|
| Agent/session rules, security non-negotiables | `AGENTS.md` |
| Phase checklist | `task.md` |
| Architecture decisions | `implementation_plan_v2.md` |
| Deployment | `docs/RAILWAY_DEPLOY.md` |
| Security policy, key handling | `SECURITY.md` |
| Project scope, quickstart | `README.md` |

## Operational health

- **CI:** `.github/workflows/ci.yml` — `npm ci` (root + stitch-out), production build, full test suite, Docker dry-run build. `npm audit` runs non-blocking (informational).
- **Tests:** 151 backend tests incl. auth-bypass regression, CSRF fail-closed, PII masking, EUDI interop suite (signature verification, disclosure hashes, key binding). Regression-critical per AGENTS.md.
- **CodeQL:** security scanning via GitHub CodeQL default setup ("CodeQL - Code Quality" workflow; repo Settings → Code security). Default setup and an advanced CodeQL workflow cannot both upload analyses, so no `codeql.yml` workflow is defined.
- **Branch protection:** PRs required before merge to `main`, up-to-date requirement enabled (owner setting, 2026-10-10).

## Compliance & claims posture

- **Claims doctrine:** no conformance, certification, "production-ready" or eIDAS/LoA claims without linked evidence (workspace `START_HERE.md` doctrine, referenced in `AGENTS.md`).
- **Key management:** issuer keys are software-held in config files (rotatable). Dev/demo grade only. KMS/HSM adapter tracked in issue #19. SECURITY.md documents rotation and compromise procedures.

## Known gaps

- #19 — pluggable KMS/HSM key provider (blocker for any high-assurance/SaaS path)
- #20 — root-level legacy artifacts (`app.js`, `index.html`, `index.css`) unreferenced by the server; on hold by owner decision, no deletion
- #21 — Phase 6: packaging (docker-compose), pilot schemas, E2E interop demo with miTch
- #18 — fail-closed golden test (stretch item, open)