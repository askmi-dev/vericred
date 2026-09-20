# Local app walkthrough

The isolated app is available at **http://127.0.0.1:3310/admin/login** while `npm run walkthrough` is running. This uses synthetic people and a custom protocol profile over local HTTP. It is not independent EUDI or miTch wallet acceptance.

## Start and sign in

From the repository root:

```powershell
npm run build
npm run walkthrough
```

The launcher creates a dedicated, gitignored fixture under `.validation-artifacts/local-walkthrough/`. It binds only to `127.0.0.1:3310` and does not load the repository's `.env` or use existing issuer data. Repeated starts retain its own keys, holders, mappings and credential history. It refuses an unrecognized non-empty fixture or an occupied port.

1. Open the local login URL.
2. Open `.validation-artifacts/local-walkthrough/secrets.json` locally and use its `adminApiKey` value in the login form. Do not share or commit this file. The launcher does not print the key.
3. Start on **Gateway overview**. The runtime information comes from authenticated checks. Local HTTP and unverified independent acceptance remain visible.
4. Open **Wallet walkthrough**. Choose a synthetic holder, review the mapping, create an offer, then create a presentation request. QR creation alone does not prove that a wallet accepted anything.

The two sample people are `walkthrough-adult` and `walkthrough-young`. Age, employee and membership mappings are preconfigured. Age claims are derived from date of birth; the date of birth is not included in the credential. Names, emails and date of birth remain masked in the admin response.

## Exercise the actual HTTP flow automatically

Leave the app running and open another terminal:

```powershell
npm run walkthrough:flow
```

This local synthetic wallet client:

1. Reads the isolated JSON source through the admin API.
2. Creates an offer and redeems a one-use grant.
3. Creates its own P-256 holder key and signs the proof.
4. Obtains and verifies a signed, holder-bound AgeCredential.
5. Presents only `age_over_18`, with nonce, audience and disclosure hash binding.
6. Checks denial of grant/proof/presentation replay and unauthenticated session reads.
7. Revokes the credential through the admin API, verifies the signed status bitmap, and confirms a fresh presentation is rejected.
8. Issues and presents a replacement credential, leaving an active record alongside the revoked one.

Refresh **Gateway overview** or **Wallet walkthrough → Inspect issuance and revocation** to see the resulting records. Use **Inspect** to see type, expiry and status index. Presentation results obtained by a separate wallet client are protected by that client's read token; the page displays results for requests created in that page.

A redacted result is written to `.validation-artifacts/local-walkthrough/flow-result.json`. It contains step outcomes and selected claims, never raw credentials, grants, proof JWTs, read tokens or secrets. Each successful repeat creates another revoked and replacement credential in this isolated fixture.

## Use a real phone wallet

A phone's localhost addresses the phone, not this PC. This local preview does not provide the public HTTPS and EUDI trust registration a real device run requires. Follow [LIVE_WALLET_WALKTHROUGH.md](LIVE_WALLET_WALKTHROUGH.md) for the exact Android app, test onboarding, certificate/schema agreement, QR flow and evidence requirements. Repeat separately on iOS and miTch.

## Stop and retain state

Stop the foreground `npm run walkthrough` process with Ctrl+C. On Windows a forced process termination can leave the normal writer lease for 30 seconds; wait before restarting. Do not remove a live lease or start two writers against the same fixture. No production service, Docker deployment or external endpoint is started by this launcher.
