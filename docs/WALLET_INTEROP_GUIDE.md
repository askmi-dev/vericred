# Wallet Interop Test Guide

## Goal

Issue an AgeCredential to a real wallet using the pre-authorized code flow.
Document the result in `docs/WALLET_INTEROP_LOG.md`.

---

## Step 0: Choose your wallet

Start with **one** wallet. Don\'t test multiple wallets simultaneously — interop failures
are hard to isolate when you\'re debugging two stacks at once.

| Wallet | Install | Notes |
|---|---|---|
| [walt.id Wallet](https://walt.id/wallet) | iOS / Android / Web | Strong OID4VCI support; good first target |
| [Sphereon Wallet](https://www.sphereon.com/sphereon-wallet/) | iOS / Android | SD-JWT-VC focused |
| [EUDI Wallet Reference](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) | Android (sideload) | Most strict; use after first success |

---

## Step 1: Expose VeriCred to the wallet

Wallets run on mobile and need to reach your issuer over HTTPS or at least HTTP.

**Option A — ngrok (easiest):**
```bash
ngrok http 3100
# Note the https://xxxxx.ngrok-free.app URL
```

Update `vericred.config.json`:
```json
{
  "issuer": {
    "url": "https://xxxxx.ngrok-free.app",
    "did": "did:web:xxxxx.ngrok-free.app"
  }
}
```

Restart VeriCred after changing the config.

**Option B — local network (same WiFi):**
```bash
# Find your local IP
ipconfig   # Windows
```
Use `http://192.168.x.x:3100` — wallet and computer must be on the same network.
Note: Some wallets require HTTPS even on local network.

---

## Step 2: Start VeriCred

```bash
DEMO_MODE=true npm run dev
```

With `DEMO_MODE=true`, synthetic holders (with `dateOfBirth`) are auto-generated.
Open `http://localhost:3100/admin` to see them.

Verify metadata loads:
```bash
curl http://localhost:3100/.well-known/openid-credential-issuer | python -m json.tool
```

Check for:
- `credential_configurations_supported.AgeCredential.format` = `"dc+sd-jwt"`
- `proof_types_supported.jwt.proof_signing_alg_values_supported` = `["ES256"]`
- `credential_endpoint` pointing to your public URL

---

## Step 3: Generate a credential offer

```bash
curl -X POST http://localhost:3100/offer \
  -H "Authorization: Bearer <your-admin-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "<holder-email>"}'
```

Or use the Admin UI: open `/admin`, click a holder, click "Offer".

The response contains:
```json
{
  "offer": { ... },
  "offer_uri": "openid-credential-offer://?credential_offer=..."
}
```

**Show as QR code** (quick option):
```bash
# Install qrencode if needed
echo "openid-credential-offer://..." | qrencode -o offer.png && open offer.png
```

Or paste the `offer_uri` into [https://qr.io](https://qr.io) for a quick QR.

---

## Step 4: Wallet scans offer

Point the wallet at the QR code or paste the `openid-credential-offer://` URI.

What the wallet does automatically:
1. Fetches `/.well-known/openid-credential-issuer`
2. Calls `POST /token` with `pre-authorized_code`
3. Receives `access_token` + `c_nonce`
4. Builds a holder proof JWT (signed with wallet key)
5. Calls `POST /credentials` with `Authorization: Bearer <access_token>` and `proof`

Watch the VeriCred server logs. You should see:
```
[issuer] Issued AgeCredential urn:uuid:... bound=<thumbprint>... status=0
```

---

## Step 5: Inspect the issued credential

The wallet receives a `credential` in Combined Format:
```
<jwt>~<disclosure1>~<disclosure2>~<disclosure3>~
```

Decode the JWT part (first segment before `~`) at [jwt.io](https://jwt.io).

Expected payload:
```json
{
  "vct": "AgeCredential",
  "iss": "did:web:...",
  "sub": "did:askmi:pairwise:...",
  "cnf": { "jkt": "<holder-key-thumbprint>" },
  "_sd_alg": "sha-256",
  "_sd": ["hash1", "hash2", "hash3"],
  "credentialStatus": { ... }
}
```

**No raw claim values should appear in the JWT payload.**

Decode a disclosure (base64url decode any segment after `~`):
```
["<salt>", "age_over_18", true]
```

---

## Step 6: Known failure modes and fixes

| Failure | Likely cause | Fix |
|---|---|---|
| Wallet can\'t fetch metadata | Issuer URL not reachable | Use ngrok; check `issuer.url` in config |
| `format` not recognized | Wallet expects `vc+sd-jwt` | Change `format: 'vc+sd-jwt'` in metadata.ts |
| Token endpoint 400 | Wallet sends wrong `grant_type` | Check wallet logs; grant type must be `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| `/credentials` 400 `holder_binding_required` | Wallet not sending proof | Check wallet proof settings; or set `DEMO_MODE=true` temporarily |
| `/credentials` 400 `invalid_proof` | Wrong `aud`, wrong `typ`, stale `iat`, bad nonce | Decode wallet\'s proof JWT at jwt.io; compare to expected values |
| `/credentials` 400 `invalid_nonce` | Nonce mismatch | Check c_nonce in token response vs proof nonce |
| Wallet can\'t parse credential | `_sd_disclosures` vs `_sd` | Already fixed — check you\'re running latest version |
| Wallet shows no claims | Wallet not parsing Combined Format | Check wallet SD-JWT-VC support level |

---

## Step 7: Log the result

Fill in `docs/WALLET_INTEROP_LOG.md` with the test entry template.

Include:
- Exact wallet version
- VeriCred git hash (`git rev-parse --short HEAD`)
- Which steps passed, which failed
- Relevant server log lines
- What you changed (if anything) to make it work
