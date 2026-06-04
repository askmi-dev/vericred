# Wallet Interop Test Log

Each test run gets its own dated entry. The goal is to isolate failures precisely,
not to log "it didn't work." Fill in every field — vague notes compound into wasted hours.

---

## Test Entry Template

```
## [YYYY-MM-DD] — <Wallet Name> <Version> — <PASS / FAIL / PARTIAL>

### Configuration
- Wallet: 
- Wallet version: 
- VeriCred version (git hash): 
- Credential type: AgeCredential
- Format identifier sent in metadata: dc+sd-jwt
- Issuer URL: http://localhost:3100 (or ngrok URL)
- DEMO_MODE: true / false

### Flow result

| Step | Result | Notes |
|---|---|---|
| 1. Server starts, metadata loads | ✅ / ❌ | |
| 2. Offer generated via /offer | ✅ / ❌ | |
| 3. Wallet reads offer URI | ✅ / ❌ | |
| 4. Wallet fetches /.well-known/openid-credential-issuer | ✅ / ❌ | |
| 5. Wallet calls /token (pre-authorized_code) | ✅ / ❌ | |
| 6. Wallet sends /credentials with proof JWT | ✅ / ❌ | |
| 7. VeriCred returns Combined Format credential | ✅ / ❌ | |
| 8. Wallet stores and displays credential | ✅ / ❌ | |

### Observed failures

**Metadata:**

**Proof JWT (from wallet logs or network tab):**

**Nonce / c_nonce:**

**Credential format / parsing:**

**Error responses received:**

### VeriCred server logs (relevant lines)

\`\`\`
paste here
\`\`\`

### Fix applied (if any)

### Next action
```

---

## Test Log

*(no entries yet — add first entry after real wallet test)*
