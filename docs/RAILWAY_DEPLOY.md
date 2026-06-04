# VeriCred — Railway Deployment Guide

## Prerequisites

- [Railway account](https://railway.app) (free tier is enough for testing)
- Railway CLI: `npm install -g @railway/cli`
- VeriCred repo pushed to GitHub (askmi-dev/vericred)

---

## One-time setup

### 1. Create the Railway project

```bash
railway login
railway init        # creates a new project, links this directory
```

Or: go to railway.app → New Project → Deploy from GitHub → select askmi-dev/vericred.

### 2. Add a Volume (secret + data persistence)

In the Railway dashboard:

1. Click your service → **Volumes** tab → **Add Volume**
2. Set **Mount Path**: `/data`
3. Railway will make `/data` survive redeploys and container restarts.

This is where `secrets.json` and `holders.json` will live.

### 3. Set required environment variables

In the Railway dashboard → your service → **Variables**:

| Variable     | Value                                      | Notes                            |
|--------------|--------------------------------------------|----------------------------------|
| `ISSUER_URL` | `https://your-app.up.railway.app`          | Copy from Railway domain settings|
| `DEMO_MODE`  | `true`                                     | Remove for production            |
| `DATA_DIR`   | `/data`                                    | Already in railway.toml          |

**Optional — pre-provision secrets** (skip on first deploy; Railway generates them):

| Variable        | Value                          | Notes                              |
|-----------------|--------------------------------|------------------------------------|
| `ADMIN_API_KEY` | output of `openssl rand -base64 24` | Must set both or neither      |
| `PSEUDO_SECRET` | output of `openssl rand -hex 32`   | NEVER change after first issuance  |

> If you do not set `ADMIN_API_KEY` / `PSEUDO_SECRET`, VeriCred generates them on
> first start and writes them to `/data/secrets.json` on the volume.
> The Admin API Key is printed once to the Railway logs — copy it immediately.

### 4. Set ISSUER_URL after first deploy

Railway assigns a domain after the first successful build. Copy it, then:

1. Set `ISSUER_URL` in Variables to `https://<your-app>.up.railway.app`
2. **Redeploy** (Railway → your service → Redeploy) so the issuer metadata
   reflects the correct public URL.

---

## Deploy

```bash
railway up          # builds Dockerfile, pushes to Railway
```

Or push to your linked GitHub branch — Railway auto-deploys on push.

---

## Verify

```bash
# Check metadata endpoint
curl https://your-app.up.railway.app/.well-known/openid-credential-issuer | jq .

# Should return:
# {
#   "issuer": "https://your-app.up.railway.app",
#   "credential_endpoint": "https://your-app.up.railway.app/credentials",
#   "token_endpoint": "https://your-app.up.railway.app/token",
#   ...
# }
```

---

## Get your Admin API Key

If you did not pre-provision `ADMIN_API_KEY`, find it in Railway logs on first start:

```
Railway dashboard → your service → Deployments → latest → View Logs
```

Look for the banner:
```
╔════════════════════════════════════════════════════╗
║         VeriCred — FIRST START SECRETS             ║
╠════════════════════════════════════════════════════╣
║  Admin API Key : <your-key>                        ║
╚════════════════════════════════════════════════════╝
```

Copy the key — it will not be shown again (it is stored in the volume).

---

## Secret persistence — what survives what

| Event              | `secrets.json` on volume | Env var secrets |
|--------------------|--------------------------|-----------------|
| Redeploy           | ✅ survives              | ✅ survives     |
| Container restart  | ✅ survives              | ✅ survives     |
| Volume deleted     | ❌ lost                  | ✅ survives     |
| New service        | ❌ must re-attach volume | ✅ survives     |

**Recommendation:** after first deploy, read `PSEUDO_SECRET` from the volume
(`cat /data/secrets.json`) and add it as a Railway Secret variable. That way
pseudonyms remain stable even if the volume is ever detached.

---

## Walt.id interop test (after deploy)

1. Open Admin UI: `https://your-app.up.railway.app/admin`
   (header: `x-admin-key: <your-admin-api-key>`)
2. Create a holder (or use DEMO_MODE synthetic holder)
3. Generate credential offer → copy URI or scan QR
4. Open [walt.id web wallet](https://wallet.walt.id) → Add credential → paste URI
5. Log result in `docs/WALLET_INTEROP_LOG.md`

---

## Tear down

```bash
railway down        # stops the service (volume persists)
```

Delete the volume manually in the dashboard if you no longer need it.
