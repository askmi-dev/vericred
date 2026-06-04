# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# Prune dev deps
RUN npm ci --omit=dev --ignore-scripts

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

# Non-root user
RUN addgroup -S vericred && adduser -S vericred -G vericred

WORKDIR /app

# Copy compiled output and production deps only
COPY --from=builder --chown=vericred:vericred /app/dist ./dist
COPY --from=builder --chown=vericred:vericred /app/node_modules ./node_modules
COPY --from=builder --chown=vericred:vericred /app/package.json ./

# /data is the persistent volume mount point:
#   - secrets.json (generated on first start, survives redeploys)
#   - holders.json (your holder data, uploaded once via Admin UI or volume)
RUN mkdir -p /data && chown vericred:vericred /data

USER vericred

EXPOSE 3100

# Required env vars (set in Railway dashboard or railway.toml):
#   ISSUER_URL     — public HTTPS URL of this deployment (no trailing slash)
#   PORT           — Railway sets this automatically
#
# Optional env vars:
#   DEMO_MODE      — "true" to allow credential issuance without real holder data
#   ADMIN_API_KEY  — if set together with PSEUDO_SECRET, skips volume-based secrets
#   PSEUDO_SECRET  — see above
#   DATA_DIR       — defaults to /data (volume mount point)

ENV DATA_DIR=/data \
    PORT=3100

CMD ["node", "dist/server.js"]
