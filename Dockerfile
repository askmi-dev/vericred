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

WORKDIR /app

# Copy compiled output and production deps only
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

EXPOSE 3100

# Required env vars (set in Railway dashboard):
#   ISSUER_URL  -- public HTTPS URL of this deployment (no trailing slash)
#   PORT        -- Railway sets this automatically
#   DATA_DIR    -- defaults to /data (Railway Volume mount point)
#   DEMO_MODE   -- set to "true" for test deployments

ENV DATA_DIR=/data \
    PORT=3100

CMD ["node", "dist/server.js"]
