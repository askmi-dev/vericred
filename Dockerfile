# ==========================================
# STAGE 1: Build Frontend & Backend Artifacts
# ==========================================
FROM node:22-alpine AS builder
WORKDIR /app

# System dependencies for potential native modules
RUN apk add --no-cache python3 make g++

# Copy package configs for layering
COPY package*.json ./
COPY stitch-out/package*.json ./stitch-out/

# Install all dependencies
RUN npm ci
RUN npm --prefix stitch-out ci

# Copy source code
COPY . .

# Build both layers
RUN npm run build

# ==========================================
# STAGE 2: Prune Node Modules for Production
# ==========================================
FROM node:22-alpine AS deps-pruner
WORKDIR /app
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
RUN npm prune --production

# ==========================================
# STAGE 3: Final Production Runtime Environment
# ==========================================
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3100
ENV DATA_DIR=/app/data

# su-exec drops root privileges after the entrypoint fixes volume ownership
RUN apk add --no-cache su-exec

# Create data directory and set permissions (covers the case where no
# external volume is mounted over DATA_DIR at all)
RUN mkdir -p /app/data && chown -R node:node /app/data

# Copy artifacts
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=deps-pruner --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/package.json ./package.json

# Copy frontend static build (Backend serves this via express.static)
COPY --from=builder --chown=node:node /app/stitch-out/dist ./stitch-out/dist

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Container starts as root so the entrypoint can chown a mounted volume
# (e.g. Railway's /data) before dropping to the non-privileged node user.
ENTRYPOINT ["docker-entrypoint.sh"]

# Expose Gateway Port
EXPOSE 3100

CMD ["node", "dist/server.js"]
