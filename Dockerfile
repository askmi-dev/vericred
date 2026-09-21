# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
COPY stitch-out/package.json stitch-out/package-lock.json ./stitch-out/
RUN npm ci --no-audit --no-fund && npm --prefix stitch-out ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY stitch-out/astro.config.mjs ./stitch-out/
COPY stitch-out/src ./stitch-out/src
COPY stitch-out/public ./stitch-out/public
RUN npm run build

FROM node:22-alpine AS production-dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production PORT=3100 DATA_DIR=/app/data ASTRO_TELEMETRY_DISABLED=1
RUN mkdir -p /app/data && chown node:node /app/data && chmod 700 /app/data
COPY --from=production-dependencies /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/stitch-out/dist ./stitch-out/dist
COPY scripts/backup-restore.mjs scripts/eudi-material-preflight.mjs ./scripts/
USER node
EXPOSE 3100
VOLUME ["/app/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3100)+'/health',{signal:AbortSignal.timeout(3000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "dist/server.js"]
