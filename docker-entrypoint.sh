#!/bin/sh
# Railway (and other platforms) mount external volumes with their own
# ownership, independent of whatever the image's build stage chowned.
# DATA_DIR may point at such a mount (e.g. Railway's /data), so fix its
# ownership here — while still root — before dropping to the non-root
# node user to run the app.
set -e

DATA_DIR="${DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"
chown -R node:node "$DATA_DIR" 2>/dev/null || true

exec su-exec node "$@"
