#!/usr/bin/env bash
# End-to-end smoke test: boots a real server on a free port with a temp DB, drives an attack through HTTP+WebSocket, checks results.
source "$(dirname "$0")/_env.sh"
exec "$PY" scripts/verify.py "$@"
