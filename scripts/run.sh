#!/usr/bin/env bash
# Start the platform. Env: HOST, PORT, RELOAD=1, WORKERS is intentionally 1 (in-process state).
source "$(dirname "$0")/_env.sh"
HOST="${HOST:-0.0.0.0}"; PORT="${PORT:-8000}"
echo "AegisClick -> http://localhost:${PORT}   simulator: /sim   api docs: /docs"
echo "demo logins: admin@aegis.local/admin123  analyst@aegis.local/analyst123  viewer@aegis.local/viewer123"
ARGS=(--factory --host "$HOST" --port "$PORT")
[ "${RELOAD:-0}" = "1" ] && ARGS+=(--reload)
exec "$PY" -m uvicorn aegis.api.app:app_factory "${ARGS[@]}"
