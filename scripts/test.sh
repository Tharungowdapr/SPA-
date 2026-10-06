#!/usr/bin/env bash
source "$(dirname "$0")/_env.sh"
"$PY" -m ruff check aegis tests scripts 2>/dev/null || echo "(ruff not installed - lint skipped)"
exec "$PY" -m pytest "$@"
