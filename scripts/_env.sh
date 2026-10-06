# Shared helpers: resolve project root and python (venv if present).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; else PY="${PYTHON:-python3}"; fi
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi
