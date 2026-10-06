#!/usr/bin/env bash
# One-command local setup: venv + dependencies + first model.  Usage: bash scripts/setup.sh [--full] [--no-train]
#   --full also installs the optional integrations (SHAP, LangGraph, Postgres, Redis, Neo4j, Kafka clients)
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11), "Python >= 3.11 required (pinned numpy/pandas/scikit-learn need it)"'
[ -d .venv ] || "$PYTHON" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements-dev.txt
if [ "${1:-}" = "--full" ] || [ "${2:-}" = "--full" ]; then
  .venv/bin/python -m pip install --quiet -r requirements-optional.txt
  .venv/bin/python -m pip install --quiet -r requirements-backends-test.txt || echo "(embedded Postgres/Redis test servers not installed - those tests will be skipped)"
fi
[ -f .env ] || cp .env.example .env
mkdir -p data/raw data/processed models reports
if [ "${1:-}" != "--no-train" ] && [ "${2:-}" != "--no-train" ]; then
  PYTHONPATH="$PWD" .venv/bin/python -m aegis.training
fi
echo "setup complete -> run: make run   (UI: http://localhost:8000)"
