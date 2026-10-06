#!/usr/bin/env bash
# Build dist/aegisclick.zip (source + trained model + docs; excludes venv, caches, db, raw data).
source "$(dirname "$0")/_env.sh"
mkdir -p dist; rm -f dist/aegisclick.zip
cd "$ROOT/.."
zip -rq "$ROOT/dist/aegisclick.zip" "$(basename "$ROOT")" \
  -x "*/.venv/*" "*/__pycache__/*" "*/.pytest_cache/*" "*/.ruff_cache/*" "*/dist/*" "*/data/*.db*" "*/data/processed/*.pkl" "*/data/raw/*.csv" "*/.env" "*/.coverage"
echo "built $ROOT/dist/aegisclick.zip"
