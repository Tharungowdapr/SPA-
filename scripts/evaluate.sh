#!/usr/bin/env bash
# Evaluation pipeline: model metrics + full-system replay + unseen-attack generalisation + benchmark.
#   bash scripts/evaluate.sh [--quick] [--retrain] | --benchmark-only
source "$(dirname "$0")/_env.sh"
if [ "${1:-}" = "--benchmark-only" ]; then exec "$PY" -W ignore -m aegis.evaluation.benchmark; fi
"$PY" -W ignore -m aegis.evaluation.evaluate "$@"
"$PY" -W ignore -m aegis.evaluation.benchmark
echo "reports written to reports/ (EVALUATION.md, metrics.json, benchmark.json, *.png)"
