#!/usr/bin/env bash
# Train, evaluate on validation data and register a new model version. Args passed through (e.g. --quick).
source "$(dirname "$0")/_env.sh"
exec "$PY" -W ignore -m aegis.training "$@"
