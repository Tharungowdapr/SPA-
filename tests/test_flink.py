"""Parity: the Apache Flink job must compute the same streaming features as the Python FeatureEngine.
Needs PyFlink + Java: set AEGIS_FLINK_PYTHON=/path/to/python-with-apache-flink (see flink/README.md). Skipped otherwise."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from aegis.simulator.traffic import build_episode
from aegis.streaming.features import FeatureEngine

PY = os.environ.get("AEGIS_FLINK_PYTHON", "")
pytestmark = pytest.mark.skipif(not PY or not Path(PY).exists(), reason="set AEGIS_FLINK_PYTHON to run the Flink parity test")
JOB = Path(__file__).resolve().parent.parent / "flink" / "aegis_flink_features.py"
KEYS = ["clicks_10s", "clicks_1m", "clicks_5m", "clicks_1h", "avg_interval", "min_interval", "interval_std",
        "interval_cv", "timing_entropy", "burst_score"]


def test_flink_features_match_python_engine(tmp_path):
    events = build_episode(8, n_users=120)
    src, dst = tmp_path / "in.jsonl", tmp_path / "out.jsonl"
    src.write_text("\n".join(json.dumps({"event_id": e.event_id, "user_id": e.user_id, "timestamp": e.timestamp}) for e in events))
    proc = subprocess.run([PY, str(JOB), "--input", str(src), "--output", str(dst)], capture_output=True, text=True, timeout=280)
    assert dst.exists(), proc.stderr[-1500:]
    got = {r["event_id"]: r["features"] for r in map(json.loads, dst.read_text().splitlines())}
    assert len(got) == len(events)
    fe = FeatureEngine()
    worst = 0.0
    for e in events:
        want = fe.update(e)
        for k in KEYS:
            worst = max(worst, abs(got[e.event_id][k] - want[k]))
    assert worst < 1e-6, f"max abs difference {worst}"
