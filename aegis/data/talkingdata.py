"""Adapter + benchmark for the public TalkingData AdTracking Fraud Detection dataset (Kaggle).

Columns: ip, app, device, os, channel, click_time, [attributed_time], is_attributed.
NOTE: `is_attributed` marks an app *download* (conversion) after the click, NOT ground-truth fraud.
Low conversion per ip/channel is the fraud signal TalkingData used, so predicting it is a recognised proxy task.
Download: https://www.kaggle.com/c/talkingdata-adtracking-fraud-detection (login required) -> data/raw/train_sample.csv
Features are computed with the same streaming idea (causal windows: only past clicks of the same ip/app/device).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from aegis.config import ROOT

REQUIRED = ["ip", "app", "device", "os", "channel", "click_time", "is_attributed"]
FEATS = ["app", "device", "os", "channel", "hour", "ip_count", "ip_app_count", "ip_dev_os_count", "ip_channel_count",
         "prev_gap_ip", "prev_gap_ipdevos", "ip_clicks_prior", "ip_unique_channels_prior"]


def load(path: Path, nrows: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(path, nrows=nrows, usecols=lambda c: c in REQUIRED + ["attributed_time"])
    miss = [c for c in REQUIRED if c not in df.columns]
    if miss:
        raise ValueError(f"missing columns {miss}; expected the Kaggle TalkingData schema")
    df["click_time"] = pd.to_datetime(df["click_time"])
    return df.sort_values("click_time", kind="stable").reset_index(drop=True)


def featurize(df: pd.DataFrame) -> pd.DataFrame:
    f = pd.DataFrame(index=df.index)
    for c in ("app", "device", "os", "channel"):
        f[c] = df[c].astype(float)
    f["hour"] = df["click_time"].dt.hour.astype(float)
    t = df["click_time"].astype("int64") / 1e9
    key_dev = df["ip"].astype(str) + "_" + df["device"].astype(str) + "_" + df["os"].astype(str)
    f["ip_count"] = df.groupby("ip")["ip"].transform("size")
    f["ip_app_count"] = df.groupby(["ip", "app"])["ip"].transform("size")
    f["ip_dev_os_count"] = key_dev.map(key_dev.value_counts())
    f["ip_channel_count"] = df.groupby(["ip", "channel"])["ip"].transform("size")
    f["prev_gap_ip"] = t.groupby(df["ip"]).diff().fillna(3600.0).clip(upper=3600.0)
    f["prev_gap_ipdevos"] = t.groupby(key_dev).diff().fillna(3600.0).clip(upper=3600.0)
    f["ip_clicks_prior"] = df.groupby("ip").cumcount().astype(float)
    f["ip_unique_channels_prior"] = (~df.duplicated(["ip", "channel"])).groupby(df["ip"]).cumsum().astype(float)
    return f[FEATS].astype(float)


def benchmark(path: Path, nrows: int | None = None) -> dict:
    df = load(path, nrows)
    y = df["is_attributed"].to_numpy().astype(int)
    X = np.log1p(featurize(df).to_numpy())
    cut = int(len(df) * 0.7)  # temporal split, no shuffling
    if y[:cut].sum() < 2 or y[cut:].sum() < 2:
        raise ValueError("too few positive labels for a split; use a larger sample")
    res = {"rows": int(len(df)), "positive_rate": float(y.mean()), "split": "first 70% train / last 30% test (time ordered)", "models": {}}
    for name, model in {
        "hgb": HistGradientBoostingClassifier(max_iter=150, random_state=42, class_weight="balanced"),
        "mlp": make_pipeline(StandardScaler(), MLPClassifier((64, 32), early_stopping=True, max_iter=200, random_state=42)),
    }.items():
        model.fit(X[:cut], y[:cut])
        p = model.predict_proba(X[cut:])[:, 1]
        res["models"][name] = {"roc_auc": float(roc_auc_score(y[cut:], p)), "pr_auc": float(average_precision_score(y[cut:], p))}
    res["note"] = "Target is app-download conversion (proxy for fraud), not a ground-truth fraud label."
    return res


def make_synthetic_sample(path: Path, n: int = 20000, seed: int = 0) -> Path:
    """Tiny file in the Kaggle schema (for tests/CI only; NOT real data)."""
    rng = np.random.default_rng(seed)
    ip = rng.integers(1, 2000, n)
    farm = ip % 3 == 0
    ch = np.where(farm, rng.integers(1, 4, n), rng.integers(1, 300, n))
    t0 = pd.Timestamp("2017-11-07 09:00:00")
    ts = t0 + pd.to_timedelta(np.sort(rng.integers(0, 4 * 86400, n)), unit="s")
    attr = (rng.random(n) < np.where(farm, 0.0005, 0.02)).astype(int)
    pd.DataFrame({"ip": ip, "app": rng.integers(1, 30, n), "device": rng.integers(1, 5, n), "os": rng.integers(1, 40, n),
                  "channel": ch, "click_time": ts, "attributed_time": "", "is_attributed": attr}).to_csv(path, index=False)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=str(ROOT / "data" / "raw" / "train_sample.csv"))
    ap.add_argument("--nrows", type=int, default=None)
    a = ap.parse_args()
    p = Path(a.path)
    if not p.exists():
        sys.exit(f"[talkingdata] {p} not found. Download train_sample.csv from Kaggle (TalkingData AdTracking Fraud Detection) "
                 "into data/raw/ - see data/README.md. (Use --path to point elsewhere.)")
    r = benchmark(p, a.nrows)
    out = ROOT / "reports" / "talkingdata.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(r, indent=2))
    print(json.dumps(r, indent=2))
