"""Write a labeled simulator episode to CSV (offline-demo input).  python scripts/export_csv.py data/raw/episode.csv [--seed 7] [--users 400]"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aegis.simulator.traffic import build_episode  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--seed", type=int, default=7)
ap.add_argument("--users", type=int, default=400)
a = ap.parse_args()
ev = build_episode(a.seed, n_users=a.users)
with open(a.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(ev[0].model_dump()))
    w.writeheader()
    w.writerows(e.model_dump() for e in ev)
print(f"wrote {len(ev)} events -> {a.out}")
