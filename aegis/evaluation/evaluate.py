"""Evaluation pipeline -> reports/metrics.json, reports/EVALUATION.md, reports/*.png.

Part A  model-level metrics on a held-out test set (logreg / MLP / HGB / ensemble / anomaly / rules / graph)
Part B  full-system replay: test episodes streamed through the real Pipeline (fusion + auto-block)
Part C  generalisation: train on 5 seen attacks, test on 3 UNSEEN ones (ip_rotation, low_and_slow, mimicry)
Every number is measured here; nothing is hard-coded.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)

from aegis.config import ROOT, Settings, load_settings
from aegis.data.dataset import UNSEEN_ATTACKS, standard_splits
from aegis.detection.models import Registry, _xy, train_bundle
from aegis.pipeline import Pipeline
from aegis.simulator.traffic import ATTACK_TYPES, build_episode
from aegis.store.db import Store


def binary_metrics(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> dict:
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y, p)) if len(set(y)) > 1 else None,
            "pr_auc": float(average_precision_score(y, p)) if len(set(y)) > 1 else None,
            "fpr": float(fp / max(1, fp + tn)), "fnr": float(fn / max(1, fn + tp)),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "threshold": thr}


def part_a(bundle, test: pd.DataFrame) -> tuple[dict, dict]:
    X, y = _xy(test)
    scores = {n: bundle.proba(X, n) for n in bundle.models}
    scores["ensemble(mlp+hgb)"] = bundle.ml_score(X)
    scores["anomaly(isolation-forest)"] = bundle.anomaly_score(X)
    scores["rules"] = test["rule_score"].to_numpy()
    scores["graph"] = test["graph_score"].to_numpy()
    return {k: binary_metrics(y, v) for k, v in scores.items()}, scores


def part_b(settings: Settings, bundle, seeds: list[int], n_users: int) -> dict:
    rows, actor_first = [], {}
    t_ingest = 0.0
    n_events = 0
    for seed in seeds:
        s = settings.copy()
        s.set("app.db_path", ":memory:")
        pipe = Pipeline(s, store=Store(":memory:"), bundle=bundle)
        events = build_episode(seed, n_users=n_users)
        t0 = time.perf_counter()
        decisions = []
        for i in range(0, len(events), 200):
            decisions += pipe.process_events(events[i:i + 200])
        t_ingest += time.perf_counter() - t0
        n_events += len(events)
        seen = defaultdict(int)
        for d in decisions:
            seen[d.user_id] += 1
            detected = d.action in ("FLAG", "BLOCK", "REJECTED")
            rows.append((seed, d.label, d.attack_type, d.risk, detected, d.action in ("BLOCK", "REJECTED"), d.latency_ms))
            if d.label == 1 and detected and (seed, d.user_id) not in actor_first:
                actor_first[(seed, d.user_id)] = (d.attack_type, seen[d.user_id])
        fraud_actors = {(seed, d.user_id): d.attack_type for d in decisions if d.label == 1}
        for k, a in fraud_actors.items():
            actor_first.setdefault(k, (a, None))
    df = pd.DataFrame(rows, columns=["seed", "label", "attack", "risk", "detected", "blocked", "lat"])
    y, det = df["label"].to_numpy(), df["detected"].to_numpy().astype(int)
    overall = binary_metrics(y, df["risk"].to_numpy(), thr=0.7)
    overall |= {"flag_precision": float(precision_score(y, det, zero_division=0)), "flag_recall": float(recall_score(y, det, zero_division=0)),
                "flag_f1": float(f1_score(y, det, zero_division=0)), "flag_fpr": float(((det == 1) & (y == 0)).sum() / max(1, (y == 0).sum()))}
    per = {}
    for a in ["normal"] + ATTACK_TYPES:
        g = df[df["attack"] == a]
        if len(g):
            per[a] = {"events": int(len(g)), "flagged_rate": float(g["detected"].mean()), "blocked_rate": float(g["blocked"].mean())}
    by_attack = defaultdict(list)
    for (_, _), (a, n) in actor_first.items():
        by_attack[a].append(n)
    actors = {a: {"actors": len(v), "detected": sum(1 for x in v if x is not None),
                  "median_clicks_to_first_flag": statistics.median([x for x in v if x is not None]) if any(x is not None for x in v) else None}
              for a, v in by_attack.items()}
    return {"overall": overall, "per_attack": per, "per_actor": actors, "throughput_events_per_s": n_events / t_ingest,
            "latency_ms": {"p50": float(df["lat"].quantile(0.5)), "p95": float(df["lat"].quantile(0.95))},
            "events": int(len(df)), "legit_users_blocked": None}


def part_c(settings: Settings, quick: bool) -> dict:
    d = standard_splits(settings.get("rules"), quick=quick)
    b = train_bundle(d["train_seen"], d["val"], settings.get("ml"), version="seen-only", compute_importance=False)
    test = d["test"]
    sub = test[test["attack_type"].isin(["normal"] + UNSEEN_ATTACKS)].reset_index(drop=True)
    X, y = _xy(sub)
    layers = {"ml(mlp+hgb)": b.ml_score(X), "logreg": b.proba(X, "logreg"), "anomaly": b.anomaly_score(X),
              "rules": sub["rule_score"].to_numpy(), "graph": sub["graph_score"].to_numpy()}
    out = {"unseen_attacks": UNSEEN_ATTACKS, "layers": {}}
    for k, p in layers.items():
        m = binary_metrics(y, p)
        m["recall_by_attack"] = {a: float((p[(sub["attack_type"] == a).to_numpy()] >= 0.5).mean()) for a in UNSEEN_ATTACKS}
        out["layers"][k] = m
    return out


def plots(scores: dict, y: np.ndarray, metrics: dict, per_attack: dict, outdir: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    files = []
    fig, ax = plt.subplots(figsize=(6, 4.5))
    for k in [k for k in ("logreg", "mlp", "hgb", "xgb", "lgbm", "ensemble(mlp+hgb)", "anomaly(isolation-forest)", "rules") if k in scores]:
        pr, rc, _ = precision_recall_curve(y, scores[k])
        ax.plot(rc, pr, label=f"{k} (AP={metrics[k]['pr_auc']:.3f})")
    ax.set_xlabel("recall"), ax.set_ylabel("precision"), ax.set_title("Precision-Recall (held-out test)"), ax.legend(fontsize=7), ax.grid(alpha=.3)
    fig.tight_layout(), fig.savefig(outdir / "pr_curve.png", dpi=130), plt.close(fig), files.append("pr_curve.png")
    cm = metrics["ensemble(mlp+hgb)"]["confusion"]
    fig, ax = plt.subplots(figsize=(3.8, 3.4))
    ax.imshow([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], cmap="Blues")
    for (i, j), v in np.ndenumerate([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]]):
        ax.text(j, i, f"{v:,}", ha="center", va="center", color="black")
    ax.set_xticks([0, 1], ["legit", "fraud"]), ax.set_yticks([0, 1], ["legit", "fraud"]), ax.set_xlabel("predicted"), ax.set_ylabel("actual"), ax.set_title("Ensemble confusion @0.5")
    fig.tight_layout(), fig.savefig(outdir / "confusion.png", dpi=130), plt.close(fig), files.append("confusion.png")
    names = [a for a in ATTACK_TYPES if a in per_attack]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    x = np.arange(len(names))
    ax.bar(x - 0.2, [per_attack[a]["flagged_rate"] for a in names], 0.4, label="flagged (HIGH+)")
    ax.bar(x + 0.2, [per_attack[a]["blocked_rate"] for a in names], 0.4, label="blocked/rejected")
    ax.set_xticks(x, names, rotation=30, ha="right", fontsize=8), ax.set_ylim(0, 1.05), ax.set_title("Full-system detection per attack (event level)"), ax.legend(), ax.grid(axis="y", alpha=.3)
    fig.tight_layout(), fig.savefig(outdir / "per_attack.png", dpi=130), plt.close(fig), files.append("per_attack.png")
    return files


def write_markdown(res: dict, path: Path, files: list[str]) -> None:
    f = lambda v: "-" if v is None else f"{v:.4f}"
    L = ["# AegisClick Evaluation Report", "", f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by `make evaluate`. All values are measured; simulator data only._", "",
         f"Model version: **{res['model_version']}**  |  test rows: {res['test_rows']:,}  |  fraud rate: {res['test_fraud_rate']:.2%}", "",
         "## A. Model-level (held-out test, threshold 0.5)", "", "| layer | precision | recall | F1 | ROC-AUC | PR-AUC | FPR | FNR |", "|---|---|---|---|---|---|---|---|"]
    for k, m in res["model_level"].items():
        L.append(f"| {k} | {f(m['precision'])} | {f(m['recall'])} | {f(m['f1'])} | {f(m['roc_auc'])} | {f(m['pr_auc'])} | {f(m['fpr'])} | {f(m['fnr'])} |")
    b = res["system"]
    o = b["overall"]
    L += ["", "## B. Full system (streamed through the real pipeline, fusion + auto-block)", "",
          f"Events: {b['events']:,} | throughput: {b['throughput_events_per_s']:,.0f} events/s (single process, includes feature engineering, 4 ML layers, persistence) | "
          f"detection latency p50 {b['latency_ms']['p50']:.1f} ms, p95 {b['latency_ms']['p95']:.1f} ms (batch of 200)", "",
          f"Flag decision (HIGH or above): precision {f(o['flag_precision'])}, recall {f(o['flag_recall'])}, F1 {f(o['flag_f1'])}, FPR {f(o['flag_fpr'])}", "",
          "| attack | events | flagged | blocked/rejected |", "|---|---|---|---|"]
    L += [f"| {a} | {v['events']:,} | {v['flagged_rate']:.1%} | {v['blocked_rate']:.1%} |" for a, v in b["per_attack"].items()]
    L += ["", "Per actor (a user/device identity running an attack): fraction detected and clicks needed before the first flag.", "", "| attack | actors | detected | median clicks to first flag |", "|---|---|---|---|"]
    L += [f"| {a} | {v['actors']} | {v['detected']} | {v['median_clicks_to_first_flag']} |" for a, v in sorted(b["per_actor"].items()) if a != "normal"]
    L += ["", f"Legitimate users auto-blocked: **{b['legit_users_blocked']}**", "", "## C. Generalisation to unseen attacks", "",
          "Models trained only on burst, bot, click_farm, device_farm, campaign_hopping; tested on ip_rotation, low_and_slow, mimicry.", "",
          "| layer | PR-AUC | recall@0.5 | FPR | " + " | ".join(res["unseen"]["unseen_attacks"]) + " |", "|---|---|---|---|" + "---|" * len(res["unseen"]["unseen_attacks"])]
    for k, m in res["unseen"]["layers"].items():
        L.append(f"| {k} | {f(m['pr_auc'])} | {f(m['recall'])} | {f(m['fpr'])} | " + " | ".join(f"{m['recall_by_attack'][a]:.2f}" for a in res["unseen"]["unseen_attacks"]) + " |")
    L += ["", "## Figures", ""] + [f"![{n}]({n})" for n in files]
    L += ["", "## Caveats", "", "- Simulator-generated data: results show the pipeline works as designed, not production accuracy.",
          "- Mimicry and low-and-slow attacks are the hardest; see sections B/C for honest per-attack numbers.",
          "- The same simulator family generates train and test (different seeds); section C removes attack-type leakage."]
    path.write_text("\n".join(L))


def run(quick: bool = False, retrain: bool = False) -> dict:
    s = load_settings()
    outdir = ROOT / s.get("app.reports_dir", "reports")
    outdir.mkdir(exist_ok=True)
    d = standard_splits(s.get("rules"), quick=quick)
    reg = Registry(s.resolve_path("app.models_dir"))
    bundle = None if retrain else reg.load()
    if bundle is None:
        bundle = train_bundle(d["train"], d["val"], s.get("ml"), version="eval", compute_importance=False)
    test = d["test"]
    model_level, scores = part_a(bundle, test)
    system = part_b(s, bundle, [300, 301] if quick else [300, 301, 302], 600 if quick else 1500)
    unseen = part_c(s, quick)
    # legit users blocked (system run) - recompute quickly on one episode
    s2 = s.copy()
    pipe = Pipeline(s2, store=Store(":memory:"), bundle=bundle)
    ev = build_episode(300, n_users=600 if quick else 1500)
    for i in range(0, len(ev), 200):
        pipe.process_events(ev[i:i + 200])
    legit_ids = {e.user_id for e in ev if e.label == 0}
    system["legit_users_blocked"] = len(pipe.blocked_users & legit_ids)
    res = {"model_version": bundle.version, "test_rows": int(len(test)), "test_fraud_rate": float(test["label"].mean()),
           "model_level": model_level, "system": system, "unseen": unseen, "generated": time.time()}
    files = plots(scores, test["label"].to_numpy(), model_level, system["per_attack"], outdir)
    (outdir / "metrics.json").write_text(json.dumps(res, indent=2))
    write_markdown(res, outdir / "EVALUATION.md", files)
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--retrain", action="store_true")
    a = ap.parse_args()
    r = run(a.quick, a.retrain)
    e = r["model_level"]["ensemble(mlp+hgb)"]
    print(f"[evaluate] ensemble PR-AUC={e['pr_auc']:.4f} F1={e['f1']:.4f} | system flag F1={r['system']['overall']['flag_f1']:.4f} "
          f"legit users blocked={r['system']['legit_users_blocked']} | report: reports/EVALUATION.md")
