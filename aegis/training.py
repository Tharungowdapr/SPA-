"""Train -> register -> promote. Used by `make train`, startup auto-train, and POST /api/models/retrain."""
from __future__ import annotations

import time

from aegis.config import Settings
from aegis.data.dataset import standard_splits
from aegis.detection.models import ModelBundle, Registry, train_bundle
from aegis.store.db import Store


def train_and_register(settings: Settings, quick: bool = False, promote: bool = True,
                       store: Store | None = None, log=print) -> ModelBundle:
    reg = Registry(settings.resolve_path("app.models_dir"))
    t0 = time.time()
    log(f"[train] building datasets (quick={quick}) ...")
    d = standard_splits(settings.get("rules"), quick=quick)
    log(f"[train] rows: train={len(d['train'])} val={len(d['val'])} test={len(d['test'])}")
    bundle = train_bundle(d["train"], d["val"], settings.get("ml"), seed=settings.get("app.seed", 42),
                          version=reg.next_version(), compute_importance=not quick)
    reg.save(bundle, promote=promote)
    if store is not None:
        store.upsert_model_version(bundle.version, bundle.trained_at, "production" if promote else "staged", bundle.metrics)
    m = bundle.metrics["ensemble"]
    log(f"[train] {bundle.version} done in {time.time() - t0:.1f}s  val PR-AUC={m['pr_auc']:.4f} ROC-AUC={m['roc_auc']:.4f}")
    return bundle


def ensure_models(settings: Settings, store: Store | None = None, log=print) -> ModelBundle | None:
    """Load production model; auto-train a quick one if none exists (and allowed); else None (rules-only mode)."""
    reg = Registry(settings.resolve_path("app.models_dir"))
    try:
        b = reg.load()
        if b is not None:
            return b
    except Exception as exc:  # noqa: BLE001 - corrupt registry must not stop startup
        log(f"[models] failed to load production model: {exc}")
    if settings.get("app.auto_train", True):
        try:
            return train_and_register(settings, quick=True, store=store, log=log)
        except Exception as exc:  # noqa: BLE001
            log(f"[models] auto-train failed: {exc}")
    return None


if __name__ == "__main__":
    import argparse

    from aegis.config import load_settings
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller dataset, skip permutation importance")
    a = ap.parse_args()
    train_and_register(load_settings(), quick=a.quick)
