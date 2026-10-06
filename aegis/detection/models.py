"""Model layer: Logistic Regression (baseline), MLP neural network, Histogram Gradient Boosting,
Isolation Forest (anomaly), SGD online learner seed. Plus a tiny versioned model registry
(MLflow-style: versions, metrics, promote, rollback) that works without any server.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

try:  # optional boosters: used when installed and listed in ml.optional_models
    from xgboost import XGBClassifier
except Exception:  # noqa: BLE001
    XGBClassifier = None
try:
    from lightgbm import LGBMClassifier
except Exception:  # noqa: BLE001
    LGBMClassifier = None

from aegis.streaming.features import FEATURES


def _log1p(x):
    return np.log1p(np.clip(x, 0, None))


def make_prep(scale: bool = True) -> Pipeline:
    steps = [("log", FunctionTransformer(_log1p))]
    if scale:
        steps.append(("scale", StandardScaler()))
    return Pipeline(steps)


@dataclass
class ModelBundle:
    version: str = "v0"
    trained_at: float = 0.0
    features: list = field(default_factory=lambda: list(FEATURES))
    models: dict = field(default_factory=dict)       # name -> fitted Pipeline (raw features in)
    prep: Pipeline | None = None                     # shared preprocessing (online learner)
    iso: Pipeline | None = None
    iso_ecdf: np.ndarray | None = None               # sorted raw anomaly scores on legit data
    sgd: SGDClassifier | None = None                 # seed state for the online learner
    baseline: np.ndarray | None = None               # median legit feature vector (explanations)
    importance: dict = field(default_factory=dict)   # global permutation importance
    shap_importance: dict = field(default_factory=dict)  # global mean|TreeSHAP| of the XGBoost model (log-odds)
    shap_background: np.ndarray | None = None        # background rows for the SHAP library explainer
    feat_edges: dict | None = None                   # per-feature decile edges (training) for PSI drift
    feat_base: dict | None = None                    # per-feature training bin proportions
    score_base: np.ndarray | None = None             # validation ML-score histogram proportions (10 bins)
    metrics: dict = field(default_factory=dict)
    ensemble: list = field(default_factory=lambda: ["mlp", "hgb"])

    # ------------------------------------------------------------------ inference
    def proba(self, X: np.ndarray, name: str) -> np.ndarray:
        return self.models[name].predict_proba(X)[:, 1]

    def ml_score(self, X: np.ndarray, ensemble: list[str] | None = None) -> np.ndarray:
        names = [n for n in (ensemble or self.ensemble) if n in self.models] or list(self.models)
        return np.mean([self.proba(X, n) for n in names], axis=0)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Map raw IsolationForest score to 0..1 via the legit-traffic ECDF (only the top 5% tail scores > 0)."""
        raw = -self.iso.decision_function(X)
        ecdf = np.searchsorted(self.iso_ecdf, raw) / len(self.iso_ecdf)
        return np.clip((ecdf - 0.95) / 0.05, 0.0, 1.0)

    def online_seed(self) -> SGDClassifier:
        import copy
        return copy.deepcopy(self.sgd)


# ---------------------------------------------------------------------- training
def _xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    return df[FEATURES].to_numpy(dtype=float), df["label"].to_numpy(dtype=int)


def train_bundle(train: pd.DataFrame, val: pd.DataFrame, cfg_ml: dict | None = None, seed: int = 42,
                 version: str = "v0", compute_importance: bool = True) -> ModelBundle:
    cfg_ml = cfg_ml or {}
    mlp_cfg, hgb_cfg = cfg_ml.get("mlp", {}), cfg_ml.get("hgb", {})
    Xtr, ytr = _xy(train)
    Xva, yva = _xy(val)

    models = {
        "logreg": Pipeline([("prep", make_prep()), ("clf", LogisticRegression(
            class_weight="balanced", max_iter=2000, C=1.0, random_state=seed))]),
        "mlp": Pipeline([("prep", make_prep()), ("clf", MLPClassifier(
            hidden_layer_sizes=tuple(mlp_cfg.get("hidden", [64, 32])), activation="relu", alpha=1e-4,
            early_stopping=True, validation_fraction=0.1, n_iter_no_change=8,
            max_iter=mlp_cfg.get("max_iter", 300), random_state=seed))]),
        "hgb": Pipeline([("prep", make_prep(scale=False)), ("clf", HistGradientBoostingClassifier(
            max_iter=hgb_cfg.get("max_iter", 150), learning_rate=0.1, random_state=seed))]),
    }
    wanted = set(cfg_ml.get("optional_models", ["xgb", "lgbm"]))
    if "xgb" in wanted and XGBClassifier is not None:
        models["xgb"] = Pipeline([("prep", make_prep(scale=False)), ("clf", XGBClassifier(
            n_estimators=150, max_depth=5, learning_rate=0.1, subsample=0.9, eval_metric="logloss", n_jobs=2, random_state=seed))])
    if "lgbm" in wanted and LGBMClassifier is not None:
        models["lgbm"] = Pipeline([("prep", make_prep(scale=False)), ("clf", LGBMClassifier(
            n_estimators=150, learning_rate=0.1, num_leaves=31, verbose=-1, n_jobs=2, random_state=seed))])
    for m in models.values():
        m.fit(Xtr, ytr)

    prep = make_prep().fit(Xtr)
    legit = Xtr[ytr == 0]
    iso = Pipeline([("prep", make_prep()), ("iso", IsolationForest(
        n_estimators=100, contamination="auto", random_state=seed, n_jobs=1))]).fit(legit)
    rng = np.random.default_rng(seed)
    sample = legit[rng.choice(len(legit), size=min(20000, len(legit)), replace=False)]
    iso_ecdf = np.sort(-iso.decision_function(sample))

    sgd = SGDClassifier(loss="log_loss", alpha=1e-4, random_state=seed)
    Xs = prep.transform(Xtr)
    for _ in range(3):
        sgd.partial_fit(Xs, ytr, classes=np.array([0, 1]))

    b = ModelBundle(version=version, trained_at=time.time(), models=models, prep=prep, iso=iso,
                    iso_ecdf=iso_ecdf, sgd=sgd, baseline=np.median(legit, axis=0),
                    ensemble=cfg_ml.get("ensemble", ["mlp", "hgb"]))
    ens = [n for n in b.ensemble if n in models]
    b.ensemble = ens or ["mlp", "hgb"]
    b.shap_background = Xtr[rng.choice(len(Xtr), size=min(60, len(Xtr)), replace=False)]
    b.feat_edges, b.feat_base = {}, {}
    for j, f in enumerate(FEATURES):
        edges = np.unique(np.quantile(Xtr[:, j], np.linspace(0.1, 0.9, 9)))
        b.feat_edges[f] = edges
        b.feat_base[f] = np.bincount(np.searchsorted(edges, Xtr[:, j], side="right"), minlength=len(edges) + 1) / len(Xtr)
    b.score_base = np.histogram(b.ml_score(Xva), bins=10, range=(0, 1))[0] / len(Xva)
    b.metrics = {n: _summ(yva, b.proba(Xva, n)) for n in models}
    b.metrics["ensemble"] = _summ(yva, b.ml_score(Xva))
    b.metrics["anomaly"] = _summ(yva, b.anomaly_score(Xva))
    b.metrics["_train_rows"] = int(len(ytr))
    if compute_importance:
        sub = rng.choice(len(yva), size=min(6000, len(yva)), replace=False)
        pi = permutation_importance(models["mlp"], Xva[sub], yva[sub], scoring="average_precision",
                                    n_repeats=3, random_state=seed, n_jobs=1)
        b.importance = {f: float(v) for f, v in sorted(zip(FEATURES, pi.importances_mean), key=lambda t: -t[1])}
    if "xgb" in models:
        try:
            import shap  # type: ignore
            sub_x = Xva[rng.choice(len(Xva), size=min(1500, len(Xva)), replace=False)]
            sv = shap.TreeExplainer(models["xgb"].named_steps["clf"]).shap_values(models["xgb"][:-1].transform(sub_x))
            b.shap_importance = {f: float(v) for f, v in sorted(zip(FEATURES, np.abs(sv).mean(axis=0)), key=lambda t: -t[1])}
        except Exception:  # noqa: BLE001 - SHAP is optional
            pass
    return b


def _summ(y: np.ndarray, p: np.ndarray) -> dict:
    return {"pr_auc": float(average_precision_score(y, p)), "roc_auc": float(roc_auc_score(y, p)),
            "f1@0.5": float(f1_score(y, p >= 0.5, zero_division=0))}


# ---------------------------------------------------------------------- registry
class Registry:
    """models/registry.json + models/<version>/bundle.joblib. Supports promote and rollback."""

    def __init__(self, models_dir: Path):
        self.dir = Path(models_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.file = self.dir / "registry.json"

    def _read(self) -> dict:
        return json.loads(self.file.read_text()) if self.file.exists() else {"production": None, "history": [], "versions": {}}

    def _write(self, reg: dict) -> None:
        self.file.write_text(json.dumps(reg, indent=2))

    def next_version(self) -> str:
        return f"v{len(self._read()['versions']) + 1}"

    def save(self, bundle: ModelBundle, promote: bool = True) -> str:
        reg = self._read()
        vdir = self.dir / bundle.version
        vdir.mkdir(exist_ok=True)
        joblib.dump(bundle, vdir / "bundle.joblib", compress=3)
        reg["versions"][bundle.version] = {"trained_at": bundle.trained_at, "metrics": bundle.metrics,
                                           "importance": bundle.importance, "features": bundle.features}
        if promote:
            self._promote(reg, bundle.version)
        self._write(reg)
        try:  # optional experiment tracking
            import mlflow  # type: ignore
            with mlflow.start_run(run_name=bundle.version):
                for n, m in bundle.metrics.items():
                    if isinstance(m, dict):
                        for k, v in m.items():
                            mlflow.log_metric(f"{n}_{k}".replace("@", "_at_"), v)
        except Exception:
            pass
        return bundle.version

    @staticmethod
    def _promote(reg: dict, version: str) -> None:
        if reg["production"] and reg["production"] != version:
            reg["history"].append(reg["production"])
        reg["production"] = version

    def promote(self, version: str) -> None:
        reg = self._read()
        if version not in reg["versions"]:
            raise KeyError(version)
        self._promote(reg, version)
        self._write(reg)

    def rollback(self) -> str | None:
        reg = self._read()
        if not reg["history"]:
            return None
        reg["production"] = reg["history"].pop()
        self._write(reg)
        return reg["production"]

    def production(self) -> str | None:
        return self._read()["production"]

    def load(self, version: str | None = None) -> ModelBundle | None:
        version = version or self.production()
        path = self.dir / (version or "") / "bundle.joblib"
        return joblib.load(path) if version and path.exists() else None

    def describe(self) -> dict:
        return self._read()


def psi(expected: np.ndarray, actual: np.ndarray, eps: float = 1e-4) -> float:
    """Population Stability Index between two bin-proportion vectors (<0.1 stable, <0.25 moderate, else drift)."""
    e, a = np.clip(np.asarray(expected, float), eps, None), np.clip(np.asarray(actual, float), eps, None)
    return float(np.sum((a - e) * np.log(a / e)))
