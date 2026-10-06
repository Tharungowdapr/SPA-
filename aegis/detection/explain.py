"""Explainability from the real model: sampled Shapley values against a legit-traffic baseline.

contribution_j = average marginal change in the ensemble fraud probability when feature j is switched
from its typical-legit value to the observed value. Contributions sum exactly to p(x) - p(baseline).
"""
from __future__ import annotations

import numpy as np

from aegis.detection.models import ModelBundle
from aegis.streaming.features import FEATURE_LABELS, FEATURES


def shap_available() -> bool:
    try:
        import shap  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def shap_explanation(bundle: ModelBundle, x: np.ndarray, top_k: int = 5) -> dict:
    """Real SHAP library (permutation algorithm, exact additivity) on the live ensemble, in probability units."""
    import shap  # type: ignore
    bg = bundle.shap_background if bundle.shap_background is not None else bundle.baseline.reshape(1, -1)
    expl = shap.Explainer(lambda X: bundle.ml_score(np.asarray(X)), shap.maskers.Independent(bg[:10], max_samples=10),
                          algorithm="permutation", seed=0)
    ex = expl(x.reshape(1, -1), max_evals=2 * len(x) * 3 + 1, silent=True)
    contrib, base = ex.values[0], float(np.ravel(ex.base_values)[0])
    order = np.argsort(-np.abs(contrib))[:top_k]
    typical = np.median(bg, axis=0)
    factors = [{"feature": FEATURES[j], "label": FEATURE_LABELS[FEATURES[j]], "value": round(float(x[j]), 3),
                "typical": round(float(typical[j]), 3), "contribution": round(float(contrib[j]), 4)} for j in order]
    return {"method": "shap-library", "base_probability": round(base, 4), "prediction": round(base + float(contrib.sum()), 4),
            "factors": factors}


def local_explanation(bundle: ModelBundle, x: np.ndarray, n_perm: int = 12, top_k: int = 5, seed: int = 0, backend: str = "shapley") -> dict:
    if backend in ("shap", "auto") and shap_available():
        try:
            return shap_explanation(bundle, x, top_k)
        except Exception:  # noqa: BLE001 - fall back to the built-in estimator
            pass
    base, f = bundle.baseline, len(x)
    rng = np.random.default_rng(seed)
    rows, perms = [base.copy()], []
    for _ in range(n_perm):
        perm = rng.permutation(f)
        cur = base.copy()
        for j in perm:
            cur = cur.copy()
            cur[j] = x[j]
            rows.append(cur)
        perms.append(perm)
    p = bundle.ml_score(np.asarray(rows))
    contrib, k = np.zeros(f), 1
    for perm in perms:
        prev = p[0]
        for j in perm:
            contrib[j] += p[k] - prev
            prev = p[k]
            k += 1
    contrib /= n_perm
    order = np.argsort(-np.abs(contrib))[:top_k]
    factors = [{"feature": FEATURES[j], "label": FEATURE_LABELS[FEATURES[j]], "value": round(float(x[j]), 3),
                "typical": round(float(base[j]), 3), "contribution": round(float(contrib[j]), 4)} for j in order]
    return {"method": "sampled-shapley", "base_probability": round(float(p[0]), 4),
            "prediction": round(float(p[-1]), 4), "factors": factors}


def rule_factors(rules_fired: list[str], feats: dict[str, float]) -> list[dict]:
    """Fallback explanation when the ML layer is unavailable (reduced-confidence mode)."""
    return [{"feature": r, "label": r.replace("_", " ").capitalize(), "value": None, "typical": None,
             "contribution": None} for r in rules_fired]


def explanation_text(factors: list[dict]) -> str:
    parts = []
    for f in factors[:3]:
        if f["contribution"] is None:
            parts.append(f["label"])
        elif f["contribution"] > 0:
            parts.append(f"{f['label']} = {f['value']:g} (typical {f['typical']:g}) raised the score by {f['contribution']:+.2f}")
    return "; ".join(parts) if parts else "No single dominant factor."
