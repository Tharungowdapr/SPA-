"""Online learning + drift detection (River-style, dependency-free).

Poisoning defence: the online model learns only from analyst-confirmed labels (default) or from
pseudo-labels that are staged and committed after a delay unless an analyst contradicts them.
"""
from __future__ import annotations

import numpy as np

from aegis.detection.models import ModelBundle


class PageHinkley:
    """Detects an upward shift in the mean of a stream (e.g. risk score) - concept-drift signal."""

    def __init__(self, delta: float = 0.01, threshold: float = 30.0):
        self.delta, self.threshold = delta, threshold
        self.reset()

    def reset(self) -> None:
        self.n, self.mean, self.cum, self.min_cum = 0, 0.0, 0.0, 0.0

    def update(self, x: float) -> bool:
        self.n += 1
        self.mean += (x - self.mean) / self.n
        self.cum += x - self.mean - self.delta
        self.min_cum = min(self.min_cum, self.cum)
        if self.cum - self.min_cum > self.threshold:
            self.reset()
            return True
        return False


class OnlineLearner:
    def __init__(self, bundle: ModelBundle, drift_threshold: float = 30.0):
        self.prep = bundle.prep
        self.sgd = bundle.online_seed()
        self.drift = PageHinkley(threshold=drift_threshold)
        self.n_learned = 0
        self.pending: dict[str, tuple[np.ndarray, int, float]] = {}
        self.drift_events = 0

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.sgd.predict_proba(self.prep.transform(X))[:, 1]

    def observe(self, risk: float) -> bool:
        hit = self.drift.update(risk)
        self.drift_events += int(hit)
        return hit

    def learn(self, x: np.ndarray, y: int) -> None:
        self.sgd.partial_fit(self.prep.transform(x.reshape(1, -1)), [int(y)])
        self.n_learned += 1

    def stage(self, event_id: str, x: np.ndarray, y: int, ts: float) -> None:
        self.pending[event_id] = (x, int(y), ts)

    def confirm(self, event_id: str, x: np.ndarray, y: int) -> None:
        """Analyst feedback: overrides any staged pseudo-label and learns immediately."""
        self.pending.pop(event_id, None)
        self.learn(x, y)

    def commit(self, now: float, delay: float = 60.0) -> int:
        ready = [k for k, (_, _, ts) in self.pending.items() if now - ts >= delay]
        for k in ready:
            x, y, _ = self.pending.pop(k)
            self.learn(x, y)
        return len(ready)
