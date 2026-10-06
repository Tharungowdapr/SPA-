"""Hybrid risk fusion. Weights are renormalised over the layers that are actually available."""
from __future__ import annotations

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ACTIONS = {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "FLAG", "CRITICAL": "BLOCK"}


class RiskEngine:
    """risk = weighted mean of the scoring layers (rules, ml, online, anomaly), renormalised over available layers,
    then the graph layer acts as corroborating evidence (noisy-OR boost): absence of a fraud ring must not
    dilute a strong single-actor signal, but presence of one must raise risk."""

    def __init__(self, weights: dict[str, float], levels: dict[str, float], hard_floor: float = 0.75,
                 graph_boost: float = 0.6):
        self.weights = {k: v for k, v in weights.items() if k != "graph"}
        self.levels, self.hard_floor, self.graph_boost = levels, hard_floor, graph_boost

    def level(self, risk: float) -> str:
        if risk >= self.levels["critical"]:
            return "CRITICAL"
        if risk >= self.levels["high"]:
            return "HIGH"
        if risk >= self.levels["medium"]:
            return "MEDIUM"
        return "LOW"

    def fuse(self, scores: dict[str, float | None], hard: bool = False) -> tuple[float, str, str, str]:
        avail = {k: v for k, v in scores.items() if v is not None and self.weights.get(k, 0) > 0}
        total = sum(self.weights.values())
        used = sum(self.weights[k] for k in avail)
        g = scores.get("graph")
        if used <= 0 and not g:
            return 0.0, "LOW", "ALLOW", "LOW"
        risk = (sum(self.weights[k] * v for k, v in avail.items()) / used) if used > 0 else 0.0
        # A strong signal from any single trusted layer must not be diluted away by quiet layers.
        peak = max((scores.get(k) or 0.0) for k in ("rules", "ml") if k in avail) if avail else 0.0
        if peak >= 0.95 and len(avail) > 1:
            risk = max(risk, 0.5 * risk + 0.5 * peak)
        if g:
            risk = 1.0 - (1.0 - risk) * (1.0 - self.graph_boost * g)
        if hard:
            risk = max(risk, self.hard_floor)
        risk = min(1.0, max(0.0, risk))
        lvl = self.level(risk)
        cov = used / total if total else 0.0
        conf = "HIGH" if cov >= 0.85 else "MEDIUM" if cov >= 0.5 else "LOW"
        return risk, lvl, ACTIONS[lvl], conf
