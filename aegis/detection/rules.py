"""Configurable rule engine (Layer 1). Thresholds and weights live in configs/config.yaml."""
from __future__ import annotations

from aegis.schemas import ClickEvent


class RuleEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.w = cfg.get("weights", {})
        self.blocked_ips: set[str] = set(cfg.get("blocked_ips", []))

    def update(self, new: dict) -> None:
        """Apply a validated partial config live (no restart)."""
        new = dict(new)
        if "weights" in new:
            self.cfg["weights"] = {**self.cfg.get("weights", {}), **new.pop("weights")}
            self.w = self.cfg["weights"]
        if "blocked_ips" in new:
            self.blocked_ips = set(new["blocked_ips"]) | self.blocked_ips
        self.cfg.update({k: v for k, v in new.items() if k != "blocked_ips"})

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(ip)

    def evaluate(self, e: ClickEvent, f: dict[str, float]) -> tuple[float, list[str], bool]:
        """Return (score 0..1, fired rule names, hard_hit)."""
        c, w = self.cfg, self.w
        fired: dict[str, float] = {}
        if f["clicks_1m"] > c["max_clicks_per_min"]:
            fired["high_click_velocity"] = w.get("high_click_velocity", 0.9)
        if f["min_interval"] < c["min_interval_s"] and f["clicks_1m"] >= c["min_interval_clicks"]:
            fired["tiny_interval"] = w.get("tiny_interval", 0.9)
        if f["ua_bot_flag"] > 0:
            fired["bot_user_agent"] = w.get("bot_user_agent", 0.6)
        if e.ip_address in self.blocked_ips:
            fired["blocked_ip"] = w.get("blocked_ip", 1.0)
        if f["geo_user_countries"] > 1 and f["clicks_1h"] >= 3:
            fired["impossible_geo"] = w.get("impossible_geo", 0.7)
        if f["unique_users_per_device"] > c["max_users_per_device"]:
            fired["device_sharing"] = w.get("device_sharing", 0.8)
        if f["unique_devices_per_ip"] > c["max_devices_per_ip"]:
            fired["ip_device_fanin"] = w.get("ip_device_fanin", 0.8)
        if f["repeat_ad_ratio"] > c["repeat_ad_ratio"] and f["clicks_5m"] >= c["repeat_ad_min_clicks"]:
            fired["repeat_ad"] = w.get("repeat_ad", 0.7)
        score = max(fired.values(), default=0.0)
        hard = any(v >= 1.0 for v in fired.values())
        return score, sorted(fired), hard


NUMERIC_BOUNDS = {"max_clicks_per_min": (1, 10000), "min_interval_s": (0.0, 60.0), "min_interval_clicks": (1, 1000),
                  "max_users_per_device": (1, 1000), "max_devices_per_ip": (1, 1000), "repeat_ad_ratio": (0.0, 1.0),
                  "repeat_ad_min_clicks": (1, 10000)}


def validate_rules(update: dict) -> dict:
    """Validate a partial rules config; raises ValueError with a readable message."""
    clean: dict = {}
    for k, v in update.items():
        if k in NUMERIC_BOUNDS:
            lo, hi = NUMERIC_BOUNDS[k]
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f"{k} must be a number between {lo} and {hi}")
            clean[k] = v
        elif k == "weights":
            if not isinstance(v, dict) or any(not isinstance(x, (int, float)) or not 0 <= x <= 1 for x in v.values()):
                raise ValueError("weights must map rule names to numbers between 0 and 1")
            clean[k] = {str(a): float(b) for a, b in v.items()}
        elif k == "bot_user_agents":
            if not isinstance(v, list) or len(v) > 100 or any(not isinstance(x, str) or not 1 <= len(x) <= 40 for x in v):
                raise ValueError("bot_user_agents must be a list of up to 100 short strings")
            clean[k] = [x.lower() for x in v]
        elif k == "blocked_ips":
            if not isinstance(v, list) or len(v) > 5000 or any(not isinstance(x, str) or len(x) > 45 for x in v):
                raise ValueError("blocked_ips must be a list of IP strings")
            clean[k] = v
        else:
            raise ValueError(f"unknown rule setting '{k}'")
    return clean
