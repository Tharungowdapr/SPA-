"""Stateful streaming feature engineering (Flink-style keyed sliding windows, event-time).

State is held per key (user, device, ip, campaign) in time-ordered windows. Each ``update`` call is
amortised O(log n + k) and returns the feature dict for the incoming click.
"""
from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from aegis.schemas import ClickEvent

FEATURES = [
    "clicks_10s", "clicks_1m", "clicks_5m", "clicks_1h",
    "avg_interval", "min_interval", "interval_std", "interval_cv", "timing_entropy", "burst_score",
    "unique_ads_1h", "repeat_ad_ratio",
    "device_clicks_1m", "unique_users_per_device", "unique_ips_per_device",
    "ip_clicks_1m", "unique_devices_per_ip", "unique_users_per_ip",
    "campaign_click_share_5m", "geo_user_countries", "geo_ip_countries",
    "ua_bot_flag", "account_age_days",
]

FEATURE_LABELS = {
    "clicks_10s": "Clicks in last 10s", "clicks_1m": "Click velocity (1 min)",
    "clicks_5m": "Clicks in last 5 min", "clicks_1h": "Clicks in last hour",
    "avg_interval": "Average click interval", "min_interval": "Shortest click interval",
    "interval_std": "Click interval variability", "interval_cv": "Click timing regularity (CV)",
    "timing_entropy": "Timing entropy", "burst_score": "Burst intensity",
    "unique_ads_1h": "Distinct ads clicked (1h)", "repeat_ad_ratio": "Repeated-ad ratio",
    "device_clicks_1m": "Device clicks (1 min)", "unique_users_per_device": "Users sharing device",
    "unique_ips_per_device": "IPs used by device", "ip_clicks_1m": "IP clicks (1 min)",
    "unique_devices_per_ip": "Devices behind IP", "unique_users_per_ip": "Users behind IP",
    "campaign_click_share_5m": "Campaign traffic share", "geo_user_countries": "Countries per user (1h)",
    "geo_ip_countries": "Countries per IP (1h)", "ua_bot_flag": "Automation user-agent",
    "account_age_days": "Account age (days)",
}

_BINS = [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600]
_DEFAULT_BOT_TOKENS = ["curl", "python-requests", "headless", "bot", "spider", "scrapy", "selenium", "wget"]


class _Win:
    __slots__ = ("ts", "vals")

    def __init__(self) -> None:
        self.ts: list[float] = []
        self.vals: list = []

    def add(self, t: float, v) -> None:
        if self.ts and t < self.ts[-1]:  # late event
            i = bisect_right(self.ts, t)
            self.ts.insert(i, t)
            self.vals.insert(i, v)
        else:
            self.ts.append(t)
            self.vals.append(v)

    def trim(self, now: float, horizon: float, cap: int) -> None:
        i = bisect_left(self.ts, now - horizon)
        extra = len(self.ts) - i - cap
        if extra > 0:
            i += extra
        if i:
            del self.ts[:i]
            del self.vals[:i]

    def count(self, since: float) -> int:
        return len(self.ts) - bisect_left(self.ts, since)

    def since(self, since: float, scan: int = 400) -> list:
        i = bisect_left(self.ts, since)
        return self.vals[max(i, len(self.vals) - scan):]


def _entropy(intervals: list[float]) -> float:
    if len(intervals) < 4:
        return 2.5  # not enough evidence: neutral/high
    bins = Counter(bisect_left(_BINS, x) for x in intervals)
    n = len(intervals)
    return -sum((c / n) * math.log2(c / n) for c in bins.values())


class FeatureEngine:
    def __init__(self, max_window_events: int = 2000, bot_tokens: list[str] | None = None):
        self.cap = max_window_events
        self.bot_tokens = [t.lower() for t in (bot_tokens or _DEFAULT_BOT_TOKENS)]
        self.user: dict[str, _Win] = defaultdict(_Win)
        self.device: dict[str, _Win] = defaultdict(_Win)
        self.ip: dict[str, _Win] = defaultdict(_Win)
        self.campaign: dict[str, _Win] = defaultdict(_Win)
        self.glob = _Win()
        self._n = 0

    # -------------------------------------------------------------- public
    def update(self, e: ClickEvent) -> dict[str, float]:
        now = e.timestamp
        h = 3600.0
        u, d, p, c = self.user[e.user_id], self.device[e.device_id], self.ip[e.ip_address], self.campaign[e.campaign_id]
        u.add(now, (e.ad_id, e.device_id, e.ip_address, e.country))
        d.add(now, (e.user_id, e.ip_address))
        p.add(now, (e.device_id, e.user_id, e.country))
        c.add(now, e.user_id)
        self.glob.add(now, None)
        for w in (u, d, p, c, self.glob):
            w.trim(now, h, self.cap)

        # --- user velocity & timing
        c10, c1m, c5m, c1h = u.count(now - 10), u.count(now - 60), u.count(now - 300), len(u.ts)
        recent = u.ts[-21:]
        iv = [b - a for a, b in zip(recent, recent[1:])]
        if iv:
            avg = sum(iv) / len(iv)
            std = math.sqrt(sum((x - avg) ** 2 for x in iv) / len(iv))
            mn = min(iv)
        else:
            avg, std, mn = 300.0, 50.0, 300.0
        uv = u.since(now - h)
        ads5 = Counter(v[0] for v in u.since(now - 300))
        n5 = sum(ads5.values())
        repeat = (max(ads5.values()) / n5) if n5 >= 3 else 0.0
        dv, pv = d.since(now - h), p.since(now - h)

        f = {
            "clicks_10s": c10, "clicks_1m": c1m, "clicks_5m": c5m, "clicks_1h": c1h,
            "avg_interval": avg, "min_interval": mn, "interval_std": std,
            "interval_cv": (std / avg) if avg > 0 and len(iv) >= 3 else 1.0,
            "timing_entropy": _entropy(iv), "burst_score": c10 / (1.0 + c5m / 30.0),
            "unique_ads_1h": len({v[0] for v in uv}), "repeat_ad_ratio": repeat,
            "device_clicks_1m": d.count(now - 60),
            "unique_users_per_device": len({v[0] for v in dv}),
            "unique_ips_per_device": len({v[1] for v in dv}),
            "ip_clicks_1m": p.count(now - 60),
            "unique_devices_per_ip": len({v[0] for v in pv}),
            "unique_users_per_ip": len({v[1] for v in pv}),
            "campaign_click_share_5m": c.count(now - 300) / max(1, self.glob.count(now - 300)),
            "geo_user_countries": len({v[3] for v in uv}),
            "geo_ip_countries": len({v[2] for v in pv}),
            "ua_bot_flag": float(self.is_bot_ua(e.user_agent)),
            "account_age_days": e.account_age_days,
        }
        self._n += 1
        if self._n % 5000 == 0:
            self._gc(now)
        return {k: float(f[k]) for k in FEATURES}

    def is_bot_ua(self, ua: str) -> bool:
        ua = (ua or "").lower()
        return (not ua) or any(t in ua for t in self.bot_tokens)

    def history(self, user_id: str, limit: int = 50) -> list[dict]:
        w = self.user.get(user_id)
        if not w:
            return []
        return [{"ts": t, "ad": v[0], "device": v[1], "country": v[3]} for t, v in zip(w.ts[-limit:], w.vals[-limit:])]

    def reset(self) -> None:
        self.__init__(self.cap, self.bot_tokens)

    # -------------------------------------------------------------- internals
    def _gc(self, now: float) -> None:
        for table in (self.user, self.device, self.ip, self.campaign):
            for k in [k for k, w in table.items() if not w.ts or w.ts[-1] < now - 7200]:
                del table[k]


def vectorize(feats: dict[str, float]) -> list[float]:
    return [feats[k] for k in FEATURES]
