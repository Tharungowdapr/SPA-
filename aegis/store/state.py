"""Low-latency shared state: block-lists, rate limiting, active users, recent-click counters, dashboard stats.

MemoryState is the default. RedisState (REDIS_URL / state.redis_url) shares the same state across restarts and
workers. Every Redis call is guarded: on failure the layer reports unhealthy and the caller keeps using its local state.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from typing import Any

KINDS = ("user", "device", "ip")


class MemoryState:
    mode = "memory"

    def __init__(self, fallback_reason: str = ""):
        self.fallback_reason = fallback_reason
        self.healthy = True
        self.last_error = ""
        self._blocks: dict[str, set] = defaultdict(set)
        self._active: dict[str, float] = {}
        self._clicks: dict[str, list] = {}
        self._rl: dict[str, list] = {}
        self._stats: dict | None = None

    def block_add(self, kind: str, eid: str) -> None:
        self._blocks[kind].add(eid)

    def block_remove(self, kind: str, eid: str) -> None:
        self._blocks[kind].discard(eid)

    def blocked(self, kind: str) -> set | None:
        return set(self._blocks[kind])

    def touch_active(self, user: str, ts: float) -> None:
        self._active[user] = ts

    def active_count(self, window: float = 60.0) -> int:
        cut = time.time() - window
        for u in [u for u, t in self._active.items() if t < cut]:
            del self._active[u]
        return len(self._active)

    def incr_click(self, user: str, window: float = 60.0) -> int:
        now = time.time()
        w = [t for t in self._clicks.get(user, []) if now - t < window] + [now]
        self._clicks[user] = w
        return len(w)

    def rate_allow(self, key: str, per_minute: int) -> bool:
        b = self._rl.setdefault(f"{key}:{int(time.time() // 60)}", [0])
        b[0] += 1
        if len(self._rl) > 5000:
            self._rl.clear()
        return b[0] <= per_minute

    def publish_stats(self, stats: dict) -> None:
        self._stats = stats

    def get_stats(self) -> dict | None:
        return self._stats

    def ping(self) -> bool:
        return True

    def live_size(self) -> int:
        return len(self._active) + len(self._clicks) + len(self._rl) + sum(len(v) for v in self._blocks.values())

    def clear_live(self) -> int:
        """Drop active users, click counters, rate-limit buckets and published stats."""
        n = self.live_size()
        self._active.clear()
        self._clicks.clear()
        self._rl.clear()
        self._stats = None
        return n

    def stats(self) -> dict:
        return {"mode": self.mode, "healthy": True, "fallback_reason": self.fallback_reason}


class RedisState:
    mode = "redis"
    P = "aegis:"

    def __init__(self, url: str):
        import redis  # type: ignore
        self.r = redis.from_url(url, decode_responses=True, socket_timeout=1.0, socket_connect_timeout=2.0)
        self.r.ping()  # raises if unreachable -> make_state falls back
        self.healthy, self.last_error, self.fallback_reason = True, "", ""

    def _g(self, fn, default: Any = None):
        try:
            out = fn()
            self.healthy = True
            return out
        except Exception as exc:  # noqa: BLE001 - Redis down must never stop detection
            self.healthy, self.last_error = False, f"{type(exc).__name__}: {str(exc)[:100]}"
            return default

    def block_add(self, kind: str, eid: str) -> None:
        self._g(lambda: self.r.sadd(f"{self.P}blocked:{kind}", eid))

    def block_remove(self, kind: str, eid: str) -> None:
        self._g(lambda: self.r.srem(f"{self.P}blocked:{kind}", eid))

    def blocked(self, kind: str) -> set | None:
        return self._g(lambda: set(self.r.smembers(f"{self.P}blocked:{kind}")), None)

    def touch_active(self, user: str, ts: float) -> None:
        self._g(lambda: self.r.zadd(f"{self.P}active", {user: ts}))

    def active_count(self, window: float = 60.0) -> int:
        def run() -> int:
            self.r.zremrangebyscore(f"{self.P}active", 0, time.time() - window)
            return int(self.r.zcard(f"{self.P}active"))
        return self._g(run, 0)

    def incr_click(self, user: str, window: float = 60.0) -> int:
        def run() -> int:
            k = f"{self.P}clicks:{user}:{int(time.time() // window)}"
            pipe = self.r.pipeline()
            pipe.incr(k)
            pipe.expire(k, int(window * 2))
            return int(pipe.execute()[0])
        return self._g(run, 0)

    def rate_allow(self, key: str, per_minute: int) -> bool:
        def run() -> bool:
            k = f"{self.P}rl:{key}:{int(time.time() // 60)}"
            n = self.r.incr(k)
            if n == 1:
                self.r.expire(k, 70)
            return n <= per_minute
        return self._g(run, True)  # fail-open: availability over strictness if Redis is down

    def publish_stats(self, stats: dict) -> None:
        self._g(lambda: self.r.set(f"{self.P}stats", json.dumps(stats), ex=10))

    def get_stats(self) -> dict | None:
        raw = self._g(lambda: self.r.get(f"{self.P}stats"))
        return json.loads(raw) if raw else None

    def ping(self) -> bool:
        return bool(self._g(self.r.ping, False))

    def live_size(self) -> int:
        def run() -> int:
            prefix = f"{self.P}blocked:"
            return sum(1 for k in self.r.scan_iter(match=f"{self.P}*") if not str(k).startswith(prefix))
        return self._g(run, 0)

    def clear_live(self) -> int:
        """Delete the shared live-tracking keys, keeping the block-list sets intact."""
        def run() -> int:
            keys = list(self.r.scan_iter(match=f"{self.P}*"))
            keys = [k for k in keys if not str(k).startswith(f"{self.P}blocked:")]
            return int(self.r.delete(*keys)) if keys else 0
        return self._g(run, 0)

    def stats(self) -> dict:
        return {"mode": self.mode, "healthy": self.healthy, "last_error": self.last_error}


def make_state(url: str = ""):
    """Redis if configured and reachable, else in-memory (graceful degradation)."""
    if url:
        try:
            return RedisState(url)
        except Exception as exc:  # noqa: BLE001
            return MemoryState(f"redis unavailable: {type(exc).__name__}: {exc}"[:200])
    return MemoryState()


class StateRateLimiter:
    """Fixed-window per-minute limiter backed by shared state (works across workers when Redis is used)."""

    def __init__(self, state, per_minute: int):
        self.state, self.per_minute = state, per_minute

    def allow(self, key: str, cost: float = 1.0) -> bool:
        return self.state.rate_allow(key, self.per_minute)
