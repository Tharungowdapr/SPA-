"""Server-side simulation runner. Events are generated server-side (identities and ground truth never come
from the browser) and fed into the same ingestion path as real traffic: submit -> bus -> pipeline."""
from __future__ import annotations

import asyncio
import random
import time
from typing import Callable

from aegis.schemas import ClickEvent, new_event_id
from aegis.simulator.traffic import (ATTACK_ALIASES, ATTACK_TYPES, ADS, UserPool, gen_attack, gen_normal)

KINDS = ["normal", "random"] + ATTACK_TYPES + list(ATTACK_ALIASES)
MAX_EVENTS = 50_000
MAX_DURATION = 600.0


def _kind(raw: str) -> str:
    k = raw.replace("-", "_").lower()
    if k not in KINDS:
        raise ValueError(f"unknown simulation '{raw}'")
    return k


def build_simulation(kind: str, pool: UserPool, rng: random.Random, t0: float, p: dict) -> list[ClickEvent]:
    kind = _kind(kind)
    duration = min(float(p.get("duration") or 60.0), MAX_DURATION)
    n_users = int(p.get("number_of_users") or 0)
    if kind in ("normal", "random"):
        users = pool.users[:n_users] if n_users else pool.users
        rate = float(p.get("click_rate") or 5.0)
        scale = max(0.1, rate * 75.0 / max(1, len(users)))
        if kind == "random":
            scale *= rng.uniform(0.5, 2.0)
            users = rng.sample(pool.users, max(1, int(len(pool.users) * rng.uniform(0.4, 1.0))))
        ev = gen_normal(pool, rng, t0, duration, rate_scale=scale, users=users)
    else:
        params = {"intensity": float(p.get("intensity") or 1.0)}
        if p.get("click_rate"):
            params["rate"] = float(p["click_rate"])
        if n_users:
            params["actors"] = n_users
        if p.get("target_ad"):
            params["ad"] = p["target_ad"] if p["target_ad"] in ADS else None
        if p.get("target_campaign"):
            params["campaign"] = p["target_campaign"]
        ev = gen_attack(kind, rng, t0, duration, **{k: v for k, v in params.items() if v is not None})
    if len(ev) > MAX_EVENTS:
        ev = ev[:MAX_EVENTS]
    return ev


class SimulationManager:
    def __init__(self, submit: Callable[[list[ClickEvent]], list[dict]], pool: UserPool, store, seed: int = 42):
        self.submit, self.pool, self.store = submit, pool, store
        self.rng = random.Random(seed)
        self.runs: dict[int, dict] = {}
        self.tasks: dict[int, asyncio.Task] = {}
        self._n = 0

    def _new_run(self, kind: str, params: dict, events: list[ClickEvent], sim_db_id: int | None = None) -> int:
        self._n += 1
        self.runs[self._n] = {"id": self._n, "kind": kind, "params": params, "total": len(events), "emitted": 0,
                              "rejected": 0, "state": "running", "started": time.time(), "db_id": sim_db_id}
        return self._n

    def start(self, kind: str, params: dict) -> dict:
        t0 = time.time() + 0.2
        events = build_simulation(kind, self.pool, self.rng, t0, params)
        db_id = self.store.add_simulation(_kind(kind), params, [e.model_dump() for e in events])
        rid = self._new_run(_kind(kind), params, events, db_id)
        self.tasks[rid] = asyncio.get_running_loop().create_task(self._play(rid, events, speed=1.0))
        return self.runs[rid]

    def replay(self, sim_db_id: int, speed: float = 1.0) -> dict:
        raw = self.store.get_simulation_events(sim_db_id)
        if raw is None:
            raise KeyError(sim_db_id)
        suffix = f"r{int(time.time()) % 100000}"
        t0 = min(e["timestamp"] for e in raw)
        now = time.time() + 0.2
        speed = max(0.1, min(float(speed), 100.0))
        events = []
        for e in raw:  # fresh identities so earlier blocks do not short-circuit the replay
            # EVENT TIME keeps its original spacing (so timing features are identical at any speed);
            # only the wall-clock emission is accelerated in _play.
            e = dict(e, event_id=new_event_id(), timestamp=now + (e["timestamp"] - t0),
                     user_id=e["user_id"] + suffix, device_id=e["device_id"] + suffix)
            events.append(ClickEvent(**e))
        rid = self._new_run("replay", {"source_sim": sim_db_id, "speed": speed}, events, sim_db_id)
        self.tasks[rid] = asyncio.get_running_loop().create_task(self._play(rid, events, speed=speed))
        return self.runs[rid]

    async def _play(self, rid: int, events: list[ClickEvent], speed: float) -> None:
        run = self.runs[rid]
        i, n = 0, len(events)
        wall0 = time.time()   # event timestamps are generated relative to ~now, so event-time zero == wall0
        try:
            while i < n:
                due = wall0 + (time.time() - wall0) * speed   # event-time that should have been emitted by now
                j = i
                while j < n and events[j].timestamp <= due and j - i < 1000:
                    j += 1
                if j > i:
                    acks = self.submit(events[i:j])
                    run["rejected"] += sum(1 for a in acks if a["status"] == "rejected")
                    run["emitted"] = j
                    i = j
                await asyncio.sleep(0.05)
            run["state"] = "finished"
        except asyncio.CancelledError:
            run["state"] = "stopped"
            raise
        except Exception as exc:  # noqa: BLE001
            run["state"] = f"error: {type(exc).__name__}"
        finally:
            run["ended"] = time.time()

    def stop(self) -> int:
        n = 0
        for rid, t in list(self.tasks.items()):
            if not t.done():
                t.cancel()
                n += 1
        return n

    def status(self) -> list[dict]:
        return sorted(self.runs.values(), key=lambda r: -r["id"])[:20]
