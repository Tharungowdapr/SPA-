"""Fraud-scenario tests: every simulated attack must be flagged by the full pipeline; legit traffic must not be blocked."""
import random

import pytest

from aegis.pipeline import Pipeline
from aegis.simulator.traffic import ATTACK_TYPES, UserPool, gen_attack, gen_normal
from aegis.store.db import Store

MIN_FLAG_RATE = {"burst": 0.9, "bot": 0.9, "click_farm": 0.6, "ip_rotation": 0.9, "device_farm": 0.9,
                 "low_and_slow": 0.6, "campaign_hopping": 0.3, "mimicry": 0.5}


@pytest.mark.parametrize("kind", ATTACK_TYPES)
def test_attack_detected_in_mixed_traffic(kind, settings, bundle):
    rng = random.Random(7)
    t0 = 1_800_000_000.0
    pool = UserPool(300, rng)
    ev = gen_normal(pool, rng, t0, 600) + gen_attack(kind, rng, t0 + 60, 300 if kind in ("low_and_slow", "mimicry", "campaign_hopping") else 90)
    ev.sort(key=lambda e: e.timestamp)
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    out = []
    for i in range(0, len(ev), 100):
        out += p.process_events(ev[i:i + 100])
    fraud = [d for d in out if d.label == 1]
    rate = sum(d.action in ("FLAG", "BLOCK", "REJECTED") for d in fraud) / len(fraud)
    assert rate >= MIN_FLAG_RATE[kind], f"{kind}: flagged {rate:.2f}"
    legit_blocked = [u for u in p.blocked_users if not u.startswith("U9")]
    assert not legit_blocked, f"false-positive blocks: {legit_blocked}"


def test_mixed_traffic_precision(settings, bundle):
    from aegis.simulator.traffic import build_episode
    ev = build_episode(4242, n_users=500)
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    out = []
    for i in range(0, len(ev), 200):
        out += p.process_events(ev[i:i + 200])
    flagged = [d for d in out if d.action in ("FLAG", "BLOCK", "REJECTED")]
    precision = sum(d.label == 1 for d in flagged) / len(flagged)
    recall = sum(d.label == 1 for d in flagged) / sum(d.label == 1 for d in out)
    assert precision > 0.97 and recall > 0.8
