"""Labeled dataset construction: simulator episodes -> streaming features (same code path as production)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd

from aegis.config import ROOT
from aegis.detection.graph import GraphEngine
from aegis.detection.rules import RuleEngine
from aegis.simulator.traffic import ATTACK_TYPES, build_episode
from aegis.streaming.features import FEATURES, FeatureEngine

META_COLS = ["event_id", "timestamp", "user_id", "campaign_id", "label", "attack_type", "episode"]
SEEN_ATTACKS = ["burst", "bot", "click_farm", "device_farm", "campaign_hopping"]
UNSEEN_ATTACKS = ["ip_rotation", "low_and_slow", "mimicry"]


def episode_frame(seed: int, rules_cfg: dict, n_users: int = 800, duration: float = 900.0,
                  repeats: int = 1, slow_repeats: int | None = None,
                  attacks: list[str] | None = None) -> pd.DataFrame:
    events = build_episode(seed, n_users=n_users, duration=duration, repeats=repeats,
                           slow_repeats=slow_repeats, attacks=attacks if attacks is not None else ATTACK_TYPES)
    fe, ge, re_ = FeatureEngine(bot_tokens=rules_cfg.get("bot_user_agents")), GraphEngine(), RuleEngine(rules_cfg)
    rows = []
    for e in events:
        f = fe.update(e)
        ge.update(e)
        gs, _ = ge.score(e)
        rs, _, hard = re_.evaluate(e, f)
        f.update(event_id=e.event_id, timestamp=e.timestamp, user_id=e.user_id, campaign_id=e.campaign_id,
                 label=e.label, attack_type=e.attack_type, episode=seed, rule_score=rs, rule_hard=float(hard),
                 graph_score=gs)
        rows.append(f)
    return pd.DataFrame(rows)


def build_frames(rules_cfg: dict, seeds: list[int], cache_dir: Path | None = None, **kw) -> pd.DataFrame:
    key = hashlib.md5(json.dumps([seeds, kw, rules_cfg], sort_keys=True, default=str).encode()).hexdigest()[:10]
    cache = (cache_dir or ROOT / "data" / "processed") / f"frames_{key}.pkl"
    if cache.exists():
        return pd.read_pickle(cache)
    df = pd.concat([episode_frame(s, rules_cfg, **kw) for s in seeds], ignore_index=True)
    cache.parent.mkdir(parents=True, exist_ok=True)
    df.to_pickle(cache)
    return df


def standard_splits(rules_cfg: dict, quick: bool = False) -> dict[str, pd.DataFrame]:
    """train / val / test (all attacks) + train_seen / test_unseen for the generalisation experiment."""
    n = 400 if quick else 800
    tr = list(range(100, 103 if quick else 106))
    out = {
        "train": build_frames(rules_cfg, tr, n_users=n, slow_repeats=3),
        "val": build_frames(rules_cfg, [200, 201][: 1 if quick else 2], n_users=n, slow_repeats=3),
        "test": build_frames(rules_cfg, [300, 301, 302][: 1 if quick else 3], n_users=1500 if not quick else 600),
        "train_seen": build_frames(rules_cfg, tr, n_users=n, attacks=SEEN_ATTACKS),
    }
    return out
