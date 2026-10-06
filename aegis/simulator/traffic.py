"""Click-traffic simulator: legitimate users + eight fraud behaviours.

Every generator returns time-sorted ``ClickEvent`` objects stamped relative to ``t0``.
Ground truth (``label``/``attack_type``) is attached here and used only for evaluation.
"""
from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass, field

from aegis.schemas import ClickEvent

ADS = [f"AD{100 + i}" for i in range(12)]
CAMPAIGNS = [f"C{10 + i}" for i in range(6)]
AD_CAMPAIGN = {ad: CAMPAIGNS[i % len(CAMPAIGNS)] for i, ad in enumerate(ADS)}
PUBLISHERS = [f"PUB{i}" for i in range(6)]
POSITIONS = ["banner_top", "sidebar", "inline", "footer", "interstitial"]
REFERRERS = ["news.example", "blog.example", "video.example", "shop.example", "search.example"]
COUNTRIES = {
    "IN": (12.97, 77.59), "US": (37.77, -122.42), "GB": (51.50, -0.12), "DE": (52.52, 13.40),
    "BR": (-23.55, -46.63), "VN": (21.03, 105.85), "RU": (55.75, 37.61), "NG": (6.52, 3.37),
    "ID": (-6.20, 106.84),
}
HUMAN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]
BOT_UA = ["curl/8.4.0", "python-requests/2.31.0", "HeadlessChrome/120.0.0.0", "Scrapy/2.11.0", "Wget/1.21"]

ATTACK_TYPES = [
    "burst", "bot", "click_farm", "ip_rotation", "device_farm",
    "low_and_slow", "campaign_hopping", "mimicry",
]
SLOW_ATTACKS = {"low_and_slow", "mimicry", "campaign_hopping"}  # need longer windows to accumulate evidence
# Aliases used by the public simulation API
ATTACK_ALIASES = {"distributed": "click_farm", "farm": "click_farm", "rapid": "burst"}

_seq = itertools.count(1)


def _eid(rng: random.Random) -> str:
    return "evt_%012x" % rng.getrandbits(48)


def rand_ip(rng: random.Random, prefix: str | None = None) -> str:
    if prefix:
        return f"{prefix}.{rng.randint(2, 250)}"
    return f"{rng.choice([11, 23, 37, 45, 59, 77, 91, 103, 122, 151, 176, 185, 201, 213])}." \
           f"{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 250)}"


def rand_prefix(rng: random.Random) -> str:
    return f"{rng.choice([45, 91, 103, 185])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}"


@dataclass
class Identity:
    user_id: str
    device_id: str
    ip: str
    ua: str
    country: str
    lat: float
    lon: float
    account_age: float
    publisher: str = "PUB0"
    fav_ads: list = field(default_factory=list)
    power: bool = False


def _geo(rng: random.Random, country: str) -> tuple[float, float]:
    lat, lon = COUNTRIES[country]
    return lat + rng.uniform(-2, 2), lon + rng.uniform(-2, 2)


def make_identity(rng: random.Random, uid: str, did: str, *, country: str | None = None,
                  ip: str | None = None, ua: str | None = None, age: float | None = None,
                  publisher: str | None = None) -> Identity:
    if age is None:  # legit population: ~20% genuinely new accounts, the rest long-lived
        age = rng.uniform(1, 60) if rng.random() < 0.20 else min(3000.0, math.exp(rng.gauss(5.5, 1.0)))
    country = country or rng.choices(list(COUNTRIES), weights=[60, 12, 6, 5, 5, 3, 3, 3, 3])[0]
    lat, lon = _geo(rng, country)
    return Identity(uid, did, ip or rand_ip(rng), ua or rng.choice(HUMAN_UA), country, lat, lon,
                    age,
                    publisher or rng.choice(PUBLISHERS), rng.sample(ADS, 3), rng.random() < 0.04)


class UserPool:
    """Legitimate ad-network users (stable identities, ~5% share a NAT IP)."""

    def __init__(self, n: int, rng: random.Random):
        self.rng = rng
        self.users: list[Identity] = []
        for i in range(n):
            # ~5% of users share a home/office NAT IP with one earlier user (small groups, realistic)
            ip = rng.choice(self.users[:i]).ip if i and rng.random() < 0.05 else None
            self.users.append(make_identity(rng, f"U{i + 1:03d}", f"D{i + 1:03d}", ip=ip))
        self.by_id = {u.user_id: u for u in self.users}


def _event(rng, ident: Identity, ts: float, ad: str, *, label: int, attack: str,
           ip: str | None = None, session: str | None = None, campaign: str | None = None,
           publisher: str | None = None, device: str | None = None, user: str | None = None,
           country: str | None = None) -> ClickEvent:
    return ClickEvent(
        event_id=_eid(rng), timestamp=ts, user_id=user or ident.user_id, ad_id=ad,
        campaign_id=campaign or AD_CAMPAIGN[ad], publisher_id=publisher or ident.publisher,
        session_id=session or f"S{ident.user_id[-4:]}", ip_address=ip or ident.ip,
        device_id=device or ident.device_id, user_agent=ident.ua, country=country or ident.country,
        latitude=ident.lat, longitude=ident.lon, referrer=rng.choice(REFERRERS),
        click_position=rng.choice(POSITIONS), page_id=f"P{rng.randint(1, 40)}",
        account_age_days=round(ident.account_age, 1), label=label, attack_type=attack,
    )


# ---------------------------------------------------------------- legitimate traffic
def gen_normal(pool: UserPool, rng: random.Random, t0: float, duration: float,
               rate_scale: float = 1.0, users: list[Identity] | None = None) -> list[ClickEvent]:
    out: list[ClickEvent] = []
    for u in users or pool.users:
        mean_gap = 14.0 if u.power else 75.0
        t = rng.uniform(0, mean_gap * 2) / max(rate_scale, 1e-3)
        sess = 0
        while t < duration:
            ad = rng.choices(u.fav_ads + [rng.choice(ADS)], weights=[5, 3, 2, 1])[0]
            out.append(_event(rng, u, t0 + t, ad, label=0, attack="normal", session=f"S{u.user_id[-4:]}_{sess}"))
            if rng.random() < 0.05:  # accidental double click
                out.append(_event(rng, u, t0 + t + rng.uniform(0.8, 3.0), ad, label=0, attack="normal",
                                  session=f"S{u.user_id[-4:]}_{sess}"))
            gap = min(900.0, max(3.0, math.exp(rng.gauss(math.log(mean_gap), 0.8)))) / max(rate_scale, 1e-3)
            t += gap
            if gap > 600:
                sess += 1
    return out


# ---------------------------------------------------------------- attacks
def _atk_age(rng: random.Random) -> float:
    """Fraudsters mix fresh throw-away accounts with aged/compromised ones (removes the age shortcut)."""
    return rng.uniform(1, 60) if rng.random() < 0.5 else min(3000.0, math.exp(rng.gauss(5.0, 1.0)))


def _attacker(rng, **kw) -> Identity:
    n = next(_seq)
    return make_identity(rng, f"U9{n:04d}", f"D9{n:04d}", **kw)


def _burst(rng, t0, dur, p):
    rate = p.get("rate") or 20.0 * p["intensity"]
    n = max(30, int(min(dur, 12) * rate))
    a = _attacker(rng, age=_atk_age(rng))
    ad = p.get("ad") or rng.choice(ADS)
    t, out = 0.0, []
    for _ in range(n):
        t += rng.expovariate(rate)
        out.append(_event(rng, a, t0 + t, ad, label=1, attack="burst"))
    return out


def _bot(rng, t0, dur, p):
    rate = p.get("rate") or 1.0 * p["intensity"]
    a = _attacker(rng, ua=rng.choice(BOT_UA) if rng.random() < 0.7 else None, age=_atk_age(rng))
    ad = p.get("ad") or rng.choice(ADS)
    gap = 1.0 / rate
    n = int(dur * rate)
    return [_event(rng, a, t0 + i * gap * rng.uniform(0.98, 1.02), ad, label=1, attack="bot") for i in range(n)]


def _click_farm(rng, t0, dur, p):
    n_act = int(p.get("actors") or (30 * p["intensity"] + 10))
    prefixes = [rand_prefix(rng) for _ in range(3)]
    camp_ads = [a for a in ADS if AD_CAMPAIGN[a] == (p.get("campaign") or rng.choice(CAMPAIGNS))] or ADS[:2]
    shared_uas = [rng.choice(HUMAN_UA) for _ in range(3)]
    country = rng.choice(["VN", "ID", "NG"])
    out = []
    for _ in range(n_act):
        a = _attacker(rng, ip=rand_ip(rng, rng.choice(prefixes)), ua=rng.choice(shared_uas), country=country,
                      age=_atk_age(rng), publisher="PUBX")
        t = rng.uniform(0, 10)
        while t < dur:
            out.append(_event(rng, a, t0 + t, rng.choice(camp_ads), label=1, attack="click_farm"))
            t += rng.uniform(4, 12)
    return out


def _ip_rotation(rng, t0, dur, p):
    a = _attacker(rng, age=_atk_age(rng))
    ad = p.get("ad") or rng.choice(ADS)
    countries = rng.sample(list(COUNTRIES), 3)
    out, t = [], 0.0
    while t < dur:
        c = rng.choice(countries)
        out.append(_event(rng, a, t0 + t, ad, label=1, attack="ip_rotation", ip=rand_ip(rng), country=c))
        t += rng.uniform(0.5, 2.0) / p["intensity"]
    return out


def _device_farm(rng, t0, dur, p):
    n_dev = int(p.get("actors") or (25 * p["intensity"] + 8))
    ips = [rand_ip(rng) for _ in range(3)]
    ad = p.get("ad") or rng.choice(ADS)
    out = []
    for _ in range(n_dev):
        a = _attacker(rng, ip=rng.choice(ips), age=_atk_age(rng), publisher="PUBX")
        t = rng.uniform(0, 8)
        while t < dur:
            out.append(_event(rng, a, t0 + t, ad, label=1, attack="device_farm"))
            t += rng.uniform(5, 15)
    return out


def _low_and_slow(rng, t0, dur, p):
    a = _attacker(rng, age=_atk_age(rng))
    ad = p.get("ad") or rng.choice(ADS)
    out, t = [], 0.0
    while t < dur:
        out.append(_event(rng, a, t0 + t, ad, label=1, attack="low_and_slow"))
        t += rng.uniform(6, 14) / p["intensity"]
    return out


def _campaign_hopping(rng, t0, dur, p):
    prefix = rand_prefix(rng)
    group = [_attacker(rng, ip=rand_ip(rng, prefix), age=_atk_age(rng)) for _ in range(6)]
    out, t = [], 0.0
    while t < dur:
        camp = rng.choice(CAMPAIGNS)
        ads = [a for a in ADS if AD_CAMPAIGN[a] == camp]
        hop_end = t + rng.uniform(20, 40)
        while t < hop_end and t < dur:
            out.append(_event(rng, rng.choice(group), t0 + t, rng.choice(ads), label=1, attack="campaign_hopping"))
            t += rng.uniform(1.5, 4.0) / p["intensity"]
    return out


def _mimicry(rng, t0, dur, p):
    ring_users = [f"U9{next(_seq):04d}" for _ in range(5)]
    devices = [f"D9{next(_seq):04d}" for _ in range(3)]
    ad = p.get("ad") or rng.choice(ADS)
    out = []
    for uid in ring_users:
        a = make_identity(rng, uid, rng.choice(devices), age=_atk_age(rng))
        t = rng.uniform(0, 30)
        while t < dur:
            out.append(_event(rng, a, t0 + t, ad, label=1, attack="mimicry", device=rng.choice(devices)))
            t += min(300, max(4, math.exp(rng.gauss(math.log(30), 0.7)))) / p["intensity"]
    return out


_ATTACKS = {
    "burst": _burst, "bot": _bot, "click_farm": _click_farm, "ip_rotation": _ip_rotation,
    "device_farm": _device_farm, "low_and_slow": _low_and_slow,
    "campaign_hopping": _campaign_hopping, "mimicry": _mimicry,
}


def gen_attack(kind: str, rng: random.Random, t0: float, duration: float = 60.0, **params) -> list[ClickEvent]:
    kind = ATTACK_ALIASES.get(kind, kind)
    if kind not in _ATTACKS:
        raise ValueError(f"unknown attack '{kind}'. choose from {ATTACK_TYPES}")
    params.setdefault("intensity", 1.0)
    params["intensity"] = max(0.1, float(params["intensity"] or 1.0))
    ev = _ATTACKS[kind](rng, t0, float(duration), params)
    ev.sort(key=lambda e: e.timestamp)
    return ev


def build_episode(seed: int, n_users: int = 250, duration: float = 900.0, t0: float = 1_750_000_000.0,
                  attacks: list[str] | None = None, repeats: int = 1,
                  slow_repeats: int | None = None) -> list[ClickEvent]:
    """Mixed legit + attack traffic, time-sorted. Deterministic for a seed."""
    rng = random.Random(seed)
    pool = UserPool(n_users, rng)
    events = gen_normal(pool, rng, t0, duration)
    for kind in attacks or ATTACK_TYPES:
        for _ in range(slow_repeats if (slow_repeats and kind in SLOW_ATTACKS) else repeats):
            dur = rng.uniform(240, 420) if kind in SLOW_ATTACKS else rng.uniform(60, 180)
            start = rng.uniform(0, max(1.0, duration - dur))
            events += gen_attack(kind, rng, t0 + start, dur)
    events.sort(key=lambda e: e.timestamp)
    return events
