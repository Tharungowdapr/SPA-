"""Classify suspicious traffic into named patterns.

Patterns describe what a group of HIGH / CRITICAL clicks has in common, so an analyst can recognise a
recurring scheme instead of reading raw features. A pattern never blocks anything on its own: it only
labels. A match needs at least MIN_CONDITIONS conditions to hold, otherwise every click would match
everything.
"""
from __future__ import annotations

import re
from typing import Any

MIN_CONDITIONS = 2
MAX_PATTERNS = 200
MAX_NAME = 60
MAX_TEXT = 400
SIGNATURES: list[dict] = [
    {"key": "click_velocity", "label": "Very high click rate",
     "test": lambda f, e: (f.get("clicks_1m") or 0) >= 25 or (f.get("clicks_10s") or 0) >= 10,
     "text": "dozens of clicks inside a minute"},
    {"key": "tight_interval", "label": "Machine-like timing",
     "test": lambda f, e: 0 <= (f.get("min_interval") or 9) < 0.35,
     "text": "gaps between clicks too regular and too short to be human"},
    {"key": "interval_regularity", "label": "Regular interval pattern",
     "test": lambda f, e: (f.get("interval_cv") or 1) < 0.3 and (f.get("clicks_1m") or 0) >= 5,
     "text": "click timing almost perfectly regular, like a script"},
    {"key": "bot_agent", "label": "Automation user-agent",
     "test": lambda f, e: bool(f.get("ua_bot_flag")),
     "text": "the browser string admits it is automated"},
    {"key": "device_farm", "label": "Many accounts per device",
     "test": lambda f, e: (f.get("unique_users_per_device") or 0) >= 3,
     "text": "several accounts clicking from one device"},
    {"key": "ip_fanin", "label": "Many devices per address",
     "test": lambda f, e: (f.get("unique_devices_per_ip") or 0) >= 4,
     "text": "many devices sharing one network address"},
    {"key": "geo_spread", "label": "Multiple countries at once",
     "test": lambda f, e: (f.get("geo_user_countries") or 1) >= 2,
     "text": "the same account seen in more than one country within the hour"},
    {"key": "repeat_ad", "label": "Same advert over and over",
     "test": lambda f, e: (f.get("repeat_ad_ratio") or 0) >= 0.8 and (f.get("clicks_5m") or 0) >= 8,
     "text": "nearly every click lands on the same advert"},
    {"key": "new_account", "label": "Very new account",
     "test": lambda f, e: (f.get("account_age_days") or 999) <= 1,
     "text": "the account was created within the last day"},
    {"key": "graph_cluster", "label": "Linked to a cluster",
     "test": lambda f, e: (e.get("graph_users") or 0) >= 5 or (e.get("graph_devices") or 0) >= 5,
     "text": "shares devices or addresses with a known group"},
    {"key": "blocked_entity", "label": "Already blocked",
     "test": lambda f, e: bool(e.get("blocked")),
     "text": "kept clicking after being blocked"},
]

_HTML = re.compile(r"<[^>]+>|(?:javascript|data):", re.I)


def clean_text(v: Any, limit: int = MAX_TEXT) -> str:
    """Strip anything that could render as markup, and cap the length."""
    s = "" if v is None else str(v)
    s = _HTML.sub("", s).replace("\x00", "").strip()
    return s[:limit]


def validate_signature(sig: dict) -> dict:
    """Validate an analyst-authored signature. Raises ValueError with a readable message."""
    if not isinstance(sig, dict):
        raise ValueError("signature must be an object")
    keys = sig.get("conditions")
    if not isinstance(keys, list) or not keys:
        raise ValueError("conditions must be a non-empty list")
    if len(keys) > 20:
        raise ValueError("at most 20 conditions are allowed")
    out = []
    for c in keys:
        if not isinstance(c, dict):
            raise ValueError("each condition must be an object")
        field = clean_text(c.get("field"), 40)
        if not field or not re.fullmatch(r"[a-z0-9_]+", field):
            raise ValueError(f"condition field '{field}' is not a known feature name")
        op = str(c.get("op") or "")
        if op not in (">=", "<=", "==", ">", "<"):
            raise ValueError(f"unsupported operator '{op}'")
        try:
            value = float(c.get("value"))
        except (TypeError, ValueError):
            raise ValueError(f"condition on '{field}' needs a numeric value") from None
        out.append({"field": field, "op": op, "value": value})
    if len(out) < MIN_CONDITIONS:
        raise ValueError(f"a pattern needs at least {MIN_CONDITIONS} conditions")
    return {"conditions": out, "min_match": max(int(sig.get("min_match") or len(out)), MIN_CONDITIONS)}


def validate_pattern(name: str, description: str, signature: dict, action: str = "label") -> dict:
    name = clean_text(name, MAX_NAME)
    if len(name) < 3:
        raise ValueError("name must be at least 3 characters")
    if action not in ("label", "alert"):
        raise ValueError("action must be 'label' or 'alert' (patterns never block on their own)")
    return {"name": name, "description": clean_text(description), "action": action,
            "signature": validate_signature(signature)}


def builtins() -> list[dict]:
    return [{"key": s["key"], "label": s["label"], "text": s["text"]} for s in SIGNATURES]


def matches(features: dict | None, extra: dict | None = None) -> list[dict]:
    """Which built-in conditions hold for one decision."""
    f, e = dict(features or {}), dict(extra or {})
    hit = []
    for s in SIGNATURES:
        try:
            if s["test"](f, e):
                hit.append({"key": s["key"], "label": s["label"], "text": s["text"]})
        except Exception:  # noqa: BLE001 - a bad feature must never break classification
            continue
    return hit


def _cond_ok(feature: float, op: str, value: float) -> bool:
    return ({"<": feature < value, "<=": feature <= value, ">": feature > value,
             ">=": feature >= value, "==": feature == value}[op])


def signature_matches(signature: dict, features: dict | None) -> tuple[bool, list[str]]:
    """Evaluate an analyst signature against one feature set."""
    f = dict(features or {})
    conds = (signature or {}).get("conditions") or []
    met = []
    for c in conds:
        try:
            if _cond_ok(float(f.get(c["field"], float("nan"))), c["op"], float(c["value"])):
                met.append(f"{c['field']} {c['op']} {c['value']:g}")
        except (TypeError, ValueError):
            continue
    need = max(int((signature or {}).get("min_match") or len(conds)), MIN_CONDITIONS)
    return len(met) >= need, met


def classify(features: dict | None = None, extra: dict | None = None) -> dict:
    """Label one suspicious decision. Requires at least MIN_CONDITIONS conditions to agree."""
    hit = matches(features, extra)
    label = ", ".join(h["label"].lower() for h in hit[:3]) if len(hit) >= MIN_CONDITIONS else "unclassified"
    return {"label": label, "conditions": hit, "n_conditions": len(hit),
            "confident": len(hit) >= MIN_CONDITIONS}


def preview(signature: dict, samples: list[dict]) -> dict:
    """Dry-run a signature against stored events before saving it."""
    sig = validate_signature(signature)
    hits, checked = [], 0
    for s in samples:
        checked += 1
        ok, met = signature_matches(sig, s.get("features") or {})
        if ok:
            hits.append({"event_id": s.get("event_id"), "user_id": s.get("user_id"), "conditions": met})
    return {"checked": checked, "matches": len(hits), "examples": hits[:10]}
