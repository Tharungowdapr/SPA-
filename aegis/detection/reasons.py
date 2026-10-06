"""Turn a decision into a short, plain-English explanation.

The reason text is derived from the rules that fired and the feature values that triggered them, so it
works in rules-only mode (no model loaded) as well as with the full ensemble. Nothing here needs numpy,
a model bundle or the LLM.
"""
from __future__ import annotations

import re
from typing import Any

# rule name -> (short title, plain-English sentence with the observed values)
RULE_TEXT: dict[str, tuple[str, str]] = {
    "high_click_velocity": ("Rapid repeat clicks",
                            "this account clicked {clicks_1m:g} times in the last minute{over_limit}"),
    "tiny_interval": ("Clicks too close together",
                      "the gap between clicks fell to {min_interval:.2f}s{under_limit}"),
    "bot_user_agent": ("Automated browser",
                       "the browser identified itself as an automation tool ({ua}) rather than a real visitor"),
    "blocked_ip": ("Blocked network",
                   "the connection came from {ip}, which is already on the block-list"),
    "impossible_geo": ("Impossible travel",
                       "clicks arrived from {geo_user_countries:g} different countries within an hour"),
    "device_sharing": ("Shared device",
                       "{unique_users_per_device:g} different accounts clicked from this one device"),
    "ip_device_fanin": ("Many devices, one address",
                        "{unique_devices_per_ip:g} devices sent clicks from this single network address"),
    "repeat_ad": ("Same ad over and over",
                  "this account clicked the same advert {repeat_ad_ratio:.0%} of the time, well above normal"),
    "blocked_entity": ("Already blocked",
                       "this account, device or network address is already blocked, so the click was rejected"),
}

# feature -> how to phrase it for a non-technical reader
FACTOR_TEXT: dict[str, str] = {
    "clicks_1m": "clicks in the last minute",
    "clicks_5m": "clicks in the last 5 minutes",
    "clicks_1h": "clicks in the last hour",
    "min_interval": "shortest gap between clicks (s)",
    "repeat_ad_ratio": "share of clicks on the same ad",
    "unique_users_per_device": "accounts sharing this device",
    "unique_devices_per_ip": "devices behind this address",
    "geo_user_countries": "countries seen in the last hour",
    "ua_bot_flag": "automation signals in the browser string",
    "ctr": "click-through rate",
    "cvr": "conversion rate",
    "account_age_days": "age of the account (days)",
    "click_position": "position of the ad on the page",
    "hour_of_day": "hour of day",
    "is_weekend": "weekend flag",
}

# Score contribution by layer, worst first: used when no rule fired (model-only detection).
LAYER_TEXT = {
    "ml": "the fraud model",
    "anomaly": "the anomaly detector",
    "graph": "the link graph",
    "online": "the online learner",
    "rules": "the rule checks",
}


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _factor_lines(factors: list[dict], limit: int = 3) -> list[str]:
    out = []
    for f in (factors or [])[:limit]:
        name = f.get("feature") or f.get("label") or "signal"
        label = FACTOR_TEXT.get(name, (f.get("label") or name).replace("_", " "))
        value, contrib = f.get("value"), f.get("contribution")
        if value is None:
            out.append(label)
        elif contrib is None:
            out.append(f"{label} was {value:g}")
        else:
            out.append(f"{label} was {value:g} (normal {f.get('typical'):g})")
    return out


def _safe_format(template: str, values: dict) -> str:
    """Format, then scrub anything we could not fill in: a reason must never show {placeholders}."""
    try:
        body = template.format(**values)
    except (KeyError, ValueError, TypeError, IndexError):
        body = re.sub(r"\{[^{}]*\}", "", template)          # unknown placeholder -> drop the clause
    return re.sub(r"\s{2,}", " ", body).replace(" ,", ",").strip().strip(",").strip()


def _rule_sentences(rules: list[str], f: dict, thresholds: dict | None = None,
                   ip: str = "") -> list[tuple[str, str]]:
    lim = {k: v for k, v in (thresholds or {}).items() if isinstance(v, (int, float))}
    out = []
    for name in rules or []:
        title, template = RULE_TEXT.get(name, (name.replace("_", " ").capitalize(), "an automated rule flagged this click"))
        values = {**f, **lim, "ip": ip or "this address"}
        values["over_limit"] = (", well above the normal rate of %g a minute" % lim["max_clicks_per_min"]
                                if "max_clicks_per_min" in lim else "")
        values["under_limit"] = (", below the %g second minimum" % lim["min_interval_s"]
                                if "min_interval_s" in lim else "")
        out.append((title, _safe_format(template, values)))
    return out


def explain_decision(event: Any = None, decision: Any = None, features: dict | None = None,
                    rule_hits: list[str] | None = None, scores: dict | None = None,
                    blockers: list[str] | None = None, graph_context: dict | None = None,
                    thresholds: dict | None = None) -> dict:
    """Build the stored explanation for one decision.

    Returns {"title", "reason", "detail"} where `detail` is JSON-safe and keeps everything an analyst
    needs to re-check the call: triggered rules, contributing factors, per-layer scores, the event id,
    the level, what was blocked and any link-graph context.
    """
    f = dict(features or {})
    fired = list(rule_hits if rule_hits is not None else getattr(decision, "rules_fired", []) or [])
    layer = dict(scores if scores is not None else getattr(decision, "scores", {}) or {})
    factors = list(getattr(decision, "top_factors", None) or [])
    level = getattr(decision, "level", "") or "LOW"
    action = getattr(decision, "action", "") or "ALLOW"
    risk = getattr(decision, "risk", None)
    eid = getattr(decision, "event_id", "") or (getattr(event, "event_id", "") or "")
    ip = getattr(decision, "ip_mask", "") or ""
    blockers = list(blockers or [])

    sentences = _rule_sentences(fired, f, thresholds, ip)
    if not sentences:                     # model-only detection: describe the strongest layer
        worst = next((k for k in ("rules", "ml", "graph", "anomaly", "online")
                      if (layer.get(k) or 0) >= 0.6), None)
        if worst:
            sentences.append((f"Suspicious to {LAYER_TEXT[worst]}",
                              f"{LAYER_TEXT[worst]} gave this click a score of {(layer.get(worst) or 0):.2f}"))
        else:
            lines = _factor_lines(factors)
            sentences.append(("Unusual click pattern", "; ".join(lines) if lines else
                              "several weak signals added up to a higher-than-usual risk score"))
    title = sentences[0][0]
    body = [s[1] for s in sentences[:2]]
    for line in _factor_lines(factors):
        if line not in body:
            body.append(line)
            break
    if blockers:
        body.append("also seen with " + ", ".join(blockers[:3]))
    reason = "; ".join(body[:2])
    if reason and reason[0].islower():
        reason = reason[0].upper() + reason[1:]

    return {"title": title, "reason": reason,
            "detail": {"event_id": eid, "level": level, "action": action,
                       "risk": round(float(risk), 4) if isinstance(risk, (int, float)) else None,
                       "rules": fired, "factors": factors, "scores": layer,
                       "blockers": blockers, "graph": graph_context or {},
                       "event_ts": getattr(decision, "timestamp", None) or getattr(event, "timestamp", None)}}


def explain_event(prediction: dict, event: dict | None = None) -> dict:
    """Same explanation, rebuilt from stored columns (used by the event drawer and the logs)."""
    return explain_decision(
        event=event, decision=prediction,
        features={}, rule_hits=prediction.get("rules") or [],
        scores=_loads(prediction.get("scores")), blockers=[], graph_context={})


def _loads(raw: Any) -> dict:
    import json
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}
