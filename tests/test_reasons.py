"""Step 3: plain-language reasons are generated at decision time and stored with the decision."""
from __future__ import annotations

import json
import time

from aegis.detection.reasons import explain_decision, explain_event
from aegis.pipeline import Pipeline
from aegis.schemas import ClickEvent
from aegis.store.db import Store


def burst(user="UR", n=40, ua="Mozilla/5.0 Chrome"):
    t0 = time.time()
    return [ClickEvent(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user,
                       ip_address="7.7.7.7", timestamp=t0 + i * 0.05, user_agent=ua) for i in range(n)]


def one(user="UR", eid="x1", **kw):
    base = dict(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user, ip_address="7.7.7.7",
                user_agent="Mozilla/5.0 Chrome")
    base.update(kw)
    return ClickEvent(event_id=eid, **base)


def pipe_of(settings, **kw):
    return Pipeline(settings, store=Store(":memory:"), **kw)


def risky(pipe, user="UR"):
    out = pipe.process_events(burst(user, 40))
    return next(d for d in out if d.level in ("HIGH", "CRITICAL"))


def test_every_suspicious_decision_has_a_plain_reason(settings):
    d = risky(pipe_of(settings))
    assert d.reason and d.reason_title
    assert "_" not in d.reason, f"reason must read as English, got {d.reason!r}"
    assert "clicks_1m" not in d.reason


def test_reason_names_the_rule_and_the_values():
    out = explain_decision(features={"clicks_1m": 40}, rule_hits=["high_click_velocity"],
                           thresholds={"max_clicks_per_min": 12})
    assert out["title"] == "Rapid repeat clicks"
    assert "40" in out["reason"] and "12" in out["reason"]


def test_reason_never_leaks_a_placeholder():
    """A threshold we were not given must drop the clause, not print {max_clicks_per_min}."""
    out = explain_decision(features={"clicks_1m": 40}, rule_hits=["high_click_velocity"])
    assert "{" not in out["reason"] and "}" not in out["reason"]
    assert "40" in out["reason"]
    bare = explain_decision(rule_hits=["tiny_interval"])
    assert "{" not in bare["reason"] and bare["reason"]


def test_reason_detail_is_json_safe_and_complete(settings):
    pipe = pipe_of(settings)
    d = risky(pipe)
    detail = explain_decision(decision=d, features={"clicks_1m": 40},
                              rule_hits=["high_click_velocity"]).pop("detail")
    json.dumps(detail)                                    # must not raise
    for key in ("event_id", "level", "scores", "rules", "blockers"):
        assert key in detail
    assert detail["event_id"] == d.event_id
    assert detail["level"] == d.level


def test_model_only_decision_still_explains():
    """No rule fired: fall back to the strongest layer, never an empty reason."""
    fake = type("D", (), {"level": "HIGH", "action": "FLAG", "risk": 0.8, "event_id": "x",
                          "rules_fired": [], "top_factors": [], "scores": {"ml": 0.91, "rules": 0.1}})()
    out = explain_decision(decision=fake, scores={"ml": 0.91})
    assert out["reason"] and "model" in out["reason"]


def test_reason_persisted_with_the_decision(settings):
    pipe = pipe_of(settings)
    risky(pipe)
    rows = [r for r in pipe.store.recent_predictions(50) if r.get("reason")]
    assert rows, "reason must be written to fraud_predictions"
    assert rows[0]["reason_title"]
    assert "_" not in rows[0]["reason"]


def test_alert_details_carry_the_reason(settings):
    pipe = pipe_of(settings)
    risky(pipe)
    # the newest alert may be the campaign cluster alert, so look for one that has a reason
    det = [a["details"] for a in pipe.store.list_alerts() if a["details"].get("reason")]
    assert det, "the per-user alert must carry the reason"
    assert det[0]["reason_detail"].get("reason")
    assert det[0]["reason_detail"].get("event_id")
    assert det[0]["reason_title"]


def test_blocklist_keeps_the_full_reason_detail(settings):
    pipe = pipe_of(settings)
    pipe.process_events(burst("UR", 40))
    pipe.process_events(burst("UR", 40))
    rows = pipe.store.list_blocked()
    assert rows, "repeated critical activity should auto-block"
    det = next((r["reason_detail"] for r in rows if r["reason_detail"]), None)
    assert det, "blocked_entities must keep the full reason detail"
    assert det.get("reason") and det.get("event_id") and det.get("level")


def test_rejected_click_says_why(settings):
    pipe = pipe_of(settings)
    pipe.block_entity("user", "UB", "manual test block", by="tester")
    d = pipe.process_events([one("UB", "rj1")])[0]
    assert d.action == "REJECTED"
    assert d.reason_title == "Already blocked"
    assert d.reason


def test_investigation_reuses_the_stored_reason(settings):
    pipe = pipe_of(settings)
    risky(pipe)
    latest = pipe.last_seen["UR"][3]              # the decision the investigator reports on
    rep = pipe.investigate("UR")
    assert rep["reason"] == latest.reason
    assert rep["event_id"] == latest.event_id
    assert rep["summary"] == rep["reason"]
    assert rep["reason_title"] == latest.reason_title


def test_user_history_rows_carry_the_reason(settings):
    pipe = pipe_of(settings)
    risky(pipe)
    assert any(r.get("reason") for r in pipe.store.user_events("UR", 20))


def test_rows_written_before_the_reason_columns_are_explained_on_read(settings):
    """Backwards compatibility: old rows have no reason, the reader derives one."""
    st = Store(":memory:")
    st._exec("INSERT INTO click_events(event_id,ts,user_id,ad_id,campaign_id,device_id,ip_mask,country) "
             "VALUES('old1',?,?,?,?,?,?,?)", (time.time(), "U1", "A1", "C1", "D1", "1.2.3.4", "US"))
    st._exec("INSERT INTO fraud_predictions(event_id,ts,user_id,risk,level,action,confidence,scores,rules,"
             "model_version,latency_ms) VALUES('old1',?,?,0.9,'HIGH','FLAG','HIGH',?,?,?,?)",
             (time.time(), "U1", json.dumps({"ml": 0.9}), json.dumps(["high_click_velocity"]), "none", 1.0))
    r = st.get_prediction("old1")
    assert r and not r["reason"]
    assert explain_event(r)["reason"]
    st.close()
