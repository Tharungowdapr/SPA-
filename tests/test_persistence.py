"""Step 1 persistence: provenance, reason detail, features, incidents and patterns round-trip."""
from __future__ import annotations

import time

import pytest

from aegis.store.db import Store


def _event(**over):
    e = {"event_id": "evt_1", "timestamp": time.time(), "user_id": "U1", "ad_id": "AD1", "campaign_id": "C1",
         "publisher_id": "PUB1", "device_id": "D1", "ip_hash": "hash", "user_agent": "Mozilla/5.0", "country": "IN"}
    e.update(over)
    return e


def _decision(**over):
    d = {"event_id": "evt_1", "timestamp": time.time(), "user_id": "U1", "risk": 0.91, "level": "HIGH",
         "action": "FLAG", "confidence": "HIGH", "scores": {"rules": 0.9, "model": 0.88},
         "rules_fired": ["CTR-05", "IP-03"], "model_version": "v3", "latency_ms": 4.2,
         "top_factors": [{"name": "ctr", "value": 0.9}], "ip_mask": "10.0.0.0/24"}
    d.update(over)
    return d


@pytest.fixture()
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_provenance_and_decision_fields_are_stored(store):
    store.save_batch([(_event(source="simulation", run_id="run_7"),
                       _decision(features={"ctr": 0.9, "device_count": 4}, classification="Bot / scripted click ring",
                                 classification_source="pattern"))])
    row = store._one("SELECT source, run_id FROM click_events WHERE event_id='evt_1'")
    assert row["source"] == "simulation" and row["run_id"] == "run_7"
    pred = store._one("SELECT features, classification, classification_source FROM fraud_predictions")
    assert pred["classification"] == "Bot / scripted click ring"
    assert pred["classification_source"] == "pattern"
    assert pred["features"]


def test_provenance_defaults_to_live_when_absent(store):
    store.save_batch([(_event(), _decision())])
    row = store._one("SELECT source, run_id FROM click_events")
    assert row["source"] == "live" and row["run_id"] is None


def test_block_keeps_reason_detail(store):
    detail = {"reason": "Bot / scripted click ring", "triggered_by": "evt_1", "score": 0.91,
              "factors": ["CTR-05", "IP-03"], "event_ts": time.time()}
    store.block("user", "U1", "Bot / scripted click ring", 0.91, reason_detail=detail)
    row = store.list_blocked()[0]
    assert row["reason"] == "Bot / scripted click ring"
    assert row["reason_detail"]["triggered_by"] == "evt_1"
    assert row["reason_detail"]["score"] == 0.91


def test_block_without_detail_is_allowed(store):
    store.block("ip", "10.0.0.0/24", "Manual block", 1.0)
    assert store.list_blocked()[0]["reason_detail"] is None


def test_alert_can_be_linked_to_an_incident(store):
    alert_id = store.add_alert("HIGH", "Bot click ring", "U1", "C1", {"reason": "r"})
    store.set_alert_incident(alert_id, 3)
    store.add_incident(time.time(), time.time(), "Bot / scripted click ring", 0.8)
    assert store._one("SELECT incident_id FROM fraud_alerts WHERE id=?", (alert_id,))["incident_id"] == 3


def test_incident_entities_accumulate(store):
    inc = store.add_incident(100.0, 100.0, "Bot / scripted click ring", 0.8, run_id="run_1")
    store.add_incident_entity(inc, "user", "U1", 100.0, flagged=1, peak_risk=0.8, blocked=0)
    store.add_incident_entity(inc, "user", "U1", 160.0, flagged=1, peak_risk=0.95, blocked=1)
    store.add_incident_entity(inc, "device", "D1", 170.0, flagged=1, peak_risk=0.7, blocked=0)
    store.add_incident_entity(inc, "ip", "10.0.0.0/24", 175.0, flagged=0, peak_risk=0.3, blocked=0)
    store.refresh_incident_counts(inc)
    got = store.get_incident(inc)
    users = [e for e in got["entities"] if e["entity_type"] == "user"]
    assert len(users) == 1
    assert users[0]["events"] == 2 and users[0]["flagged"] == 2 and users[0]["blocked"] == 1
    assert users[0]["first_seen"] == 100.0 and users[0]["last_seen"] == 160.0
    assert users[0]["peak_risk"] == 0.95
    assert (got["users_n"], got["devices_n"], got["ips_n"]) == (1, 1, 1)
    assert got["events_n"] == 4 and got["flagged_n"] == 3 and got["blocked_n"] == 1
    assert got["peak_risk"] == 0.95


def test_incident_candidates_ignore_expired(store):
    inc = store.add_incident(100.0, 100.0, "c", 0.5)
    store.update_incident(inc, time.time() - 10_000)
    assert [c["id"] for c in store.candidate_incidents(time.time() - 300)] == []
    assert [c["id"] for c in store.candidate_incidents(time.time() - 100_000)] == [inc]


def test_incident_campaigns_are_a_list(store):
    inc = store.add_incident(1.0, 2.0, "c", 0.5)
    store._exec("UPDATE incidents SET campaigns=? WHERE id=?", ("C1,C2", inc))
    assert store.get_incident(inc)["campaigns"] == ["C1", "C2"]


def test_pattern_crud_and_hits(store):
    pid = store.add_pattern("Bot / scripted click ring", "Repeated automated clicks", "label",
                            {"conditions": [{"feature": "is_bot", "op": "eq", "value": True}], "min_match": 1},
                            "analyst@aegis.local", examples_n=12)
    assert store.get_pattern(pid)["signature"]["conditions"][0]["feature"] == "is_bot"
    assert store.get_pattern(pid)["enabled"] is True
    store.add_pattern_hit(pid, 100.0, "evt_1", "U1", 7)
    store.add_pattern_hit(pid, 200.0, "evt_2", "U2")
    assert store.get_pattern(pid)["hits"] == 2
    assert store.pattern_hit_counts() == {str(pid): 2}
    assert [h["event_id"] for h in store.pattern_hits(pid)] == ["evt_2", "evt_1"]
    assert store.patterns_matching("evt_1")[0]["id"] == pid
    assert store.update_pattern(pid, "renamed", "d", "block", {"conditions": [], "min_match": 1}, enabled=False)
    assert store.get_pattern(pid)["name"] == "renamed" and store.get_pattern(pid)["enabled"] is False
    assert [p["id"] for p in store.list_patterns(enabled_only=True)] == []
    assert store.delete_pattern(pid)
    assert store.pattern_hits(pid) == [] and store.get_pattern(pid) is None


def test_pattern_delete_is_idempotent(store):
    pid = store.add_pattern("x", "", "label", {"conditions": [], "min_match": 1}, "a")
    assert store.delete_pattern(pid) is True
    assert store.delete_pattern(pid) is False
