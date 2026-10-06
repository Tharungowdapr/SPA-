"""Step 2: clearing data. Scope catalogue, roles, idempotency, presets and preserved tables."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.pipeline import Pipeline
from aegis.schemas import ClickEvent
from aegis.store.db import Store

ALL_SCOPES = ("simulation_runs", "events", "alerts", "incidents", "recommendations", "live_state",
              "blocklist", "learning", "saved_attacks", "patterns")
NEVER_CLEARED = ("users", "audit_log", "model_versions", "api_settings")


def burst(user="UR", n=40, ua="Mozilla/5.0 Chrome"):
    t0 = time.time()
    return [ClickEvent(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user, ip_address="7.7.7.7",
                       timestamp=t0 + i * 0.05, user_agent=ua) for i in range(n)]


@pytest.fixture()
def pipe(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    yield p
    p.store.close()


@pytest.fixture()
def filled(pipe):
    """A pipeline holding rows in most clearable tables."""
    p = pipe
    p.process_events(burst("UR", 40))
    p.store.add_alert("HIGH", "t", "UR", "C10", {"reason": "r"})
    p.store.add_recommendation("UR", "s", "bot", 0.9, "block", "rule", {})
    p.store.add_simulation("bot_clique", {}, [])
    inc = p.store.add_incident(time.time(), time.time(), "Bot / scripted click ring", 0.8)
    p.store.add_incident_entity(inc, "user", "UR", time.time(), flagged=1, peak_risk=0.8, blocked=0)
    pid = p.store.add_pattern("Bot / scripted click ring", "d", "label", {"conditions": [], "min_match": 1}, "analyst")
    p.store.add_pattern_hit(pid, time.time(), "evt_x", "UR", inc)
    p.store.add_user("keep@me", "admin", "hash")
    p.store.audit("tester", "seed", "x")
    return p


def counts(store: Store) -> dict[str, int]:
    return {t: int(store._one(f"SELECT COUNT(*) n FROM {t}")["n"])
            for t in ("click_events", "fraud_predictions", "fraud_alerts", "recommendations", "attack_simulations",
                      "incidents", "incident_entities", "patterns", "pattern_hits", "blocked_entities", "users",
                      "audit_log", "model_versions", "api_settings")}


# ------------------------------------------------------------------ scope catalogue
def test_all_scopes_are_defined():
    assert set(ALL_SCOPES) == set(Store.ALL_SCOPES)
    assert set(Store.PRESETS) == {"reset_network", "factory_reset"}


def test_preview_counts_every_scope(filled):
    out = filled.reset_preview()
    assert set(ALL_SCOPES) <= set(out["counts"])
    assert out["counts"]["events"] > 0             # click_events + fraud_predictions
    assert out["counts"]["alerts"] >= 1
    assert out["counts"]["incidents"] >= 2      # incidents + incident_entities (correlation adds more)
    assert out["counts"]["patterns"] == 2          # patterns + pattern_hits
    assert out["counts"]["live_state"] > 0
    assert out["presets"] == ["factory_reset", "reset_network"]


def test_preview_of_selected_scopes_only_totals_those(filled):
    out = filled.reset_preview(["alerts"])
    assert list(out["selected"]) == ["alerts"]
    assert out["total"] == out["counts"]["alerts"]


# ------------------------------------------------------------------ individual scopes
def test_clear_events_removes_events_and_predictions_only(filled):
    before = counts(filled.store)
    filled.reset(["events"])
    c = counts(filled.store)
    assert c["click_events"] == 0 and c["fraud_predictions"] == 0
    assert c["fraud_alerts"] == before["fraud_alerts"]
    assert c["recommendations"] == before["recommendations"] and c["users"] == before["users"]


def test_clear_alerts_and_recommendations(filled):
    filled.reset(["alerts", "recommendations"])
    c = counts(filled.store)
    assert c["fraud_alerts"] == 0 and c["recommendations"] == 0
    assert c["click_events"] > 0


def test_clear_incidents_removes_entities_too(filled):
    filled.reset(["incidents"])
    c = counts(filled.store)
    assert c["incidents"] == 0 and c["incident_entities"] == 0
    assert c["click_events"] > 0 and c["patterns"] == 1


def test_clear_blocklist_empties_memory_and_store(filled):
    filled.block_entity("user", "UR", "manual", by="analyst")
    assert "UR" in filled.blocked_users
    filled.reset(["blocklist"])
    assert counts(filled.store)["blocked_entities"] == 0
    assert not filled.blocked_users and not filled.blocked_devices


def test_clear_patterns_removes_hits_and_resets_counters(filled):
    filled.reset(["patterns"])
    c = counts(filled.store)
    assert c["patterns"] == 0 and c["pattern_hits"] == 0


def test_saved_attacks_survive_a_simulation_reset(filled):
    sim_id = filled.store.add_simulation("bot_clique", {}, [])
    filled.store._exec("UPDATE attack_simulations SET name='Saved ring' WHERE id=?", (sim_id,))
    filled.reset(["simulation_runs"])
    c = counts(filled.store)
    assert c["attack_simulations"] == 1                      # only the saved one is left
    assert filled.store._one("SELECT name FROM attack_simulations")["name"] == "Saved ring"
    filled.reset(["saved_attacks"])
    assert counts(filled.store)["attack_simulations"] == 0


def test_learning_clears_stored_thresholds_only(filled):
    filled.store.set_kv("thresholds", {"high": 0.9})
    filled.store.set_kv("rules_override", {"max_clicks_per_min": 7})
    filled.reset(["learning"])
    assert filled.store.get_kv("thresholds") is None
    assert filled.store.get_kv("rules_override") == {"max_clicks_per_min": 7}   # manual edits survive


def test_live_state_clears_duplicate_memory(filled):
    e = burst("UDUP", 1)[0]
    filled.process_events([e])
    assert filled.process_events([e]) == [] and filled.dups == 1
    filled.reset(["live_state"])
    assert len(filled.process_events([e])) == 1 and filled.dups == 0


def test_reset_always_forgets_duplicates_even_for_another_scope(filled):
    e = burst("UDUP2", 1)[0]
    filled.process_events([e])
    filled.process_events([e])
    assert filled.dups == 1
    filled.reset(["alerts"])
    assert len(filled.process_events([e])) == 1 and filled.dups == 0


def test_live_state_keeps_the_blocklist(filled):
    filled.block_entity("user", "UR", "manual", by="analyst")
    before = counts(filled.store)["blocked_entities"]
    filled.reset(["live_state"])
    assert "UR" in filled.blocked_users
    assert counts(filled.store)["blocked_entities"] == before


def test_counters_are_zeroed(filled):
    assert filled.total > 0
    filled.reset(["live_state"])
    assert filled.total == filled.flagged == filled.dups == 0
    assert not filled.seen and not filled.active_users


# ------------------------------------------------------------------ idempotency & safety
def test_reset_is_idempotent(filled):
    first = filled.reset(Store.ALL_SCOPES)
    assert sum(first["deleted"].values()) > 0
    second = filled.reset(Store.ALL_SCOPES)
    assert set(second["deleted"].values()) <= {0, 1}
    assert second["deleted"]["events"] == 0 and second["deleted"]["patterns"] == 0


def test_reset_never_touches_users_audit_models_or_ai(filled):
    before = counts(filled.store)
    filled.reset(Store.ALL_SCOPES)
    after = counts(filled.store)
    for t in ("users", "model_versions", "api_settings"):
        assert after[t] == before[t], t
    assert after["audit_log"] >= before["audit_log"]      # the reset itself is audited


def test_reset_writes_an_audit_entry(filled):
    filled.reset(["alerts"], actor="analyst@aegis.local")
    assert any(a["action"] == "reset" and a["actor"] == "analyst@aegis.local" for a in filled.store.audit_log())


def test_unknown_scope_is_rejected(filled):
    with pytest.raises(ValueError):
        filled.reset(["not_a_scope"])


# ------------------------------------------------------------------ presets
def test_reset_network_keeps_saved_attacks_patterns_and_rule_edits(filled):
    filled.store.add_simulation("bot_clique", {}, [])
    saved = filled.store.add_simulation("bot_clique", {}, [])
    filled.store._exec("UPDATE attack_simulations SET name='keep me' WHERE id=?", (saved,))
    filled.store.set_kv("rules_override", {"max_clicks_per_min": 7})
    filled.reset(list(Store.PRESETS["reset_network"]), preset="reset_network")
    c = counts(filled.store)
    assert c["click_events"] == 0 and c["blocked_entities"] == 0
    assert c["attack_simulations"] == 1 and c["patterns"] == 1
    assert filled.store.get_kv("rules_override") == {"max_clicks_per_min": 7}


def test_factory_reset_clears_saved_attacks_patterns_and_rule_edits(filled):
    filled.store.add_simulation("bot_clique", {}, [])
    saved = filled.store.add_simulation("bot_clique", {}, [])
    filled.store._exec("UPDATE attack_simulations SET name='drop me' WHERE id=?", (saved,))
    filled.store.set_kv("rules_override", {"max_clicks_per_min": 7})
    filled.reset(list(Store.PRESETS["factory_reset"]), preset="factory_reset")
    c = counts(filled.store)
    assert c["attack_simulations"] == 0 and c["patterns"] == 0 and c["pattern_hits"] == 0
    assert filled.store.get_kv("rules_override") is None
    assert filled.rules_config()["max_clicks_per_min"] == filled.s.get("rules.max_clicks_per_min")


# ------------------------------------------------------------------ HTTP surface
@pytest.fixture()
def client(settings, bundle):
    settings.set("security.rate_limit_per_min", 10_000_000)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        yield c


def login(c, who):
    r = c.post("/api/auth/login", json={"email": f"{who}@aegis.local", "password": f"{who}123"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_scope_catalogue_lists_roles_and_preserved_tables(client):
    body = client.get("/api/admin/reset/scopes", headers=login(client, "viewer")).json()
    assert {s["id"] for s in body["scopes"]} == set(ALL_SCOPES)
    assert [s["id"] for s in body["scopes"] if s["admin_only"]] == ["blocklist", "learning", "saved_attacks", "patterns"]
    assert body["preserved"] == list(NEVER_CLEARED)
    assert body["role"] == "viewer"


def test_preview_endpoint(client):
    client.post("/api/events", json=[e.model_dump() for e in burst("UR", 5)], headers=login(client, "analyst"))
    body = client.get("/api/admin/reset/preview?scopes=events,alerts", headers=login(client, "analyst")).json()
    assert body["selected"]["events"] > 0
    assert "denied" not in body or body["denied"] == []


def test_viewer_cannot_reset(client):
    assert client.post("/api/admin/reset", json={"scopes": ["events"], "confirm": True},
                       headers=login(client, "viewer")).status_code == 403


def test_viewer_preview_hides_admin_scopes(client):
    """A viewer may read the counts but may not clear anything, so every scope is denied."""
    body = client.get("/api/admin/reset/preview?scopes=events,blocklist", headers=login(client, "viewer")).json()
    assert body["denied"] == ["events", "blocklist"]
    assert body["selected"] == {} and body["total"] == 0
    assert body["counts"]["events"] >= 0            # counts are still visible


def test_analyst_preview_denies_only_admin_scopes(client):
    client.post("/api/events", json=[e.model_dump() for e in burst("UR", 5)], headers=login(client, "analyst"))
    body = client.get("/api/admin/reset/preview?scopes=events,blocklist", headers=login(client, "analyst")).json()
    assert body["denied"] == ["blocklist"]
    assert list(body["selected"]) == ["events"] and body["selected"]["events"] > 0


def test_admin_preview_denies_nothing(client):
    body = client.get("/api/admin/reset/preview?scopes=events,blocklist", headers=login(client, "admin")).json()
    assert body["denied"] == [] and len(body["selected"]) == 2


def test_preview_rejects_unknown_scope(client):
    r = client.get("/api/admin/reset/preview?scopes=nope", headers=login(client, "admin"))
    assert r.status_code == 400 and "unknown scope" in r.json()["detail"]


def test_analyst_can_clear_data_scopes_but_not_admin_scopes(client):
    h = login(client, "analyst")
    client.post("/api/events", json=[e.model_dump() for e in burst("UR", 5)], headers=h)
    assert client.post("/api/admin/reset", json={"scopes": ["events"], "confirm": True}, headers=h).status_code == 200
    r = client.post("/api/admin/reset", json={"scopes": ["blocklist"], "confirm": True}, headers=h)
    assert r.status_code == 403 and "admin role required" in r.json()["detail"]


def test_reset_requires_confirmation(client):
    r = client.post("/api/admin/reset", json={"scopes": ["events"], "confirm": False}, headers=login(client, "admin"))
    assert r.status_code == 400 and "confirm" in r.json()["detail"]


def test_reset_rejects_unknown_scope(client):
    r = client.post("/api/admin/reset", json={"scopes": ["nope"], "confirm": True}, headers=login(client, "admin"))
    assert r.status_code == 422


def test_reset_requires_at_least_one_scope(client):
    r = client.post("/api/admin/reset", json={"scopes": [], "confirm": True}, headers=login(client, "admin"))
    assert r.status_code == 400


def test_admin_preset_over_http(client):
    h = login(client, "admin")
    r = client.post("/api/admin/reset", json={"scopes": [], "preset": "reset_network", "confirm": True}, headers=h)
    assert r.status_code == 200 and r.json()["preset"] == "reset_network"
    assert r.json()["deleted"]["events"] >= 0
    assert client.post("/api/admin/reset", json={"scopes": [], "preset": "nope", "confirm": True},
                       headers=h).status_code == 400


def test_reset_broadcasts_over_websocket(client):
    h = login(client, "admin")
    token = h["Authorization"][7:]
    with client.websocket_connect(f"/ws?token={token}") as ws:
        client.post("/api/admin/reset", json={"scopes": ["live_state"], "confirm": True}, headers=h)
        msg = ws.receive_json()
        while msg["type"] == "hello":      # the socket greets on connect
            msg = ws.receive_json()
        assert msg["type"] == "reset" and msg["scopes"] == ["live_state"]


def test_reset_response_reports_counts(client):
    client.post("/api/events", json=[e.model_dump() for e in burst("UR", 5)], headers=login(client, "analyst"))
    body = client.post("/api/admin/reset", json={"scopes": ["events"], "confirm": True},
                       headers=login(client, "admin")).json()
    assert body["deleted"]["events"] == 10          # 5 click_events + 5 fraud_predictions
    assert body["role"] == "admin" and body["ts"] > 0
