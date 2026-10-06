import time

import numpy as np

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.pipeline import Pipeline
from aegis.schemas import ClickEvent
from aegis.simulator.traffic import build_episode
from aegis.store.db import Store


def burst(user="UB", n=60, t0=None, ua="Mozilla/5.0 Chrome"):
    t0 = t0 or time.time()
    return [ClickEvent(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user, ip_address="7.7.7.7",
                       timestamp=t0 + i * 0.05, user_agent=ua) for i in range(n)]


# ---------------------------------------------------------------- pipeline / fail-safe
def test_burst_is_detected_blocked_then_rejected(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    p.submit(burst())
    assert "UB" in p.blocked_users and p.store.list_blocked()
    acks = p.submit(burst(n=3))
    assert all(a["status"] == "rejected" for a in acks) and p.rejected >= 3
    assert p.store.list_alerts()


def test_legit_traffic_not_blocked(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    ev = [e for e in build_episode(41, n_users=300, attacks=[]) if e.label == 0]
    for i in range(0, len(ev), 200):
        p.process_events(ev[i:i + 200])
    assert not p.blocked_users and p.flagged / p.total < 0.01


def test_duplicate_events_ignored(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    e = burst(n=1)[0]
    assert len(p.process_events([e, e])) == 1 and p.dups == 1


def test_works_without_ml_models_rules_only(settings):
    p = Pipeline(settings, store=Store(":memory:"), bundle=None)
    out = p.process_events(burst(n=80))
    assert p.health()["mode"].startswith("rules-only") and p.health()["status"] == "DEGRADED"
    assert max(d.risk for d in out) >= 0.75 and out[-1].scores["ml"] is None and out[-1].confidence in ("LOW", "MEDIUM")
    assert out[-1].top_factors  # rule-based explanation still produced


def test_ml_failure_degrades_gracefully_and_recovers(settings, bundle, monkeypatch):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    orig = bundle.ml_score
    monkeypatch.setattr(type(bundle), "ml_score", lambda self, X, e=None: (_ for _ in ()).throw(RuntimeError("model gone")))
    out = p.process_events(burst("UM", 60))
    assert p.status["ml"]["state"] == "DEGRADED" and out and out[-1].scores["ml"] is None
    assert max(d.risk for d in out) >= 0.7  # rules + anomaly + graph still catch the burst
    monkeypatch.setattr(type(bundle), "ml_score", orig)
    p.process_events(burst("UN", 3))
    assert p.status["ml"]["state"] == "ONLINE"


def test_database_failure_does_not_stop_detection(settings, bundle, monkeypatch):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    monkeypatch.setattr(p.store, "save_batch", lambda rows: (_ for _ in ()).throw(RuntimeError("disk full")))
    out = p.process_events(burst("UD", 30))
    assert out and p.status["database"]["state"] == "DEGRADED" and p.health()["status"] == "DEGRADED"


def test_graph_failure_is_isolated(settings, bundle, monkeypatch):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    monkeypatch.setattr(p.graph, "update", lambda e: (_ for _ in ()).throw(RuntimeError("neo4j down")))
    out = p.process_events(burst("UG", 30))
    assert out and out[-1].scores["graph"] is None and p.status["graph"]["state"] == "DEGRADED"


def test_kafka_unavailable_falls_back(settings, bundle):
    from aegis.streaming.bus import make_bus
    bus = make_bus("127.0.0.1:1")
    p = Pipeline(settings, store=Store(":memory:"), bus=bus, bundle=bundle)
    p.submit(burst("UK", 5))
    h = p.health()
    assert bus.mode == "memory" and h["components"]["bus"]["state"] == "FALLBACK" and p.total == 5


def test_unblock_and_feedback_and_investigation(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    out = p.process_events(burst("UF", 60))
    assert p.unblock_entity("user", "UF") and "UF" not in p.blocked_users
    assert p.feedback(out[10].event_id, 1) and p.online.n_learned == 1
    rep = p.investigate("UF")
    assert rep["mode"] == "rule-based" and rep["requires_approval"] and rep["recommendation_id"]
    assert p.store.list_recommendations()[0]["status"] == "pending"  # agent only recommends


# ---------------------------------------------------------------- API
@pytest.fixture()
def client(settings, bundle):
    settings.set("security.rate_limit_per_min", 10_000_000)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        yield c


def login(c, who):
    r = c.post("/api/auth/login", json={"email": f"{who}@aegis.local", "password": f"{who}123"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_health_status_metrics_public(client):
    assert client.get("/health").json() == {"status": "ok"}
    st = client.get("/status").json()
    assert st["status"] == "OPERATIONAL" and "components" in st and st["mode"].startswith("ml-only")
    assert "aegis_events_total" in client.get("/metrics").text


def test_auth_and_rbac(client):
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/users", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "admin@aegis.local", "password": "wrong"}).status_code == 401
    viewer, analyst, admin = login(client, "viewer"), login(client, "analyst"), login(client, "admin")
    assert client.get("/api/users", headers=viewer).status_code == 200
    assert client.post("/api/clicks", json={"user_id": "U001", "ad_id": "AD100"}, headers=viewer).status_code == 403
    assert client.put("/api/settings/ai", json={"provider": "grok"}, headers=analyst).status_code == 403
    assert client.get("/api/audit", headers=admin).status_code == 200


def test_validation_and_injection_rejected(client):
    h = login(client, "analyst")
    assert client.post("/api/clicks", json={"user_id": "U001'; --", "ad_id": "AD100"}, headers=h).status_code == 422
    assert client.post("/api/clicks", json={"user_id": "U001", "ad_id": "AD100", "count": 99999}, headers=h).status_code == 422
    assert client.post("/api/clicks", json={"user_id": "NOPE", "ad_id": "AD100"}, headers=h).status_code == 404
    assert client.post("/api/simulation/does-not-exist", json={}, headers=h).status_code == 404


def test_click_flow_block_reject_unblock(client):
    h = login(client, "analyst")
    r = client.post("/api/clicks", json={"user_id": "U002", "ad_id": "AD101", "count": 80, "profile": "rapid"}, headers=h).json()
    assert r["blocked"] and r["level"] == "CRITICAL"
    again = client.post("/api/clicks", json={"user_id": "U002", "ad_id": "AD101"}, headers=h).json()
    assert again["rejected"] == 1 and again["accepted"] == 0
    users = {u["user_id"]: u for u in client.get("/api/users", headers=h).json()}
    assert users["U002"]["blocked"]
    assert client.delete("/api/blocked/user/U002", headers=h).status_code == 400  # needs confirm
    assert client.delete("/api/blocked/user/U002?confirm=true", headers=h).status_code == 200
    assert client.post("/api/clicks", json={"user_id": "U002", "ad_id": "AD101"}, headers=h).json()["accepted"] == 1


def test_client_cannot_inject_ground_truth_or_bypass(client):
    h = login(client, "analyst")
    ev = burst("UX", 1)[0].model_dump() | {"label": 0, "attack_type": "normal"}
    assert client.post("/api/events", json=[ev], headers=h).status_code == 200
    row = client.app.state.store._one("SELECT label, attack_type FROM click_events WHERE user_id='UX'")
    assert row["label"] is None and row["attack_type"] is None


def test_event_explanation_endpoint(client):
    h = login(client, "analyst")
    client.post("/api/events", json=[e.model_dump() for e in burst("UE", 60)], headers=h)
    top = client.get("/api/fraud/events?limit=1&min_risk=0.9", headers=h).json()[0]
    d = client.get(f"/api/fraud/events/{top['event_id']}", headers=h).json()
    assert d["factors"] and d["factors"][0]["contribution"] is not None and ("shap" in d["explanation_method"])
    u = client.get("/api/fraud/users/UE", headers=h).json()
    assert u["blocked"] and u["graph"]["nodes"] and u["features"]["clicks_1m"] > 30


def test_ai_key_encrypted_never_returned_and_agent_optional(client):
    admin = login(client, "admin")
    assert client.get("/api/settings/ai", headers=admin).json()["status"]["state"] == "DISABLED"
    r = client.put("/api/settings/ai", json={"provider": "grok", "api_key": "sk-TOPSECRET", "model": "grok-3", "enabled": True}, headers=admin)
    assert r.status_code == 200 and "sk-TOPSECRET" not in r.text
    assert "sk-TOPSECRET" not in client.get("/api/settings/ai", headers=admin).text
    raw = client.app.state.store._one("SELECT encrypted_key FROM api_settings")["encrypted_key"]
    assert raw and "sk-TOPSECRET" not in raw
    assert client.put("/api/settings/ai", json={"provider": "bogus"}, headers=admin).status_code == 422
    t = client.post("/api/settings/ai/test", headers=admin).json()
    assert t["ok"] is False and "sk-TOPSECRET" not in t["message"]
    # agent enabled but unreachable -> investigation still works (rule-based fallback)
    client.post("/api/events", json=[e.model_dump() for e in burst("UA", 30)], headers=admin)
    rep = client.post("/api/investigate/UA", headers=admin).json()
    assert rep["mode"] == "rule-based" and "sk-TOPSECRET" not in str(rep)


def test_human_in_the_loop_recommendation(client):
    h = login(client, "analyst")
    client.post("/api/settings/system", headers=h)  # wrong verb: 405, harmless
    client.put("/api/settings/system", json={"auto_block": False}, headers=login(client, "admin"))
    client.post("/api/events", json=[e.model_dump() for e in burst("UH", 60)], headers=h)
    assert "UH" not in client.app.state.pipeline.blocked_users  # auto-block off
    rep = client.post("/api/investigate/UH", headers=h).json()
    assert rep["recommendation"] == "block" and "UH" not in client.app.state.pipeline.blocked_users
    assert client.post(f"/api/recommendations/{rep['recommendation_id']}/approve", headers=h).status_code == 200
    assert "UH" in client.app.state.pipeline.blocked_users


def test_simulation_start_stop_replay_and_websocket(client):
    h = login(client, "analyst")
    tok = h["Authorization"][7:]
    with client.websocket_connect("/ws?token=" + tok) as ws:
        assert ws.receive_json()["type"] == "hello"
        r = client.post("/api/simulation/bot", json={"duration": 10, "intensity": 5}, headers=h)
        assert r.status_code == 200 and r.json()["total"] > 10
        got = None
        for _ in range(60):
            m = ws.receive_json()
            if m["type"] == "decisions":
                got = m
                break
        assert got and got["items"][0]["risk"] >= 0
    assert client.post("/api/simulation/stop", headers=h).json()["stopped"] >= 0
    sims = client.get("/api/simulations", headers=h).json()
    assert sims and client.post(f"/api/simulations/{sims[0]['id']}/replay?speed=50", headers=h).status_code == 200
    assert client.post("/api/simulations/99999/replay", headers=h).status_code == 404
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=bad"):
            pass


def test_rate_limit_and_security_headers(settings, bundle):
    settings.set("security.rate_limit_per_min", 40)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        codes = [c.get("/api/ads").status_code for _ in range(60)]
        assert 429 in codes
        assert c.get("/health").headers["x-content-type-options"] == "nosniff"


def test_models_endpoints_and_frontends(client):
    h = login(client, "admin")
    assert "registry" in client.get("/api/models", headers=h).json()
    assert client.get("/").status_code == 200 and "FRAUD//CONTROL" in client.get("/").text
    assert client.get("/sim").status_code == 200 and client.get("/static/common.js").status_code == 200
    assert client.get("/api/analytics?since_minutes=60", headers=h).status_code == 200


def test_docs_page_csp_allows_swagger_cdn_only_there(client):
    assert "cdn.jsdelivr.net" in client.get("/docs").headers["content-security-policy"]
    assert "cdn.jsdelivr.net" not in client.get("/").headers["content-security-policy"]


def test_dimension_tables_populated(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    p.process_events(burst("UT", 5))
    st = p.store
    assert st._one("SELECT COUNT(*) n FROM campaigns")["n"] == 1 and st._one("SELECT COUNT(*) n FROM advertisements")["n"] == 1
    assert st._one("SELECT device_id FROM devices")["device_id"] == "DUT"


def test_pseudo_labels_off_by_default_and_staged_when_enabled(settings, bundle):
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    p.process_events(burst("UP1", 60))
    assert not p.online.pending  # default: confirmed labels only
    s2 = settings.copy()
    s2.set("ml.online_learn_confirmed_only", False)
    q = Pipeline(s2, store=Store(":memory:"), bundle=bundle)
    out = q.process_events(burst("UP2", 80))
    assert q.online.pending, "agreed CRITICAL events should be staged"
    eid = next(iter(q.online.pending))
    assert q.online.commit(time.time(), delay=60) == 0  # not before the delay
    assert q.feedback(eid, 0) and eid not in q.online.pending  # analyst override wins
    assert q.online.commit(time.time() + 120, delay=60) >= 1 and out


# ---------------------------------------------------------------- v1.1: replay timing, retention, rules, analytics, monitor
def test_replay_preserves_event_time_spacing_at_any_speed(settings, bundle):
    import asyncio
    import random

    from aegis.simulator.manager import SimulationManager
    from aegis.simulator.traffic import UserPool

    async def go():
        got = []
        st = Store(":memory:")
        mgr = SimulationManager(lambda evs: got.extend(evs) or [{"status": "accepted"}] * len(evs), UserPool(20, random.Random(1)), st)
        orig = mgr.start("bot", {"duration": 10, "intensity": 2})
        await asyncio.sleep(0.5)
        mgr.stop()
        mgr.runs.clear()
        got.clear()
        t0 = time.time()
        run = mgr.replay(orig["db_id"], speed=100)
        await asyncio.sleep(1.2)
        mgr.stop()
        return orig, run, got, time.time() - t0

    orig, run, got, wall = asyncio.run(go())
    assert run["total"] > 10 and len(got) == run["total"] and wall < 2.5  # 10 s of event time replayed in ~1 s of wall time
    ts = sorted(e.timestamp for e in got)
    assert ts[-1] - ts[0] > 7.0  # ...but event timestamps keep their ORIGINAL spacing (not compressed 100x)


def test_retention_prune_and_rule_editor_and_analytics(client):
    h = login(client, "admin")
    pipe = client.app.state.pipeline
    old = time.time() - 40 * 86400
    client.post("/api/events", json=[e.model_dump() for e in burst("UR", 5, t0=old)], headers=h)
    client.post("/api/events", json=[e.model_dump() for e in burst("UR2", 5)], headers=h)
    st = client.app.state.store
    assert st._one("SELECT COUNT(*) n FROM fraud_predictions")["n"] == 10
    out = client.post("/api/admin/prune?days=7", headers=h).json()
    assert out["predictions"] == 5 and st._one("SELECT COUNT(*) n FROM fraud_predictions")["n"] == 5
    assert client.post("/api/admin/prune", headers=login(client, "viewer")).status_code == 403
    # live rule editing + persistence + validation
    cur = client.get("/api/rules", headers=h).json()
    assert cur["max_clicks_per_min"] == 30
    r = client.put("/api/rules", json={"max_clicks_per_min": 5, "weights": {"high_click_velocity": 0.5}}, headers=h)
    assert r.status_code == 200 and pipe.rules.cfg["max_clicks_per_min"] == 5 and pipe.rules.w["high_click_velocity"] == 0.5
    assert client.put("/api/rules", json={"max_clicks_per_min": -3}, headers=h).status_code == 422
    assert client.put("/api/rules", json={"nope": 1}, headers=h).status_code == 422
    assert client.put("/api/rules", json={"bot_user_agents": ["curl"]}, headers=login(client, "analyst")).status_code == 403
    fresh = Pipeline(pipe.s.copy(), store=st, bundle=None)
    assert fresh.rules.cfg["max_clicks_per_min"] == 5  # persisted override reloaded on restart
    # timelines, device types, campaigns with spend
    tl = client.get("/api/analytics/timeline?window=5m", headers=h).json()
    assert tl["bucket_s"] == 15 and sum(p["n"] for p in tl["points"]) == 5
    assert client.get("/api/analytics/timeline?window=7y", headers=h).status_code == 422
    dv = {d["k"]: d for d in client.get("/api/analytics/devices", headers=h).json()}
    assert dv["Unknown"]["n"] == 5
    client.post("/api/events", json=[e.model_dump() for e in burst("UW", 1, ua="Mozilla/5.0 (Windows NT 10.0; Win64)")] +
                [e.model_dump() for e in burst("UC", 1, ua="curl/8.0")] + [e.model_dump() for e in burst("UI", 1, ua="Mozilla/5.0 (iPhone; CPU)")], headers=h)
    dv = {d["k"]: d["n"] for d in client.get("/api/analytics/devices", headers=h).json()}
    assert dv["Desktop"] == 1 and dv["Bot/script"] == 1 and dv["Mobile"] == 1
    cs = client.get("/api/campaigns", headers=h).json()
    c10 = next(c for c in cs["campaigns"] if c["campaign_id"] == "C10")
    assert c10["clicks"] == 8 and c10["spend"] == pytest.approx(8 * 12.0) and c10["wasted"] <= c10["spend"]
    assert client.get("/api/campaigns/C10", headers=h).json()["top_users"]


def test_monitor_drift_and_quality_over_time(settings, bundle):
    settings.set("ml.drift", {"warmup_s": 100, "ref_size": 400, "window": 400})
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    assert p.monitor()["available"] is False
    ev = build_episode(61, n_users=400)
    for i in range(0, len(ev), 200):
        p.process_events(ev[i:i + 200])
    m = p.monitor()
    assert m["available"] and m["reference_size"] == 400 and m["score"]["status"] in ("stable", "moderate", "drift")
    assert m["quality"] and m["cumulative"]["tp"] > 0 and m["quality"][-1]["precision"] > 0.8
    # cold start: before the reference is captured the monitor says so instead of raising a false alarm
    q = Pipeline(settings, store=Store(":memory:"), bundle=bundle)
    q.process_events(ev[:300])
    assert q.monitor()["available"] is False and "reference" in q.monitor()["reason"]
    # a shifted live window must register as drift
    p.live_vecs.clear()
    for _ in range(400):
        p.live_vecs.append(np.full(len(bundle.baseline), 1e6))
    assert p.monitor()["overall"] == "drift"
    p.reset_drift_baseline()
    assert p.monitor()["available"] is False
