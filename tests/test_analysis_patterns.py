"""Steps 6-8: combined / targeted analysis, event log, saved attacks, pattern library."""
import time

import pytest

from aegis.detection import patterns
from aegis.pipeline import Pipeline
from aegis.schemas import ClickEvent
from aegis.store.db import Store


def burst(pipe, user="U1", n=25, ad="AD1", ip="9.9.9.9", device=None, campaign="C1"):
    """Feed a suspicious burst through the pipeline, the way the simulator would."""
    t0 = time.time()
    kw = {"user_id": user, "ad_id": ad, "device_id": device or ("D" + user), "ip_address": ip,
          "user_agent": "Mozilla/5.0 Chrome", "campaign_id": campaign or "UNATTR"}
    pipe.process_events([ClickEvent(timestamp=t0 + i * 0.05, **kw) for i in range(n)])


# ------------------------------------------------------------------ patterns module
def test_signature_needs_two_conditions():
    with pytest.raises(ValueError, match="at least 2"):
        patterns.validate_signature({"conditions": [{"field": "clicks_1m", "op": ">=", "value": 5}]})


def test_signature_rejects_junk():
    for bad in ({"conditions": [{"field": "a;b", "op": ">=", "value": 1}, {"field": "x", "op": ">=", "value": 1}]},
                {"conditions": [{"field": "clicks_1m", "op": "~~", "value": 1}, {"field": "x", "op": ">=", "value": 1}]},
                {"conditions": [{"field": "clicks_1m", "op": ">=", "value": "abc"}, {"field": "x", "op": ">=", "value": 1}]},
                {"conditions": []}):
        with pytest.raises(ValueError):
            patterns.validate_signature(bad)


def test_clean_text_strips_markup():
    out = patterns.clean_text("<img src=x onerror=alert(1)>hello")
    assert "<" not in out and "onerror=alert" not in out.replace(" ", "")
    assert len(patterns.clean_text("x" * 900)) <= 400


def test_classify_requires_agreement():
    assert patterns.classify({"clicks_1m": 2})["confident"] is False
    hot = patterns.classify({"clicks_1m": 40, "min_interval": 0.05})
    assert hot["confident"] and hot["n_conditions"] >= 2


def test_signature_matches_evaluates_ops():
    sig = {"conditions": [{"field": "clicks_1m", "op": ">=", "value": 20},
                          {"field": "interval_cv", "op": "<=", "value": 0.2}]}
    assert patterns.signature_matches(sig, {"clicks_1m": 30, "interval_cv": 0.1})[0]
    assert not patterns.signature_matches(sig, {"clicks_1m": 30, "interval_cv": 0.9})[0]


# ------------------------------------------------------------------ pipeline labelling
def test_patterns_label_without_blocking(settings):
    settings.set("risk.auto_block", False)
    store = Store(":memory:")
    p = Pipeline(settings, store=store)
    try:
        store.add_pattern("rush job", "many clicks very fast", "label",
                          {"conditions": [{"field": "clicks_1m", "op": ">=", "value": 5},
                                          {"field": "min_interval", "op": "<", "value": 0.5}]}, "analyst")
        burst(p)
        rows = store.log_events(level="HIGH") or store.log_events(limit=50)
        assert any("rush job" in (r.get("reason_title") or "") for r in rows)
        assert not store.list_blocked(), "patterns label, they never block"
        assert store.pattern_hit_counts(), "hits are recorded for the pattern"
    finally:
        store.close()


# ------------------------------------------------------------------ store queries
@pytest.fixture()
def pipe(settings):
    settings.set("risk.auto_block", False)
    p = Pipeline(settings, store=Store(":memory:"))
    yield p
    p.store.close()


def test_combined_groups_by_source(pipe):
    burst(pipe, "U1", 25, ad="ADX")
    burst(pipe, "U2", 25, ad="ADX")
    out = pipe.store.combined_attacks()
    assert out["clusters"], "suspicious clicks are grouped"
    row = out["clusters"][0]
    assert row["k"] == "C1" and row["users"] == 2, "campaign is the strongest shared key"
    burst(pipe, "U3", 25, ad="ADONLY", campaign="CAD2")
    keys = {c["k"] for c in pipe.store.combined_attacks()["clusters"]}
    assert keys == {"C1", "CAD2"}, "each campaign is its own cluster"
    assert out["kinds"]["totals"]["decisions"] > 0


def test_targeted_analysis_lists_victims(pipe):
    burst(pipe, "UV1", 25, campaign="CAMPA")
    out = pipe.store.targeted_analysis()
    assert any(v["user_id"] == "UV1" for v in out["victims"])
    assert any(c["campaign_id"] == "CAMPA" for c in out["campaigns"])
    assert out["at_risk_users"] >= 1


def test_log_events_filters(pipe):
    burst(pipe, "ULOG", 25, campaign="CLOG")
    assert pipe.store.log_events(campaign_id="CLOG")
    assert not pipe.store.log_events(campaign_id="NOPE")
    assert pipe.store.log_events(user_id="ULOG")
    assert pipe.store.log_events(q="ULOG")


def test_search_finds_across_sources(pipe):
    burst(pipe, "USRCH", 25, ad="ADSEARCH", campaign="CSRCH")
    out = pipe.store.search_everything("USRCH")
    assert any(u["user_id"] == "USRCH" for u in out["users"])
    assert out["ads"] == [], "the search term has to match the advert too"
    assert any(a["ad_id"] == "ADSEARCH" for a in pipe.store.search_everything("ADSEARCH")["ads"])
    assert not pipe.store.search_everything("nothing-here")["users"]


# ------------------------------------------------------------------ API
@pytest.fixture()
def client(settings, bundle):
    from fastapi.testclient import TestClient

    from aegis.api.app import create_app
    settings.set("security.rate_limit_per_min", 10_000_000)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        yield c


def auth(client, who="analyst"):
    r = client.post("/api/auth/login", json={"email": f"{who}@aegis.local", "password": f"{who}123"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_analysis_endpoints(client):
    burst(client.app.state.pipeline, "UAPI", 25, ad="ADAPI", campaign="CAPI")
    h = auth(client)
    combined = client.get("/api/analysis/combined", headers=h).json()
    assert combined["clusters"]
    target = client.get("/api/analysis/target", headers=h).json()
    assert target["victims"]
    found = client.get("/api/analysis/search?q=UAPI", headers=h).json()
    assert any(u["user_id"] == "UAPI" for u in found["users"])
    assert client.get("/api/analysis/search?q=", headers=h).status_code == 422, "empty search rejected"


def test_log_endpoint_filters(client):
    burst(client.app.state.pipeline, "ULOGAPI", 25, campaign="CLOGAPI")
    h = auth(client)
    assert client.get("/api/logs/events?campaign_id=CLOGAPI", headers=h).json()
    assert client.get("/api/logs/events?level=CRITICAL", headers=h).json()
    assert client.get("/api/logs/events?level=BOGUS", headers=h).status_code == 422


def test_pattern_crud_and_preview(client):
    h = auth(client)
    body = {"name": "fast and wide", "description": "click flood", "action": "label",
            "signature": {"conditions": [{"field": "clicks_1m", "op": ">=", "value": 5},
                                         {"field": "min_interval", "op": "<", "value": 0.5}]}}
    r = client.post("/api/patterns", json=body, headers=h)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    listing = client.get("/api/patterns", headers=h).json()
    assert listing["max"] == 200 and listing["builtins"] and any(p["id"] == pid for p in listing["patterns"])
    assert client.post("/api/patterns", json={**body, "signature": {"conditions": []}},
                       headers=h).status_code == 422
    assert client.post("/api/patterns/preview", json={"signature": body["signature"]},
                       headers=h).status_code == 200
    assert client.post("/api/patterns", json=body, headers=auth(client, "viewer")).status_code == 403
    assert client.delete(f"/api/patterns/{pid}", headers=h).status_code == 400, "confirm required"
    assert client.delete(f"/api/patterns/{pid}?confirm=true", headers=h).json()["ok"]


def test_saved_attack_lifecycle(client):
    store = client.app.state.store
    sim_id = store.add_simulation("bot_burst", {"n": 3}, [{"user_id": "U1", "ad_id": "AD1"}])
    h = auth(client)
    saved = client.post(f"/api/simulations/{sim_id}/save", json={"name": "my attack"}, headers=h).json()
    assert saved["name"] == "my attack"
    assert any(s["id"] == sim_id for s in client.get("/api/simulations/saved", headers=h).json())
    export = client.get(f"/api/simulations/{sim_id}/export", headers=h).json()
    assert export["schema"] == "aegis.saved_attack.v1"
    imported = client.post("/api/simulations/import", json=export, headers=h).json()
    assert imported["events"] == 1
    assert client.post(f"/api/simulations/{sim_id}/save", json={"name": "bad<script>"},
                       headers=h).status_code == 200, "markup is stripped, not rejected"
    assert client.delete(f"/api/simulations/{sim_id}", headers=h).status_code == 400, "confirm required"
    assert client.delete(f"/api/simulations/{sim_id}?confirm=true", headers=h).json()["ok"]


def test_import_rejects_junk(client):
    h = auth(client)
    assert client.post("/api/simulations/import", json={"kind": "x"}, headers=h).status_code == 400
    assert client.post("/api/simulations/import", json={"kind": "x", "events": [{"user_id": "U"}]},
                       headers=h).status_code == 400
    r = client.post("/api/simulations/import",
                    json={"kind": "x", "events": [{"user_id": "U1", "ad_id": "AD1", "source": "spoofed"}]},
                    headers=h)
    assert r.status_code == 200, "a valid import is accepted"
    rows = client.app.state.store.get_simulation_events(r.json()["id"])
    assert rows[0]["source"] == "import", "import never keeps a claimed source"


def test_compare_needs_two(client):
    store = client.app.state.store
    a = store.add_simulation("bot_burst", {}, [{"user_id": "U1", "ad_id": "AD1"}])
    b = store.add_simulation("slow_burn", {}, [{"user_id": "U2", "ad_id": "AD2"}])
    h = auth(client)
    assert client.get(f"/api/simulations/compare?a={a}&b={a}", headers=h).status_code == 400
    assert client.get(f"/api/simulations/compare?a={a}&b={b}", headers=h).status_code == 200
    assert client.get(f"/api/simulations/compare?a={a}&b=99999", headers=h).status_code == 404
