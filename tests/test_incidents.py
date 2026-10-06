"""Step 4: incidents. Decisions that share an entity (or a campaign+attack inside the short
window) merge into one incident; idle incidents close; analysts can block every entity at once."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.pipeline import Pipeline
from aegis.schemas import ClickEvent
from aegis.store.db import Store


def click(user, device, ip, campaign="C10", ts=None, ua="Mozilla/5.0 Chrome", attack=None, n=25):
    t0 = ts if ts is not None else time.time()
    return [ClickEvent(user_id=user, ad_id="AD1", campaign_id=campaign, device_id=device, ip_address=ip,
                       user_agent=ua, timestamp=t0 + i * 0.05, attack_type=attack) for i in range(n)]


@pytest.fixture()
def pipe(settings):
    p = Pipeline(settings, store=Store(":memory:"))
    yield p
    p.store.close()


@pytest.fixture()
def correlator(settings):
    """Auto-blocking off: these tests exercise correlation only, not the blocking side effects."""
    settings.set("risk.auto_block", False)
    p = Pipeline(settings, store=Store(":memory:"))
    yield p
    p.store.close()


def test_same_user_merges_into_one_incident(pipe):
    pipe.process_events(click("UI1", "DI1", "9.1.1.1", ts=1000.0))
    pipe.process_events(click("UI1", "DI1", "9.1.1.1", ts=1010.0))
    incs = pipe.store.list_incidents(50)
    assert len(incs) == 1, "the same account must not open a second incident"
    assert incs[0]["users_n"] == 1
    assert incs[0]["events_n"] >= 25


def test_shared_device_merges_two_users(correlator):
    correlator.process_events(click("UI1", "DSHARED", "9.1.1.1", ts=1000.0))
    correlator.process_events(click("UI2", "DSHARED", "9.2.2.2", ts=1005.0))
    incs = correlator.store.list_incidents(50)
    assert len(incs) == 1
    assert incs[0]["users_n"] == 2, "two accounts on one device are one incident"


def test_shared_ip_merges(correlator):
    correlator.process_events(click("UI3", "DA", "9.3.3.3", ts=1000.0))
    correlator.process_events(click("UI4", "DB", "9.3.3.3", ts=1005.0))
    assert len(correlator.store.list_incidents(50)) == 1


def test_shared_subnet_merges(correlator):
    correlator.process_events(click("UI5", "DC", "9.4.1.1", ts=1000.0))
    correlator.process_events(click("UI6", "DD", "9.4.2.2", ts=1005.0))
    assert len(correlator.store.list_incidents(50)) == 1, "the same /24 counts as one group"


def test_unrelated_activity_stays_separate(correlator):
    correlator.process_events(click("UI7", "DX", "1.1.1.1", ts=1000.0))
    correlator.process_events(click("UI8", "DY", "2.2.2.2", ts=1005.0))
    assert len(correlator.store.list_incidents(50)) == 2


def test_campaign_and_attack_merge_inside_the_short_window(correlator):
    correlator.process_events(click("UI9", "DZ", "3.3.3.3", campaign="CMERGE", attack="click_farm", ts=2000.0))
    correlator.process_events(click("UI10", "DW", "4.4.4.4", campaign="CMERGE", attack="click_farm", ts=2060.0))
    assert len(correlator.store.list_incidents(50)) == 1, "same campaign + attack inside 120s merges"


def test_campaign_and_attack_do_not_merge_outside_the_window(correlator):
    correlator.process_events(click("UI11", "DV", "5.5.5.5", campaign="COLD", attack="click_farm", ts=3000.0))
    correlator.process_events(click("UI12", "DU", "6.6.6.6", campaign="COLD", attack="click_farm", ts=3400.0))
    assert len(correlator.store.list_incidents(50)) == 2, "400s apart is outside the 120s campaign window"


def test_idle_incident_reads_as_closed(pipe):
    pipe.process_events(click("UI13", "DT", "7.7.7.7", ts=1000.0))
    assert pipe.store.list_incidents(50, now=1100.0)[0]["status"] == "open"
    assert pipe.store.list_incidents(50, now=1500.0)[0]["status"] == "closed", "300s idle closes it"
    assert pipe.store.list_incidents(50, status="closed", now=1500.0)


def test_incident_carries_classification_and_reason(pipe):
    out = pipe.process_events(click("UI14", "DR", "8.8.8.8", ts=1000.0))
    hot = next(d for d in out if d.level in ("HIGH", "CRITICAL"))
    assert hot.incident_id
    inc = pipe.store.get_incident(hot.incident_id)
    assert inc["classification"]
    assert inc["summary"]
    assert inc["events_n"] >= 25
    assert inc["peak_risk"] > 0


def test_low_risk_clicks_open_no_incident(settings):
    p = Pipeline(settings, store=Store(":memory:"))
    slow = [ClickEvent(user_id="ULO", ad_id="AD1", campaign_id="CL", device_id="DLO", ip_address="8.8.4.4",
                       user_agent="Mozilla/5.0 Chrome", timestamp=1000.0 + i * 30.0) for i in range(10)]
    p.process_events(slow)
    assert p.store.list_incidents(50) == []
    p.store.close()


# ------------------------------------------------------------------ API
@pytest.fixture()
def client(settings, bundle):
    app = create_app(settings, bundle=bundle)
    with TestClient(app) as c:
        yield c
    app.state.store.close() if hasattr(app.state, "store") else None


def _auth(client, who="analyst"):
    r = client.post("/api/auth/login", json={"email": f"{who}@aegis.local", "password": f"{who}123"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_incident_endpoints(client):
    h = _auth(client, "admin")
    evs = [{"user_id": "UAPI", "ad_id": "AD1", "campaign_id": "CAPI", "device_id": "DAPI",
            "ip_address": "9.9.9.9", "user_agent": "Mozilla/5.0 Chrome"} for _ in range(25)]
    client.post("/api/events", json=evs, headers=h)

    r = client.get("/api/incidents", headers=h)
    assert r.status_code == 200
    rows = r.json()
    assert rows and rows[0]["entities_preview"]

    iid = rows[0]["id"]
    d = client.get(f"/api/incidents/{iid}", headers=h)
    assert d.status_code == 200
    body = d.json()
    assert body["combined"]["events"] >= 1
    assert body["combined"]["users"] == ["UAPI"]
    assert body["combined"]["reasons"], "the incident must summarise why it was flagged"
    assert body["entities"]

    assert client.get("/api/incidents/999999", headers=h).status_code == 404


def test_block_all_requires_confirmation_and_blocks(client):
    h = _auth(client, "admin")
    evs = [{"user_id": "UBLK", "ad_id": "AD1", "campaign_id": "CBLK", "device_id": "DBLK",
            "ip_address": "9.9.8.8", "user_agent": "Mozilla/5.0 Chrome"} for _ in range(25)]
    client.post("/api/events", json=evs, headers=h)
    iid = client.get("/api/incidents", headers=h).json()[0]["id"]

    assert client.post(f"/api/incidents/{iid}/block-all", headers=h).status_code == 400, "confirm required"
    for b in client.get("/api/blocked", headers=h).json():          # clear the engine's auto-blocks first
        client.delete(f"/api/blocked/{b['entity_type']}/{b['entity_id']}?confirm=true", headers=h)
    r = client.post(f"/api/incidents/{iid}/block-all?confirm=true", headers=h)
    assert r.status_code == 200 and r.json()["count"] >= 1
    blocked = client.get("/api/blocked", headers=h).json()
    assert any(b["entity_id"] == "UBLK" for b in blocked)
    detail = next(b for b in blocked if b["entity_id"] == "UBLK")
    assert detail["reason_detail"]["incident_id"] == iid, "the block records which incident caused it"


def test_viewer_cannot_block_an_incident(client):
    h = _auth(client, "admin")
    evs = [{"user_id": "UVIEW", "ad_id": "AD1", "campaign_id": "CVIEW", "device_id": "DVIEW",
            "ip_address": "9.9.7.7", "user_agent": "Mozilla/5.0 Chrome"} for _ in range(25)]
    client.post("/api/events", json=evs, headers=h)
    iid = client.get("/api/incidents", headers=h).json()[0]["id"]
    vh = _auth(client, "viewer")
    assert client.get("/api/incidents", headers=vh).status_code == 200, "viewers may read"
    assert client.post(f"/api/incidents/{iid}/block-all?confirm=true", headers=vh).status_code == 403


def test_alert_carries_its_incident_id(client):
    h = _auth(client, "admin")
    evs = [{"user_id": "UALERT", "ad_id": "AD1", "campaign_id": "CALERT", "device_id": "DALERT",
            "ip_address": "9.9.6.6", "user_agent": "Mozilla/5.0 Chrome"} for _ in range(25)]
    client.post("/api/events", json=evs, headers=h)
    alerts = client.get("/api/alerts", headers=h).json()
    linked = [a for a in alerts if a.get("incident_id")]
    assert linked, "alerts raised during an incident point back at it"
    assert client.get(f"/api/incidents/{linked[0]['incident_id']}", headers=h).status_code == 200
