"""Runs the persistence layer and the full pipeline/API against a REAL PostgreSQL (embedded via pgserver). Skipped if unavailable."""
import time

import pytest

pgserver = pytest.importorskip("pgserver")
pytest.importorskip("psycopg", exc_type=ImportError)

from fastapi.testclient import TestClient  # noqa: E402

from aegis.api.app import create_app  # noqa: E402
from aegis.pipeline import Pipeline  # noqa: E402
from aegis.schemas import ClickEvent  # noqa: E402
from aegis.store.db import Store  # noqa: E402


@pytest.fixture(scope="module")
def pg_uri(tmp_path_factory):
    srv = pgserver.get_server(tmp_path_factory.mktemp("pgdata"), cleanup_mode="stop")
    yield srv.get_uri()
    srv.cleanup()


@pytest.fixture()
def pgstore(pg_uri):
    st = Store(pg_uri)
    for t in ("fraud_predictions", "click_events", "advertisements", "campaigns", "devices", "fraud_alerts", "blocked_entities",
              "attack_simulations", "recommendations", "system_events", "audit_log", "settings_kv", "model_versions", "api_settings", "users"):
        st.conn.execute(f"DELETE FROM {t}")
    st.conn.commit()
    yield st


def burst(user, n=60, t0=None, ua="Mozilla/5.0 (Windows NT 10.0)"):
    t0 = t0 or time.time()
    return [ClickEvent(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user, ip_address="7.7.7.7",
                       timestamp=t0 + i * 0.05, user_agent=ua) for i in range(n)]


def test_store_all_operations_on_postgres(pgstore):
    st = pgstore
    assert st.dialect == "postgres" and st.ping()
    st.add_user("a@b.c", "admin", "hash")
    st.add_user("a@b.c", "admin", "hash")  # INSERT OR IGNORE -> ON CONFLICT DO NOTHING
    u = st.get_user("a@b.c")
    assert u["role"] == "admin" and isinstance(u["id"], int)
    st.set_ai_settings(u["id"], "grok", "enc", "m", 0.2, True)
    st.set_ai_settings(u["id"], "openai", None, "m2", 0.3, False)  # upsert keeps old key
    a = st.get_ai_settings(u["id"])
    assert a["provider"] == "openai" and a["encrypted_key"] == "enc"
    st.set_kv("k", {"x": 1})
    st.set_kv("k", {"x": 2})
    assert st.get_kv("k") == {"x": 2}
    st.block("user", "U1", "r", 0.9)
    st.block("user", "U1", "r2", 0.95)  # replace
    assert len(st.list_blocked()) == 1 and st.list_blocked()[0]["reason"] == "r2"
    assert st.unblock("user", "U1") and st.list_blocked() == []
    aid = st.add_alert("HIGH", "t", "U1", "C10", {"a": 1})
    assert isinstance(aid, int) and st.set_alert_status(aid, "resolved") and st.list_alerts("open") == []
    sid = st.add_simulation("bot", {"d": 1}, [{"timestamp": 1.0}])
    assert st.get_simulation_events(sid) == [{"timestamp": 1.0}] and st.list_simulations()[0]["id"] == sid
    rid = st.add_recommendation("U1", "s", "bot", 0.9, "block", "rule-based", {})
    st.set_recommendation_status(rid, "approved")
    assert st.get_recommendation(rid)["status"] == "approved"
    st.upsert_model_version("v1", 1.0, "production", {"a": 1})
    st.upsert_model_version("v1", 1.0, "staged", {"a": 2})
    assert st.model_versions()[0]["status"] == "staged"
    st.audit("x", "y")
    st.system_event("k", "m")
    assert st.audit_log() and st.system_events()


def test_pipeline_end_to_end_on_postgres(pgstore, settings, bundle):
    old = time.time() - 40 * 86400
    p = Pipeline(settings, store=pgstore, bundle=bundle)
    p.submit(burst("UPG"))
    p.process_events(burst("UOLD", 5, t0=old))
    assert "UPG" in p.blocked_users and pgstore.list_blocked()
    assert p.status["database"]["state"] == "ONLINE" and p.status["database"]["detail"] == "postgres"
    assert pgstore.analytics()["totals"]["n"] > 50
    assert pgstore.get_prediction(next(iter(p.seen)))["scores"] is not None
    tl = pgstore.timeline("5m")
    assert tl["points"] and pgstore.device_types()[0]["k"] == "Desktop"
    cs = pgstore.campaign_stats({"C10": 12.0}, 9.0)
    assert cs[0]["campaign_id"] == "C10" and cs[0]["spend"] > 0
    assert pgstore.top_risk_users(3)[0]["user_id"] == "UPG"
    assert pgstore.user_events("UPG") and pgstore.recent_predictions(5)
    out = pgstore.prune(days=7)
    assert out["predictions"] == 5 and pgstore._one("SELECT COUNT(*) n FROM fraud_predictions")["n"] >= 50
    p.apply_rules({"max_clicks_per_min": 9})
    assert Pipeline(settings, store=pgstore, bundle=None).rules.cfg["max_clicks_per_min"] == 9  # persisted in PG


def test_api_runs_on_postgres_and_falls_back_when_down(pg_uri, settings, bundle, monkeypatch):
    settings.set("security.rate_limit_per_min", 10_000_000)
    monkeypatch.setenv("DATABASE_URL", pg_uri)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        assert c.app.state.store.dialect == "postgres"
        tok = c.post("/api/auth/login", json={"email": "analyst@aegis.local", "password": "analyst123"}).json()["token"]
        h = {"Authorization": "Bearer " + tok}
        r = c.post("/api/clicks", json={"user_id": "U003", "ad_id": "AD101", "count": 80, "profile": "rapid"}, headers=h).json()
        assert r["blocked"] and c.get("/api/analytics", headers=h).json()["totals"]["n"] >= 80
        assert c.get("/status").json()["components"]["database"]["detail"] == "postgres"
    monkeypatch.setenv("DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
    with TestClient(create_app(settings, bundle=bundle)) as c:  # unreachable Postgres -> graceful SQLite fallback
        assert c.app.state.store.dialect == "sqlite" and c.get("/status").json()["status"] == "OPERATIONAL"
