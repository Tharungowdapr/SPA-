"""Shared-state layer against a REAL Redis server (embedded via redislite). Skipped if unavailable."""
import time

import pytest

redislite = pytest.importorskip("redislite")
pytest.importorskip("redis")

from fastapi.testclient import TestClient  # noqa: E402

from aegis.api.app import create_app  # noqa: E402
from aegis.pipeline import Pipeline  # noqa: E402
from aegis.schemas import ClickEvent  # noqa: E402
from aegis.store.db import Store  # noqa: E402
from aegis.store.state import RedisState, StateRateLimiter, make_state  # noqa: E402


@pytest.fixture()
def rurl(tmp_path):
    srv = redislite.Redis(str(tmp_path / "r.db"))
    srv.flushall()
    yield "unix://" + srv.socket_file
    srv.shutdown()


def burst(user, n=60):
    t0 = time.time()
    return [ClickEvent(user_id=user, ad_id="AD100", campaign_id="C10", device_id="D" + user, ip_address="7.7.7.7",
                       timestamp=t0 + i * 0.05) for i in range(n)]


def test_redis_state_primitives(rurl):
    st = make_state(rurl)
    assert st.mode == "redis" and st.ping()
    st.block_add("user", "U1")
    st.block_add("ip", "1.2.3.4")
    assert st.blocked("user") == {"U1"} and st.blocked("ip") == {"1.2.3.4"}
    st.block_remove("user", "U1")
    assert st.blocked("user") == set()
    st.touch_active("U1", time.time())
    st.touch_active("U2", time.time() - 500)
    assert st.active_count(60) == 1
    assert [st.incr_click("U9") for _ in range(3)] == [1, 2, 3]
    lim = StateRateLimiter(st, 3)
    assert [lim.allow("c") for _ in range(5)] == [True, True, True, False, False]
    st.publish_stats({"a": 1})
    assert st.get_stats() == {"a": 1}


def test_blocklist_shared_between_two_pipelines(rurl, settings, bundle):
    a = Pipeline(settings, store=Store(":memory:"), bundle=bundle, state=make_state(rurl))
    b = Pipeline(settings.copy(), store=Store(":memory:"), bundle=bundle, state=make_state(rurl))
    a.submit(burst("USH"))
    assert "USH" in a.blocked_users and "USH" not in b.blocked_users
    b.sync_blocklist()
    assert "USH" in b.blocked_users and all(x["status"] == "rejected" for x in b.submit(burst("USH", 3)))
    a.unblock_entity("user", "USH")
    b.sync_blocklist()
    assert "USH" not in b.blocked_users


def test_redis_failure_degrades_without_stopping_detection(rurl, settings, bundle):
    st = make_state(rurl)
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle, state=st)
    class Dead:  # every Redis call now raises, as if the server vanished
        def __getattr__(self, name):
            raise ConnectionError("redis down")

    st.r = Dead()
    out = p.process_events(burst("UDEG"))
    assert out and "UDEG" in p.blocked_users  # local state still works
    assert st.healthy is False and p.health()["components"]["state"]["state"] == "DEGRADED"
    assert StateRateLimiter(st, 1).allow("x") is True  # fail-open


def test_unreachable_redis_falls_back_to_memory():
    st = make_state("redis://127.0.0.1:1/0")
    assert st.mode == "memory" and "unavailable" in st.fallback_reason


def test_api_with_redis(rurl, settings, bundle, monkeypatch):
    settings.set("security.rate_limit_per_min", 10_000_000)
    monkeypatch.setenv("REDIS_URL", rurl)
    with TestClient(create_app(settings, bundle=bundle)) as c:
        assert isinstance(c.app.state.pipeline.state, RedisState)
        assert c.get("/status").json()["components"]["state"]["detail"] == "redis"
        tok = c.post("/api/auth/login", json={"email": "analyst@aegis.local", "password": "analyst123"}).json()["token"]
        h = {"Authorization": "Bearer " + tok}
        assert c.post("/api/clicks", json={"user_id": "U004", "ad_id": "AD101", "count": 80, "profile": "rapid"}, headers=h).json()["blocked"]
        assert "U004" in c.app.state.pipeline.state.blocked("user")
        time.sleep(1.5)
        assert c.get("/api/stats/shared", headers=h).json()["stats"]["total_events"] >= 80
