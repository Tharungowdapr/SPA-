import random

import numpy as np
import pytest

from aegis.agent.investigator import Investigator, LLMManager
from aegis.detection.explain import local_explanation
from aegis.detection.graph import GraphEngine
from aegis.detection.online import OnlineLearner, PageHinkley
from aegis.detection.risk import RiskEngine
from aegis.detection.rules import RuleEngine
from aegis.schemas import ClickEvent
from aegis.security.auth import (KeyVault, RateLimiter, create_token, decode_token, has_role, hash_ip, hash_password,
                                 mask_ip, verify_password)
from aegis.simulator.traffic import ATTACK_TYPES, build_episode, gen_attack
from aegis.store.db import Store
from aegis.streaming.bus import InMemoryBus, make_bus
from aegis.streaming.features import FEATURES, FeatureEngine, vectorize


def ev(user="U1", ts=1000.0, ad="AD100", device="D1", ip="1.2.3.4", ua="Mozilla/5.0 Chrome", camp="C10", country="IN"):
    return ClickEvent(user_id=user, ad_id=ad, campaign_id=camp, device_id=device, ip_address=ip, timestamp=ts,
                      user_agent=ua, country=country)


# ---------------------------------------------------------------- simulator
def test_simulator_deterministic_and_labeled():
    a, b = build_episode(5, n_users=50), build_episode(5, n_users=50)
    assert [e.event_id for e in a] == [e.event_id for e in b]
    assert {e.attack_type for e in a} >= {"normal", *ATTACK_TYPES}
    assert all(e.label in (0, 1) for e in a)
    assert all(a[i].timestamp <= a[i + 1].timestamp for i in range(len(a) - 1))


@pytest.mark.parametrize("kind", ATTACK_TYPES)
def test_each_attack_generates_fraud(kind):
    events = gen_attack(kind, random.Random(1), 1_000_000.0, 120)
    assert events and all(e.label == 1 and e.attack_type == kind for e in events)


def test_unknown_attack_rejected():
    with pytest.raises(ValueError):
        gen_attack("nope", random.Random(1), 1.0)


# ---------------------------------------------------------------- schema validation
def test_schema_rejects_injection_and_strips_truth():
    with pytest.raises(Exception):
        ClickEvent(user_id="U1; DROP TABLE", ad_id="A", campaign_id="C", device_id="D")
    with pytest.raises(Exception):
        ClickEvent(user_id="U1", ad_id="A", campaign_id="C", device_id="D", ip_address="<script>")
    e = ClickEvent(user_id="U1", ad_id="A", campaign_id="C", device_id="D", user_agent="<b>x</b>", label=1, attack_type="bot")
    assert "<" not in e.user_agent and e.public().label is None and e.public().attack_type is None


# ---------------------------------------------------------------- features
def test_feature_windows_and_intervals():
    fe = FeatureEngine()
    for i in range(12):
        f = fe.update(ev(ts=1000 + i * 0.1))
    assert f["clicks_10s"] == 12 and f["clicks_1m"] == 12 and f["min_interval"] == pytest.approx(0.1, abs=1e-6)
    f = fe.update(ev(ts=1000 + 4000))  # old events fall out of the 1h window
    assert f["clicks_1h"] == 1 and set(f) == set(FEATURES) and len(vectorize(f)) == len(FEATURES)


def test_feature_sharing_and_geo_and_late_event():
    fe = FeatureEngine()
    for i in range(5):
        f = fe.update(ev(user=f"U{i}", ts=1000 + i, device="DX", ip="9.9.9.9"))
    assert f["unique_users_per_device"] == 5 and f["unique_users_per_ip"] == 5
    f = fe.update(ev(user="U0", ts=1010, device="DX", ip="9.9.9.9", country="VN"))
    assert f["geo_user_countries"] == 2
    fe.update(ev(user="U0", ts=1005))  # late event must not raise
    assert fe.update(ev(ua="python-requests/2.0"))["ua_bot_flag"] == 1.0


# ---------------------------------------------------------------- rules / risk
def test_rules_fire_and_blocklist(settings):
    r = RuleEngine(settings.get("rules"))
    fe = FeatureEngine()
    for i in range(40):
        e = ev(ts=1000 + i * 0.1)
        f = fe.update(e)
    score, fired, hard = r.evaluate(e, f)
    assert "high_click_velocity" in fired and "tiny_interval" in fired and score >= 0.9 and not hard
    r.block_ip("1.2.3.4")
    assert r.evaluate(e, f)[2] is True
    calm = FeatureEngine().update(ev(ts=5000))
    assert r.evaluate(ev(ts=5000, ip="8.8.8.8"), calm)[1] == []


def test_risk_fusion_levels_and_renormalisation(settings):
    r = RiskEngine(settings.get("risk.weights"), settings.get("risk.levels"), 0.75, 0.6)
    assert r.fuse({"rules": 0.0, "ml": 0.0, "online": 0.0, "anomaly": 0.0, "graph": 0.0})[1:3] == ("LOW", "ALLOW")
    risk, lvl, act, conf = r.fuse({"rules": 1.0, "ml": 1.0, "online": 1.0, "anomaly": 1.0, "graph": 0.0})
    assert (lvl, act, conf) == ("CRITICAL", "BLOCK", "HIGH")
    risk, lvl, _, conf = r.fuse({"rules": 0.9, "ml": None, "online": None, "anomaly": None, "graph": None})
    assert risk == pytest.approx(0.9) and conf == "LOW"  # only rules available: renormalised, reduced confidence
    assert r.fuse({"rules": 0.0, "ml": 0.0, "graph": 0.9})[0] > 0.3  # graph evidence raises risk
    assert r.fuse({"rules": 0.0, "ml": 0.0}, hard=True)[0] >= 0.75
    assert r.fuse({"rules": None, "ml": None, "graph": None})[1] == "LOW"


# ---------------------------------------------------------------- graph
def test_graph_detects_shared_resource_ring():
    g = GraphEngine()
    for i in range(30):
        e = ev(user=f"U{i}", device=f"D{i}", ip=f"45.9.9.{i + 2}", ts=1000 + i)
        g.update(e)
    s, comp = g.score(e)
    assert s > 0.9 and comp["users"] == 30 and comp["subnets"] == 1
    lone = ev(user="L", device="DL", ip="77.1.1.1", ts=2000)
    g.update(lone)
    assert g.score(lone)[0] == 0.0
    assert g.export(user_id="U3")["nodes"]


# ---------------------------------------------------------------- security
def test_security_primitives():
    h = hash_password("pw", 1000)
    assert verify_password("pw", h) and not verify_password("x", h) and not verify_password("pw", "garbage")
    tok = create_token("s", "a@b", "analyst")
    assert decode_token("s", tok)["role"] == "analyst"
    with pytest.raises(Exception):
        decode_token("other", tok)
    assert has_role("admin", "analyst") and not has_role("viewer", "analyst")
    v = KeyVault("master")
    enc = v.encrypt("sk-abc")
    assert "sk-abc" not in enc and v.decrypt(enc) == "sk-abc"
    with pytest.raises(Exception):
        KeyVault("other").decrypt(enc)
    rl = RateLimiter(60, burst=3)
    assert [rl.allow("k") for _ in range(5)] == [True, True, True, False, False]
    assert mask_ip("192.168.1.45") == "192.168.x.x" and hash_ip("1.1.1.1", "s") != hash_ip("1.1.1.2", "s")


# ---------------------------------------------------------------- bus
def test_bus_offsets_groups_replay_and_fallback():
    b = InMemoryBus(buffer=5)
    for i in range(8):
        b.publish("t", {"i": i}, key=str(i))
    first = b.consume("t", "g1", 100)
    assert [m["value"]["i"] for m in first] == [3, 4, 5, 6, 7]  # bounded log keeps newest
    assert b.consume("t", "g1") == [] and b.lag("t", "g1") == 0
    assert len(b.consume("t", "g2")) == 5  # independent consumer group
    b.seek_beginning("t", "g1")
    assert len(b.consume("t", "g1")) == 5
    k = make_bus("127.0.0.1:1")
    assert k.mode == "memory" and "unavailable" in k.fallback_reason


# ---------------------------------------------------------------- store
def test_store_roundtrip_block_and_analytics():
    s = Store(":memory:")
    e = ev().model_dump() | {"ip_hash": "h"}
    d = {"event_id": e["event_id"], "timestamp": 1.0, "user_id": "U1", "risk": 0.95, "level": "CRITICAL", "action": "BLOCK",
         "confidence": "HIGH", "scores": {"ml": 0.9}, "rules_fired": ["x"], "model_version": "v", "latency_ms": 5.0,
         "top_factors": [{"label": "a"}], "ip_mask": "1.2.x.x"}
    s.save_batch([(e, d)])
    s.save_batch([(e, d)])  # idempotent
    p = s.get_prediction(e["event_id"])
    assert p["action"] == "BLOCK" and p["scores"]["ml"] == 0.9 and p["factors"][0]["label"] == "a"
    assert s.analytics()["totals"]["n"] == 1 and s.analytics(min_level="CRITICAL")["totals"]["flagged"] == 1
    s.block("user", "U1", "r", 0.9)
    assert len(s.list_blocked()) == 1 and s.unblock("user", "U1") and s.list_blocked() == []
    aid = s.add_alert("HIGH", "t", "U1", "C", {"a": 1})
    assert s.set_alert_status(aid, "resolved") and s.list_alerts("open") == []


# ---------------------------------------------------------------- online learning / drift
def test_page_hinkley_detects_shift():
    ph, rng = PageHinkley(threshold=5), random.Random(0)
    assert not any(ph.update(rng.random() * 0.1) for _ in range(300))
    assert any(ph.update(0.8 + rng.random() * 0.1) for _ in range(300))


def test_online_learner_delayed_commit_and_feedback(bundle):
    ol = OnlineLearner(bundle)
    x = np.asarray(vectorize(FeatureEngine().update(ev())))
    ol.stage("e1", x, 1, ts=100.0)
    assert ol.commit(now=110.0, delay=60) == 0 and ol.n_learned == 0  # poisoning defence: not yet
    assert ol.commit(now=200.0, delay=60) == 1 and ol.n_learned == 1
    ol.stage("e2", x, 1, ts=300.0)
    ol.confirm("e2", x, 0)  # analyst overrides the pseudo-label
    assert ol.n_learned == 2 and "e2" not in ol.pending


# ---------------------------------------------------------------- explainability
def test_local_explanation_is_additive_and_real(bundle):
    fe = FeatureEngine()
    for i in range(40):
        f = fe.update(ev(ts=1000 + i * 0.1, ua="curl/8"))
    x = np.asarray(vectorize(f))
    r = local_explanation(bundle, x, n_perm=20)
    total = sum(c for c in (bundle.ml_score(x.reshape(1, -1))[0] - r["base_probability"],))
    assert r["prediction"] > 0.5 and r["factors"] and r["factors"][0]["contribution"] > 0
    assert abs(r["prediction"] - r["base_probability"] - total) < 1e-3


# ---------------------------------------------------------------- agent
def _tools():
    return {"features": lambda u: {"unique_devices_per_ip": 9, "clicks_1m": 3}, "graph": lambda u: {"component": {"users": 25, "devices": 25, "subnets": 1}},
            "explanation": lambda u: {"factors": [{"label": "Devices behind IP", "value": 9}]}}


def test_agent_rule_fallback_and_llm_failure_degrades():
    rep = Investigator(_tools(), None).investigate("U1", 0.95)
    assert rep["mode"] == "rule-based" and rep["requires_approval"] and rep["recommendation"] == "block"
    llm = LLMManager("grok", "sk-secret", base_url="http://127.0.0.1:1/x")
    rep = Investigator(_tools(), llm).investigate("U1", 0.95)
    assert rep["mode"] == "rule-based" and "llm_error" in rep  # unreachable provider -> graceful fallback
    ok, msg = llm.test()
    assert not ok and "sk-secret" not in msg
    assert not LLMManager("disabled", "k").available and not LLMManager("grok", "").available and LLMManager("ollama", "").available


def test_langgraph_and_loop_engines_agree_and_degrade():
    pytest.importorskip("langgraph")
    a = Investigator(_tools(), None).investigate("U1", 0.95, engine="langgraph")
    b = Investigator(_tools(), None).investigate("U1", 0.95, engine="loop")
    assert a["engine"] == "langgraph" and b["engine"] == "loop"
    assert {k: a[k] for k in ("attack_type", "recommendation", "mode", "summary")} == {k: b[k] for k in ("attack_type", "recommendation", "mode", "summary")}
    llm = LLMManager("grok", "sk-x", base_url="http://127.0.0.1:1/x")
    c = Investigator(_tools(), llm).investigate("U1", 0.95, engine="langgraph")
    assert c["engine"] == "langgraph" and c["mode"] == "rule-based" and "llm_error" in c and c["requires_approval"]


def test_shap_library_explanation_is_additive(bundle):
    pytest.importorskip("shap")
    from aegis.detection.models import LGBMClassifier
    from aegis.detection.explain import shap_explanation
    if LGBMClassifier is None:
        pytest.skip("lightgbm is installed but not loadable on this host (e.g. blocked unsigned native lib)")
    assert {"xgb", "lgbm"} <= set(bundle.models)
    fe = FeatureEngine()
    for i in range(40):
        f = fe.update(ev(ts=1000 + i * 0.1, ua="curl/8"))
    x = np.asarray(vectorize(f))
    r = shap_explanation(bundle, x)
    assert r["method"] == "shap-library" and r["factors"][0]["contribution"] > 0
    assert abs(r["prediction"] - float(bundle.ml_score(x.reshape(1, -1))[0])) < 1e-3
    assert bundle.shap_importance and next(iter(bundle.shap_importance)) in FEATURES


def test_agent_and_explainer_work_without_optional_libraries(bundle, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.split(".")[0] in ("langgraph", "shap"):
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    rep = Investigator(_tools(), None).investigate("U1", 0.95)
    assert rep["engine"] == "loop" and rep["recommendation"] == "block"
    x = np.asarray(vectorize(FeatureEngine().update(ev(ua="curl/8"))))
    assert local_explanation(bundle, x, backend="auto")["method"] == "sampled-shapley"


def test_neo4j_mirror_with_fake_driver_and_failure_isolation():
    from aegis.detection.graph_neo4j import UPSERT, Neo4jMirror

    class Sess:
        def __init__(self, drv):
            self.d = drv

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, q, **kw):
            if self.d.fail:
                raise ConnectionError("neo4j down")
            self.d.calls.append((q, kw))
            return [{"kind": "Device", "n": 3}]

    class Drv:
        fail, calls = False, []

        def session(self):
            return Sess(self)

        def close(self):
            pass

    d = Drv()
    m = Neo4jMirror("bolt://x", driver=d, batch=2)
    for i in range(5):
        m.add(f"U{i}", f"D{i}", "iphash", "C10", float(i))
    assert m.flush() == 5 and m.healthy and [c[0] for c in d.calls] == [UPSERT] * 3 and d.calls[0][1]["rows"][0]["user"] == "U0"
    d.fail = True
    m.add("U9", "D9", "h", "C10", 9.0)
    assert m.flush() == 0 and not m.healthy and len(m.queue) == 1 and "ConnectionError" in m.last_error  # queued, not lost
    d.fail = False
    assert m.flush() == 1 and m.healthy and m.component("U1") == {"Device": 3}
    q = Neo4jMirror("bolt://x", driver=d, max_queue=3)
    for i in range(5):
        q.add("U", "D", "h", "C", float(i))
    assert q.dropped == 2 and len(q.queue) == 3  # bounded: never grows without limit


def test_pipeline_feeds_neo4j_mirror_and_survives_its_failure(settings, bundle):
    from aegis.detection.graph_neo4j import Neo4jMirror
    from aegis.pipeline import Pipeline
    from aegis.store.db import Store

    class Drv:
        def session(self):
            raise ConnectionError("down")

        def close(self):
            pass
    m = Neo4jMirror("bolt://x", driver=Drv())
    p = Pipeline(settings, store=Store(":memory:"), bundle=bundle, graph_mirror=m)
    out = p.process_events([ev(ts=1000 + i * 0.05, user="UN") for i in range(40)])
    assert out and len(m.queue) == 40
    m.flush()
    assert p.health()["components"]["neo4j"]["state"] == "DEGRADED" and p.health()["status"] == "DEGRADED"
