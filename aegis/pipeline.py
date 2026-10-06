"""Pipeline orchestrator: click -> features -> rules/ML/anomaly/graph/online -> fusion -> action.

Every advanced layer is optional. A failure in any layer is caught, recorded in the component status
table, and the remaining layers keep working (weights are renormalised, confidence is reduced).
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque
from typing import Callable

import numpy as np

from aegis.agent.investigator import Investigator, LLMManager
from aegis.config import Settings
from aegis.detection.explain import local_explanation, rule_factors, shap_available
from aegis.detection.graph import GraphEngine
from aegis.detection.models import ModelBundle, psi
from aegis.detection import patterns as pattern_lib
from aegis.detection.online import OnlineLearner
from aegis.detection.reasons import explain_decision
from aegis.detection.risk import RiskEngine
from aegis.detection.rules import RuleEngine, validate_rules
from aegis.schemas import ClickEvent, Decision
from aegis.security.auth import hash_ip, mask_ip
from aegis.store.db import Store
from aegis.store.state import MemoryState
from aegis.streaming.bus import InMemoryBus
from aegis.streaming.features import FEATURES, FeatureEngine, vectorize

GROUP = "fraud-engine"
_SHAP_WARMED = False   # SHAP JIT-compiles once per process; warming it again per Pipeline would waste CPU


class _LRU(OrderedDict):
    def __init__(self, cap: int):
        super().__init__()
        self.cap = cap

    def put(self, k, v):
        self[k] = v
        self.move_to_end(k)
        while len(self) > self.cap:
            self.popitem(last=False)


class Pipeline:
    def __init__(self, settings: Settings, store: Store | None = None, bus=None, bundle: ModelBundle | None = None, state=None, graph_mirror=None):
        self.s = settings
        self.mirror = graph_mirror
        self.state = state or MemoryState()
        self.store = store or Store(":memory:")
        self.bus = bus or InMemoryBus()
        self.topics = settings.get("bus.topics")
        self.salt = settings.secret_key[:16]
        rules_cfg = settings.get("rules")
        self.fe = FeatureEngine(settings.get("features.max_window_events", 2000), rules_cfg.get("bot_user_agents"))
        self.rules = RuleEngine(rules_cfg)
        self.graph = GraphEngine(settings.get("features.graph_edge_ttl", 900), settings.get("features.graph_rebuild_every", 200))
        self.risk = RiskEngine(settings.get("risk.weights"), settings.get("risk.levels"), settings.get("risk.hard_rule_floor", 0.75),
                               settings.get("risk.graph_boost", 0.6))
        self.lock = threading.RLock()
        self.bundle: ModelBundle | None = None
        self.online: OnlineLearner | None = None
        self.status: dict[str, dict] = {k: {"state": "OFFLINE", "detail": ""} for k in
                                        ("ml", "anomaly", "graph", "online", "agent", "database")}
        self.llm = LLMManager(settings.get("agent.provider", "disabled"), os.environ.get("LLM_API_KEY", ""),
                              settings.get("agent.model", ""), settings.get("agent.temperature", 0.2))
        self.agent_enabled = bool(settings.get("agent.enabled", False))
        self.explain_backend = settings.get("ml.explain_backend", "auto")
        # state
        self.blocked_users: set[str] = set()
        self.blocked_devices: set[str] = set()
        self.seen = _LRU(200_000)
        self.last_seen = _LRU(20_000)       # user -> (event, feats, vec, decision)
        self.ingest_ts = _LRU(50_000)        # event_id -> wall time at ingest (detection latency)
        self.vectors = _LRU(10_000)         # event_id -> vec (analyst feedback)
        self.crit_hits: dict[str, deque] = defaultdict(deque)
        self.last_alert: dict[str, float] = {}
        self.cluster_blocks: dict[str, deque] = defaultdict(deque)
        self.cluster_until: dict[str, float] = {}
        # incident correlation (Change 4)
        self.inc_keys: dict[int, set[str]] = {}       # incident id -> correlation keys it already covers
        self.inc_last: dict[int, float] = {}          # incident id -> last activity seen in memory
        self.inc_hydrated = False
        self.block_links: dict[str, set] = defaultdict(set)   # user -> devices auto-blocked together with it
        self.listeners: list[Callable[[list[Decision]], None]] = []
        # stats
        self.t_started = time.time()
        self.total = self.flagged = self.rejected = self.dups = self.invalid = 0
        self.levels = defaultdict(int)
        self.latencies: deque = deque(maxlen=5000)
        self.rate: deque = deque(maxlen=2000)
        self.active_users: dict[str, float] = {}
        self.recent: deque = deque(maxlen=500)
        self.drift_events = 0
        dc = settings.get("ml.drift", {}) or {}
        self.drift_cfg = {"warmup_s": float(dc.get("warmup_s", 600)), "ref_size": int(dc.get("ref_size", 1500)), "window": int(dc.get("window", 1500))}
        self.live_vecs: deque = deque(maxlen=self.drift_cfg["window"])
        self.live_ml: deque = deque(maxlen=self.drift_cfg["window"])
        self.first_ts: float | None = None
        self.ref_vecs: list = []
        self.ref_ml: list = []
        self.ref_done = False
        self.quality: OrderedDict = OrderedDict()   # 10 s bucket -> [tp, fp, fn, tn] (simulated ground truth only)
        self._load_rules_override()
        self._load_blocklist()
        self.set_bundle(bundle)
        self._refresh_agent_status()
        self.status["graph"] = {"state": "ONLINE", "detail": ""}
        self.status["database"] = {"state": "ONLINE" if self.store.ping() else "OFFLINE", "detail": getattr(self.store, "dialect", "sqlite")}

    # ================================================================ lifecycle
    def set_bundle(self, bundle: ModelBundle | None) -> None:
        with self.lock:
            self.bundle = bundle
            self.online = None
            if bundle is None:
                for k in ("ml", "anomaly", "online"):
                    self.status[k] = {"state": "OFFLINE", "detail": "no model loaded - rules-only mode"}
                return
            self.status["ml"] = {"state": "ONLINE", "detail": bundle.version}
            self.status["anomaly"] = {"state": "ONLINE", "detail": "isolation forest"}
            if self.s.get("ml.online_enabled", True):
                try:
                    self.online = OnlineLearner(bundle)
                    self.status["online"] = {"state": "ONLINE", "detail": "sgd + page-hinkley"}
                except Exception as exc:  # noqa: BLE001
                    self._fail("online", exc)
            else:
                self.status["online"] = {"state": "DISABLED", "detail": "ml.online_enabled=false"}

    @property
    def explain_method(self) -> str:
        return "shap-library" if (self.explain_backend in ("auto", "shap") and shap_available()) else "sampled-shapley"

    def warm_explainer(self) -> None:
        """SHAP's first call JIT-compiles (seconds); do it off the request path."""
        global _SHAP_WARMED
        if _SHAP_WARMED:
            return
        _SHAP_WARMED = True

        def run():
            try:
                if self.bundle is not None and self.explain_method == "shap-library":
                    local_explanation(self.bundle, self.bundle.baseline.copy(), backend="shap")
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=run, daemon=True).start()

    def configure_llm(self, provider: str, api_key: str | None, model: str, temperature: float, enabled: bool) -> None:
        key = api_key if api_key is not None else self.llm.api_key
        self.llm = LLMManager(provider, key, model, temperature)
        self.agent_enabled = enabled
        self._refresh_agent_status()

    def _refresh_agent_status(self) -> None:
        if not self.agent_enabled:
            self.status["agent"] = {"state": "DISABLED", "detail": "rule-based explanation mode"}
        elif self.llm.available:
            self.status["agent"] = {"state": "ONLINE", "detail": f"{self.llm.provider}:{self.llm.model}"}
        else:
            self.status["agent"] = {"state": "DEGRADED", "detail": "enabled but no provider/key - rule-based fallback"}

    def _fail(self, name: str, exc: Exception) -> None:
        self.status[name] = {"state": "DEGRADED", "detail": f"{type(exc).__name__}: {str(exc)[:120]}"}

    # ------------------------------------------------------------ rules (live-editable, persisted)
    def _load_rules_override(self) -> None:
        try:
            ov = self.store.get_kv("rules_override")
            if ov:
                self.rules.update(validate_rules(ov))
                self.fe.bot_tokens = [t.lower() for t in self.rules.cfg.get("bot_user_agents", self.fe.bot_tokens)]
        except Exception:  # noqa: BLE001 - corrupt override must not stop startup
            pass

    def rules_config(self) -> dict:
        c = self.rules.cfg
        return {k: c.get(k) for k in ("max_clicks_per_min", "min_interval_s", "min_interval_clicks", "max_users_per_device",
                                       "max_devices_per_ip", "repeat_ad_ratio", "repeat_ad_min_clicks", "weights", "bot_user_agents")} | \
            {"blocked_ips": sorted(self.rules.blocked_ips)}

    def apply_rules(self, update: dict, by: str = "admin") -> dict:
        clean = validate_rules(update)
        with self.lock:
            self.rules.update(clean)
            if "bot_user_agents" in clean:
                self.fe.bot_tokens = [t.lower() for t in clean["bot_user_agents"]]
            persist = {k: v for k, v in {**(self.store.get_kv("rules_override") or {}), **clean}.items()}
            if "weights" in clean:
                persist["weights"] = {**((self.store.get_kv("rules_override") or {}).get("weights", {})), **clean["weights"]}
            self.store.set_kv("rules_override", persist)
            self.store.audit(by, "rules_update", "", json.dumps(clean)[:500])
        return self.rules_config()

    def _load_blocklist(self) -> None:
        for b in self.store.list_blocked():
            self.state.block_add(b["entity_type"], b["entity_id"])
            (self.blocked_users if b["entity_type"] == "user" else self.blocked_devices if b["entity_type"] == "device"
             else set()).add(b["entity_id"])
            if b["entity_type"] == "ip":
                self.rules.block_ip(b["entity_id"])

    # ================================================================ blocking
    def sync_blocklist(self) -> None:
        """Adopt the shared (Redis) block-list so several workers / restarts agree. No-op for in-memory state."""
        if self.state.mode != "redis":
            return
        for kind, local in (("user", self.blocked_users), ("device", self.blocked_devices), ("ip", self.rules.blocked_ips)):
            remote = self.state.blocked(kind)
            if remote is not None:
                with self.lock:
                    local.clear()
                    local.update(remote)

    def is_blocked(self, e: ClickEvent) -> bool:
        return (e.user_id in self.blocked_users or e.device_id in self.blocked_devices
                or e.ip_address in self.rules.blocked_ips)

    def block_entity(self, etype: str, eid: str, reason: str, score: float = 1.0, by: str = "analyst",
                       reason_detail: dict | None = None) -> None:
        with self.lock:
            self.store.block(etype, eid, reason, score, by, reason_detail=reason_detail)
            if etype == "user":
                self.blocked_users.add(eid)
            elif etype == "device":
                self.blocked_devices.add(eid)
            elif etype == "ip":
                self.rules.block_ip(eid)
            self.state.block_add(etype, eid)
            self.store.audit(by, "block", f"{etype}:{eid}", reason)
            self.bus.publish(self.topics["blocks"], {"type": "USER_BLOCKED" if etype == "user" else "ENTITY_BLOCKED",
                                                      "entity_type": etype, "entity_id": eid, "reason": reason,
                                                      "score": score, "by": by, "ts": time.time()}, key=eid)

    def unblock_entity(self, etype: str, eid: str, by: str = "analyst") -> bool:
        with self.lock:
            ok = self.store.unblock(etype, eid)
            self.blocked_users.discard(eid) if etype == "user" else self.blocked_devices.discard(eid) if etype == "device" \
                else self.rules.blocked_ips.discard(eid)
            self.crit_hits.pop(eid, None)
            self.state.block_remove(etype, eid)
            if etype == "user":  # release the devices that were auto-blocked together with this user
                for dev in self.block_links.pop(eid, set()):
                    self.store.unblock("device", dev)
                    self.blocked_devices.discard(dev)
                    self.state.block_remove("device", dev)
            self.store.audit(by, "unblock", f"{etype}:{eid}")
            self.bus.publish(self.topics["blocks"], {"type": "ENTITY_UNBLOCKED", "entity_type": etype, "entity_id": eid,
                                                      "by": by, "ts": time.time()}, key=eid)
            return ok

    # ================================================================ ingestion
    def submit(self, events: list[ClickEvent]) -> list[dict]:
        """Public ingest path: reject blocked traffic, publish to the bus, process inline in memory mode."""
        acks, accepted = [], []
        for e in events:
            if self.is_blocked(e):
                self.rejected += 1
                acks.append({"event_id": e.event_id, "status": "rejected", "reason": "blocked"})
            else:
                accepted.append(e)
                self.ingest_ts.put(e.event_id, time.time())
                acks.append({"event_id": e.event_id, "status": "accepted"})
                self.bus.publish(self.topics["clicks"], e.model_dump(), key=e.user_id)
        if self.s.get("app.sync_processing", True) and self.bus.mode == "memory":
            self.pump()
        return acks

    def pump(self, max_events: int = 2000) -> list[Decision]:
        """Consume click events from the bus (consumer group `fraud-engine`) and score them."""
        msgs = self.bus.consume(self.topics["clicks"], GROUP, max_events)
        events = []
        for m in msgs:
            try:
                events.append(ClickEvent(**m["value"]))
            except Exception:  # noqa: BLE001
                self.invalid += 1
        return self.process_events(events) if events else []

    # ================================================================ core
    def process_events(self, events: list[ClickEvent], persist: bool = True) -> list[Decision]:
        t0 = time.perf_counter()
        with self.lock:
            return self._process(events, persist, t0)

    def process_event(self, e: ClickEvent) -> Decision | None:
        out = self.process_events([e])
        return out[0] if out else None

    def _process(self, events: list[ClickEvent], persist: bool, t0: float) -> list[Decision]:
        results: list[Decision | None] = []
        live: list[tuple[int, ClickEvent, dict, np.ndarray, float, list[str], bool, float | None]] = []
        for e in events:
            if e.event_id in self.seen:
                self.dups += 1
                continue
            self.seen.put(e.event_id, 1)
            if self.is_blocked(e):
                self.rejected += 1
                rd = self._rejected(e)
                self._quality(rd)
                results.append(rd)
                continue
            f = self.fe.update(e)
            gs = None
            try:
                self.graph.update(e)
                if self.mirror is not None:
                    self.mirror.add(e.user_id, e.device_id, hash_ip(e.ip_address, self.salt), e.campaign_id, e.timestamp)
                gs, _ = self.graph.score(e)
                if self.status["graph"]["state"] != "ONLINE":
                    self.status["graph"] = {"state": "ONLINE", "detail": ""}
            except Exception as exc:  # noqa: BLE001
                self._fail("graph", exc)
            rs, fired, hard = self.rules.evaluate(e, f)
            results.append(None)
            live.append((len(results) - 1, e, f, np.asarray(vectorize(f)), rs, fired, hard, gs))

        if live:
            X = np.vstack([row[3] for row in live])
            ml = self._batch("ml", lambda: self.bundle.ml_score(X), len(live))
            an = self._batch("anomaly", lambda: self.bundle.anomaly_score(X), len(live))
            on = self._batch("online", lambda: self.online.score(X), len(live))
            batch_ms = (time.perf_counter() - t0) * 1000.0
            now = time.time()
            n_explain = 0
            for i, (slot, e, f, vec, rs, fired, hard, gs) in enumerate(live):
                scores = {"rules": rs, "ml": _v(ml, i), "online": _v(on, i), "anomaly": _v(an, i), "graph": gs}
                risk, level, action, conf = self.risk.fuse(scores, hard)
                factors: list[dict] = []
                if level in ("HIGH", "CRITICAL"):
                    if scores["ml"] is None:        # cheap rule-based explanation: always available
                        factors = rule_factors(fired, f)
                    elif n_explain < 15:            # Shapley sampling is costly: cap per batch, rest explained on demand
                        n_explain += 1
                        factors = self._explain(vec, fired, f, True)
                t_in = self.ingest_ts.pop(e.event_id, None)
                lat = (now - t_in) * 1000.0 if t_in else batch_ms   # ingest -> decision
                d = Decision(
                    event_id=e.event_id, timestamp=e.timestamp, user_id=e.user_id, ad_id=e.ad_id,
                    campaign_id=e.campaign_id, device_id=e.device_id, ip_mask=mask_ip(e.ip_address),
                    risk=round(risk, 4), level=level, action=action, confidence=conf,
                    scores={k: (round(v, 4) if v is not None else None) for k, v in scores.items()},
                    rules_fired=fired, top_factors=factors, model_version=self.bundle.version if self.bundle else "none",
                    latency_ms=round(lat, 2), label=e.label, attack_type=e.attack_type,
                    features={k: v for k, v in f.items() if isinstance(v, (int, float))})
                # Plain-English reason, derived from the rules and features that fired (no model needed).
                why = explain_decision(event=e, decision=d, features=f, rule_hits=fired, scores=scores,
                                       graph_context=gs if isinstance(gs, dict) else {},
                                       thresholds=self.rules.cfg)
                d.reason, d.reason_title = why["reason"], why["title"]
                if level in ("HIGH", "CRITICAL"):
                    labels = self._label_patterns(e, f)
                    if labels:
                        d.reason_title = f"{d.reason_title} ({', '.join(labels[:2])})"
                if level == "CRITICAL" and self.s.get("risk.auto_block", True):
                    d.blocked_now = self._register_critical(e, d)
                if level in ("HIGH", "CRITICAL"):
                    try:
                        d.incident_id = self._correlate(e, d)
                    except Exception as exc:  # noqa: BLE001 - correlation must never stop detection
                        self.store.system_event("incident_error", f"correlation failed: {type(exc).__name__}: {exc}")
                        d.incident_id = None
                    self._maybe_alert(e, d, incident_id=d.incident_id)
                results[slot] = d
                self.vectors.put(e.event_id, vec)
                self.live_vecs.append(vec)
                if scores["ml"] is not None:
                    self.live_ml.append(scores["ml"])
                if self.first_ts is None:
                    self.first_ts = e.timestamp
                if not self.ref_done and e.timestamp - self.first_ts >= self.drift_cfg["warmup_s"]:
                    self.ref_vecs.append(vec)
                    if scores["ml"] is not None:
                        self.ref_ml.append(scores["ml"])
                    self.ref_done = len(self.ref_vecs) >= self.drift_cfg["ref_size"]
                self._quality(d)
                self._stage_pseudo_label(e, vec, scores, level)
                self.last_seen.put(e.user_id, (e, f, vec, d))
                self._count(d, now)
                if self.online and self.online.observe(risk):
                    self._on_drift(now)
            if persist:
                self._persist([(r, e) for r, (_, e, *_rest) in zip([results[l[0]] for l in live], live)])
        out = [r for r in results if r is not None]
        if out:
            self._emit(out)
        return out

    # ------------------------------------------------------------ helpers
    def _batch(self, name: str, fn: Callable[[], np.ndarray], n: int):
        if name == "ml" and self.bundle is None or name == "anomaly" and self.bundle is None:
            return None
        if name == "online" and self.online is None:
            return None
        try:
            out = fn()
            if self.status[name]["state"] == "DEGRADED":  # recovered
                self.status[name] = {"state": "ONLINE", "detail": "recovered"}
            return out
        except Exception as exc:  # noqa: BLE001 - layer failure must never stop detection
            self._fail(name, exc)
            return None

    def _explain(self, vec: np.ndarray, fired: list[str], f: dict, ml_ok: bool) -> list[dict]:
        if ml_ok and self.bundle is not None:
            try:
                return local_explanation(self.bundle, vec, backend="shapley")["factors"]   # live path: fast estimator (SHAP library is ~4x slower)
            except Exception as exc:  # noqa: BLE001
                self._fail("ml", exc)
        return rule_factors(fired, f)

    def _stage_pseudo_label(self, e: ClickEvent, vec: np.ndarray, scores: dict, level: str) -> None:
        """Poisoning defence: pseudo-labels are OFF by default (ml.online_learn_confirmed_only=true). When enabled,
        only events where rules AND the ML ensemble agree are staged, and they are committed after a delay
        unless an analyst contradicts them (OnlineLearner.confirm overrides the staged label)."""
        if self.online is None or self.s.get("ml.online_learn_confirmed_only", True):
            return
        if level == "CRITICAL" and (scores["rules"] or 0) >= 0.9 and (scores["ml"] or 0) >= 0.9:
            self.online.stage(e.event_id, vec, 1, time.time())
        elif level == "LOW" and (scores["ml"] or 1) <= 0.02 and hash(e.event_id) % 50 == 0:  # sparse benign sample
            self.online.stage(e.event_id, vec, 0, time.time())

    def _rejected(self, e: ClickEvent) -> Decision:
        d = Decision(event_id=e.event_id, timestamp=e.timestamp, user_id=e.user_id, ad_id=e.ad_id,
                     campaign_id=e.campaign_id, device_id=e.device_id, ip_mask=mask_ip(e.ip_address), risk=1.0,
                     level="CRITICAL", action="REJECTED", confidence="HIGH", scores={}, rules_fired=["blocked_entity"],
                     label=e.label, attack_type=e.attack_type)
        d.reason, d.reason_title = explain_decision(event=e, decision=d)["reason"], "Already blocked"
        return d

    def _register_critical(self, e: ClickEvent, d: Decision) -> bool:
        now = time.time()
        q = self.crit_hits[e.user_id]
        q.append(now)
        while q and now - q[0] > 300:
            q.popleft()
        if len(q) < self.s.get("risk.block_min_hits", 2):
            return False
        reason = "auto: risk %.2f (%s)" % (d.risk, ", ".join(d.rules_fired) or "ml/graph/anomaly")
        detail = {"title": d.reason_title, "reason": d.reason,
                  "event_id": d.event_id, "level": d.level, "scores": d.scores,
                  "rules": d.rules_fired, "factors": d.top_factors[:3], "risk": d.risk,
                  "user_id": e.user_id, "device_id": e.device_id, "campaign_id": e.campaign_id}
        self.block_entity("user", e.user_id, reason, d.risk, by="engine", reason_detail=detail)
        self.block_entity("device", e.device_id, reason, d.risk, by="engine", reason_detail=detail)
        self.block_links[e.user_id].add(e.device_id)
        cb = self.cluster_blocks[e.campaign_id]
        cb.append(now)
        while cb and now - cb[0] > 120:
            cb.popleft()
        if len(cb) >= 5 and self.cluster_until.get(e.campaign_id, 0) < now:
            self.cluster_until[e.campaign_id] = now + 120
            aid = self.store.add_alert("CRITICAL", f"Distributed click attack detected on {e.campaign_id}", None,
                                       e.campaign_id, {"users_blocked_2min": len(cb), "risk": d.risk})
            self.bus.publish(self.topics["alerts"], {"alert_id": aid, "severity": "CRITICAL", "campaign": e.campaign_id,
                                                     "users": len(cb)}, key=e.campaign_id)
        return True

    def _maybe_alert(self, e: ClickEvent, d: Decision, incident_id: int | None = None) -> None:
        now = time.time()
        if now - self.last_alert.get(e.user_id, 0) < 300 or self.cluster_until.get(e.campaign_id, 0) > now:
            return
        self.last_alert[e.user_id] = now
        sev = "CRITICAL" if d.level == "CRITICAL" else "HIGH"
        detail = {"title": d.reason_title, "reason": d.reason, "event_id": d.event_id, "level": d.level,
                  "scores": d.scores, "rules": d.rules_fired, "factors": d.top_factors[:3], "risk": d.risk}
        aid = self.store.add_alert(sev, f"Suspicious activity: {e.user_id}", e.user_id, e.campaign_id,
                                   {"risk": d.risk, "rules": d.rules_fired, "factors": d.top_factors[:3],
                                    "event_id": e.event_id, "reason": d.reason,
                                    "reason_title": d.reason_title, "reason_detail": detail,
                                    "incident_id": incident_id})
        if incident_id:
            self.store.set_alert_incident(aid, incident_id)
        self.bus.publish(self.topics["alerts"], {"alert_id": aid, "severity": sev, "user_id": e.user_id,
                                                 "risk": d.risk}, key=e.user_id)

    def _on_drift(self, now: float) -> None:
        self.drift_events += 1
        self.store.system_event("drift", "Page-Hinkley drift detected on risk-score stream")
        self.bus.publish(self.topics["model_updates"], {"type": "DRIFT_DETECTED", "ts": now})

    def _quality(self, d: Decision) -> None:
        """Rolling confusion counts per 10 s bucket (only events with simulated ground truth)."""
        if d.label is None:
            return
        detected = d.action in ("FLAG", "BLOCK", "REJECTED")
        b = self.quality.setdefault(int(time.time() // 10) * 10, [0, 0, 0, 0])
        b[0 if (detected and d.label == 1) else 1 if detected else 2 if d.label == 1 else 3] += 1
        while len(self.quality) > 360:
            self.quality.popitem(last=False)

    def reset_drift_baseline(self) -> None:
        with self.lock:
            self.first_ts, self.ref_vecs, self.ref_ml, self.ref_done = None, [], [], False
            self.live_vecs.clear()
            self.live_ml.clear()

    # ================================================================ reset / clear
    def _live_state_size(self) -> int:
        return (len(self.seen) + len(self.last_seen) + len(self.ingest_ts) + len(self.vectors) + len(self.active_users)
                + sum(len(v) for v in self.crit_hits.values()) + sum(len(v) for v in self.cluster_blocks.values())
                + len(self.last_alert) + len(self.recent) + len(self.live_vecs) + len(self.quality))

    def _clear_live_state(self) -> None:
        """Empty the in-memory trackers: active users, click/session counters, graph clusters,
        duplicate-event memory and the rolling statistics. Detection keeps running."""
        self.seen.clear()
        self.last_seen.clear()
        self.ingest_ts.clear()
        self.vectors.clear()
        self.crit_hits.clear()
        self.cluster_blocks.clear()
        self.cluster_until.clear()
        self.block_links.clear()
        self.last_alert.clear()
        self.active_users.clear()
        if hasattr(self.fe, "seen"):
            self.fe.seen.clear()
        if hasattr(self.graph, "clear"):
            self.graph.clear()
        self.recent.clear()
        self.quality.clear()
        self.latencies.clear()
        self.rate.clear()
        self.total = self.flagged = self.rejected = self.dups = self.invalid = 0
        self.levels.clear()
        self.state.clear_live()
        self.reset_drift_baseline()
        if self.online is not None and hasattr(self.online, "reset"):
            try:
                self.online.reset()
            except Exception:  # noqa: BLE001 - learner state is best-effort
                pass

    def reset_preview(self, scopes: tuple[str, ...] | list[str] | None = None) -> dict:
        """Row counts each scope would remove, for the confirmation dialog."""
        counts = self.store.reset_counts()
        counts["live_state"] = self._live_state_size()
        wanted = list(self.store.ALL_SCOPES) if scopes is None else list(scopes)
        return {"counts": counts, "selected": {s: counts.get(s, 0) for s in wanted},
                "total": sum(counts.get(s, 0) for s in wanted), "presets": sorted(self.store.PRESETS)}

    def reset(self, scopes: tuple[str, ...] | list[str], actor: str = "analyst", preset: str = "") -> dict:
        """Clear the requested scopes. Runs under the pipeline lock, is idempotent and always
        forgets duplicate-event memory so a replayed run is ingested again."""
        unknown = [s for s in scopes if s not in self.store.ALL_SCOPES]
        if unknown:
            raise ValueError(f"unknown scope(s): {', '.join(unknown)}")
        with self.lock:
            deleted = self.store.execute_reset(scopes)
            self._clear_live_state()          # always: duplicate memory and live trackers
            if "blocklist" in scopes:
                self.blocked_users.clear()
                self.blocked_devices.clear()
                self.rules.blocked_ips.clear()
                self._load_blocklist()         # re-read whatever survived
            if preset == "factory_reset":
                deleted["rules_override"] = self.store.clear_rules_override()
                self.rules.update(validate_rules(self.s.get("rules", {}) or {}))
                self.fe.bot_tokens = [t.lower() for t in self.rules.cfg.get("bot_user_agents", self.fe.bot_tokens)]
            deleted["live_state"] = 1
            self.store.audit(actor, "reset", ",".join(scopes), f"preset={preset or '-'} " + json.dumps(deleted))
            self.store.system_event("reset", f"{actor} cleared {', '.join(scopes)}")
        self.bus.publish(self.topics["model_updates"], {"type": "RESET", "scopes": list(scopes), "ts": time.time()})
        return {"deleted": deleted, "scopes": list(scopes), "preset": preset, "ts": time.time()}

    def monitor(self) -> dict:
        """Model monitoring: feature/prediction drift (PSI vs training) and live precision/recall over time."""
        qs, cum = [], [0, 0, 0, 0]
        for t, (tp, fp, fn, tn) in self.quality.items():
            cum = [cum[0] + tp, cum[1] + fp, cum[2] + fn, cum[3] + tn]
            qs.append({"t": t, "precision": cum[0] / (cum[0] + cum[1]) if cum[0] + cum[1] else None,
                       "recall": cum[0] / (cum[0] + cum[2]) if cum[0] + cum[2] else None,
                       "window_precision": tp / (tp + fp) if tp + fp else None, "window_recall": tp / (tp + fn) if tp + fn else None,
                       "events": tp + fp + fn + tn})
        out = {"quality": qs, "cumulative": {"tp": cum[0], "fp": cum[1], "fn": cum[2], "tn": cum[3]}, "window": len(self.live_vecs),
               "available": False}
        b = self.bundle
        dcfg = self.drift_cfg
        if b is None or b.feat_edges is None:
            out["reason"] = "no model" if b is None else "retrain the model to enable drift binning"
            return out
        if not self.ref_done:
            out["reason"] = (f"capturing reference window: {len(self.ref_vecs)}/{dcfg['ref_size']} events "
                             f"(starts after {dcfg['warmup_s']:.0f}s of traffic so 1h windows warm up)")
            return out
        X, R = np.vstack(self.live_vecs), np.vstack(self.ref_vecs)

        def prop(j: int, rows: np.ndarray) -> np.ndarray:
            edges = b.feat_edges[FEATURES[j]]
            return np.bincount(np.searchsorted(edges, rows[:, j], side="right"), minlength=len(edges) + 1) / len(rows)
        feats = {f: round(psi(prop(j, R), prop(j, X)), 4) for j, f in enumerate(FEATURES)}
        skew = {f: round(psi(b.feat_base[f], prop(j, R)), 4) for j, f in enumerate(FEATURES)}
        ls = np.histogram(np.asarray(self.live_ml), bins=10, range=(0, 1))[0] / max(1, len(self.live_ml))
        rs = np.histogram(np.asarray(self.ref_ml), bins=10, range=(0, 1))[0] / max(1, len(self.ref_ml))
        sp = round(psi(rs, ls), 4)
        status = lambda v: "stable" if v < 0.1 else "moderate" if v < 0.25 else "drift"  # noqa: E731
        out.update(available=True, feature_psi=dict(sorted(feats.items(), key=lambda kv: -kv[1])),
                   feature_status={k: status(v) for k, v in feats.items()},
                   score={"psi": sp, "status": status(sp), "baseline": [round(float(x), 4) for x in rs],
                          "live": [round(float(x), 4) for x in ls]},
                   overall=status(max(list(feats.values()) + [sp])), reference_size=len(self.ref_vecs),
                   training_skew_max=max(skew.values()), training_skew_top=sorted(skew.items(), key=lambda kv: -kv[1])[:3],
                   note="PSI of the latest window vs a reference window captured after warm-up. training_skew_* compares that reference "
                        "to the training data (informational: training episodes are short, so some skew is expected).")
        return out

    def _count(self, d: Decision, now: float) -> None:
        self.total += 1
        self.levels[d.level] += 1
        if d.action in ("FLAG", "BLOCK"):
            self.flagged += 1
        self.latencies.append(d.latency_ms)
        self.active_users[d.user_id] = now
        self.state.touch_active(d.user_id, now)
        self.state.incr_click(d.user_id)
        self.recent.append(d)

    def _persist(self, pairs: list[tuple[Decision, ClickEvent]]) -> None:
        rows = []
        for d, e in pairs:
            ev = e.model_dump()
            ev["ip_hash"] = hash_ip(e.ip_address, self.salt)
            rows.append((ev, d.model_dump()))
        try:
            self.store.save_batch(rows)
            self.status["database"] = {"state": "ONLINE", "detail": getattr(self.store, "dialect", "sqlite")}
        except Exception as exc:  # noqa: BLE001 - DB failure must not stop scoring
            self.status["database"] = {"state": "DEGRADED", "detail": f"{type(exc).__name__}: {exc}"[:120]}

    def _emit(self, decisions: list[Decision]) -> None:
        now = time.time()
        self.rate.append((now, len(decisions)))
        for d in decisions:
            self.bus.publish(self.topics["predictions"], {"event_id": d.event_id, "user_id": d.user_id, "risk": d.risk,
                                                          "level": d.level, "action": d.action, "ts": d.timestamp},
                             key=d.user_id)
        for fn in list(self.listeners):
            try:
                fn(decisions)
            except Exception:  # noqa: BLE001
                pass

    # ================================================================ feedback & investigation
    def feedback(self, event_id: str, label: int, actor: str = "analyst") -> bool:
        vec = self.vectors.get(event_id)
        if vec is None or self.online is None:
            return False
        with self.lock:
            self.online.confirm(event_id, vec, int(label))
        self.store.audit(actor, "feedback", event_id, f"label={label}")
        return True

    # ------------------------------------------------------------ incidents
    def _pattern_cache(self) -> list[dict]:
        """Saved patterns change rarely, so cache them and reload when the table version moves."""
        try:
            ver = self.store._one("SELECT COUNT(*) n, MAX(COALESCE(updated, created)) v FROM patterns")
        except Exception:  # noqa: BLE001 - patterns must never stop detection
            return []
        key = (ver.get("n"), ver.get("v"))
        if getattr(self, "_pattern_key", None) != key:
            self._patterns = [p for p in self.store.list_patterns() if p.get("enabled", 1)]
            self._pattern_key = key
        return getattr(self, "_patterns", [])

    def _label_patterns(self, e, feats: dict) -> list[str]:
        """Label a suspicious decision with matching patterns. Never blocks: patterns are advisory."""
        hits: list[str] = []
        feats = feats or {}
        for p in self._pattern_cache():
            ok, _ = pattern_lib.signature_matches(p.get("signature") or {}, feats)
            if not ok:
                continue
            hits.append(p["name"])
            try:
                self.store.add_pattern_hit(int(p["id"]), e.timestamp, e.event_id, e.user_id, e.device_id)
            except Exception:  # noqa: BLE001 - hit recording is best effort
                pass
        return hits

    def _incident_cfg(self) -> dict:
        c = self.s.get("incident", {}) or {}
        return {"close_after": float(c.get("merge_after_s", 300)),
                "campaign_window": float(c.get("campaign_window_s", 120)),
                "min_level": str(c.get("min_level", "HIGH")),
                "keep_last": int(c.get("keep_last", 200))}

    def _incident_keys(self, e: ClickEvent, d: Decision) -> set[str]:
        """Every way this click could belong to an existing incident.

        Shared user / device / IP / subnet / link-graph group, plus campaign+attack type, which only
        merges inside the shorter campaign window.
        """
        keys = {f"user:{e.user_id}", f"device:{e.device_id}"}
        if e.ip_address:
            keys.add(f"ip:{mask_ip(e.ip_address)}")
            try:
                keys.add("subnet:" + ".".join(e.ip_address.split(".")[:3]) + ".0/24")
            except Exception:  # noqa: BLE001 - malformed address, skip the subnet key
                pass
        try:                                   # stable group id: the lowest device id in the component
            comp = self.graph.component(e)
            seed = sorted(comp.get("D") or comp.get("U") or [])
            if seed:
                keys.add("graph:" + seed[0])
        except Exception:  # noqa: BLE001 - the graph layer must never break detection
            pass
        if e.attack_type:
            keys.add(f"campaign_attack:{e.campaign_id}|{e.attack_type}")
        return keys

    def _hydrate_incidents(self) -> None:
        """Rebuild the in-memory correlation index after a restart."""
        if self.inc_hydrated:
            return
        self.inc_hydrated = True
        now = time.time()
        for inc in self.store.candidate_incidents(now - 86400):
            keys = self._incident_keys_from_row(inc)
            if keys:
                self.inc_keys[inc["id"]] = keys
            self.inc_last[inc["id"]] = inc.get("last_seen") or now

    def _incident_keys_from_row(self, inc: dict) -> set[str]:
        keys = {f"campaign_attack:{c}|{inc.get('classification') or ''}" for c in (inc.get("campaigns") or [])[:1]}
        for ent in self.store.incident_entities(int(inc["id"])):
            t, i = ent["entity_type"], ent["entity_id"]
            keys.add(f"{t}:{i}")
            if t == "ip":
                keys.add("subnet:" + ".".join(i.split(".")[:3]) + ".0/24")
        return keys

    def _close_stale_incidents(self, now: float) -> None:
        """Incidents with no new activity inside the window are closed."""
        close_after = self._incident_cfg()["close_after"]
        for iid, last in list(self.inc_last.items()):
            if now - last > close_after:
                self.store.update_incident(iid, last, status="closed")
                self.inc_keys.pop(iid, None)
                self.inc_last.pop(iid, None)

    def _correlate(self, e: ClickEvent, d: Decision) -> int | None:
        """Attach a suspicious decision to an incident, merging into a recent one when they overlap.

        Returns the incident id, or None when this decision is not incident-worthy.
        """
        cfg = self._incident_cfg()
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if order.get(d.level, 0) < order.get(cfg["min_level"], 2):
            return None
        now = e.timestamp or time.time()
        self._hydrate_incidents()
        self._close_stale_incidents(now)
        keys = self._incident_keys(e, d)
        camp_key = next((k for k in keys if k.startswith("campaign_attack:")), None)

        target: int | None = None
        for iid, known in sorted(self.inc_keys.items(), key=lambda kv: -self.inc_last.get(kv[0], 0.0)):
            hit = keys & known
            if not hit:
                continue
            if hit == {camp_key} and camp_key and now - self.inc_last.get(iid, 0.0) > cfg["campaign_window"]:
                continue                      # campaign-only overlap is too weak, and too old
            target = iid
            break

        if target is None:
            target = self.store.add_incident(now, now, self._incident_title(e, d), round(d.risk, 3), e.run_id)
            self.store.system_event("incident", f"Incident #{target} opened: {self._incident_title(e, d)}")
        else:
            self.store.update_incident(target, now, peak_risk=d.risk)

        for etype, eid in (("user", e.user_id), ("device", e.device_id), ("ip", mask_ip(e.ip_address))):
            if eid:
                self.store.add_incident_entity(target, etype, eid, now, flagged=1, peak_risk=d.risk,
                                              blocked=1 if self.is_blocked_entity(etype, eid) else 0)
        self.store.add_incident_campaign(target, e.campaign_id)
        self.store.refresh_incident_counts(target)
        self.store.update_incident(target, now, summary=self._incident_summary(target))
        self.inc_keys[target] = self.inc_keys.get(target, set()) | keys
        self.inc_last[target] = now
        self._trim_incidents()
        return target

    def _incident_title(self, e: ClickEvent, d: Decision) -> str:
        if e.attack_type:
            return f"{d.reason_title or d.level.title()} on {e.campaign_id}"
        return d.reason_title or f"{d.level.title()} activity on {e.campaign_id}"

    def _incident_summary(self, incident_id: int) -> str:
        inc = self.store.get_incident(incident_id) or {}
        users, devices = inc.get("users_n") or 0, inc.get("devices_n") or 0
        camps = ", ".join(inc.get("campaigns") or []) or "no campaign"
        return (f"{inc.get('events_n') or 0} suspicious clicks from {users} account(s) across {devices} "
                f"device(s) on {camps}; peak risk {(inc.get('peak_risk') or 0):.2f}")

    def _trim_incidents(self) -> None:
        keep = self._incident_cfg()["keep_last"]
        excess = len(self.inc_keys) - keep
        if excess <= 0:
            return
        for iid, _ in sorted(self.inc_keys.items(), key=lambda kv: self.inc_last.get(kv[0], 0.0))[:excess]:
            self.inc_keys.pop(iid, None)
            self.inc_last.pop(iid, None)

    def is_blocked_entity(self, etype: str, eid: str) -> bool:
        return (eid in self.blocked_users if etype == "user"
                else eid in self.blocked_devices if etype == "device"
                else eid in self.rules.blocked_ips)

    def _tools(self) -> dict[str, Callable[[str], object]]:
        def last(u):
            return self.last_seen.get(u)

        def features(u):
            r = last(u)
            return r[1] if r else {}

        def history(u):
            return self.fe.history(u, 30)

        def graph(u):
            r = last(u)
            comp = self.graph.score(r[0])[1] if r else {}
            return {"component": comp, "subgraph": self.graph.export(user_id=u, limit=40)}

        def device(u):
            r = last(u)
            if not r:
                return {}
            d = self.fe.device.get(r[0].device_id)
            return {"device_id": r[0].device_id, "clicks_1h": len(d.ts) if d else 0,
                    "users": len({v[0] for v in d.vals}) if d else 0}

        def campaign(u):
            r = last(u)
            return {"campaign_id": r[0].campaign_id, "share_5m": r[1]["campaign_click_share_5m"]} if r else {}

        def explanation(u):
            r = last(u)
            return local_explanation(self.bundle, r[2], backend=self.explain_backend) if (r and self.bundle) else {}

        def decision(u):
            r = last(u)
            d = r[3] if r else None
            return ({"event_id": d.event_id, "risk": d.risk, "level": d.level, "action": d.action,
                     "rules": d.rules_fired, "reason": d.reason, "reason_title": d.reason_title,
                     "blocked_now": d.blocked_now} if d else {})

        return {"features": features, "history": history, "graph": graph, "device_profile": device,
                "campaign_stats": campaign, "explanation": explanation, "decision": decision}

    def investigate(self, user_id: str) -> dict:
        r = self.last_seen.get(user_id)
        risk = r[3].risk if r else 0.0
        inv = Investigator(self._tools(), self.llm if self.agent_enabled else None)
        rep = inv.investigate(user_id, risk, engine=self.s.get("agent.engine", "auto"))
        rec_id = self.store.add_recommendation(user_id, rep["summary"], rep["attack_type"], rep["confidence"],
                                               rep["recommendation"], rep["mode"],
                                               {k: v for k, v in rep.items() if k != "evidence"})
        rep["recommendation_id"] = rec_id
        r_seen = self.last_seen.get(user_id)
        if r_seen is not None:            # same plain-English reason as the alert and blocklist
            rep.setdefault("reason", r_seen[3].reason)
            rep.setdefault("reason_title", r_seen[3].reason_title)
            rep.setdefault("event_id", r_seen[3].event_id)
        self.bus.publish(self.topics["agent"], {"recommendation_id": rec_id, "user_id": user_id,
                                                "action": rep["recommendation"], "mode": rep["mode"]}, key=user_id)
        return rep

    # ================================================================ observability
    def snapshot(self) -> dict:
        now = time.time()
        recent = [(t, n) for t, n in self.rate if now - t <= 10]
        eps = sum(n for _, n in recent) / 10.0
        lats = sorted(self.latencies)
        pct = (lambda q: lats[min(len(lats) - 1, int(q * len(lats)))] if lats else 0.0)
        for u in [u for u, t in self.active_users.items() if now - t > 60]:
            del self.active_users[u]
        return {
            "events_per_sec": round(eps, 1), "total_events": self.total, "flagged": self.flagged,
            "fraud_rate": round(self.flagged / self.total, 4) if self.total else 0.0,
            "blocked_users": len(self.blocked_users), "blocked_devices": len(self.blocked_devices),
            "rejected": self.rejected, "duplicates": self.dups, "invalid": self.invalid,
            "active_users": self.state.active_count(60) if self.state.mode == "redis" else len(self.active_users),
            "active_campaigns": len({d.campaign_id for d in self.recent}),
            "levels": dict(self.levels), "latency_ms": {"p50": round(pct(0.5), 2), "p95": round(pct(0.95), 2),
                                                        "avg": round(sum(lats) / len(lats), 2) if lats else 0.0},
            "model_version": self.bundle.version if self.bundle else "none", "drift_events": self.drift_events,
            "online_learned": self.online.n_learned if self.online else 0, "uptime_s": round(now - self.t_started, 1),
            "bus": self.bus.stats() | {"lag": self.bus.lag(self.topics["clicks"], GROUP)},
        }

    def health(self) -> dict:
        bus = {"state": "ONLINE" if self.bus.mode == "kafka" else "FALLBACK",
               "detail": self.bus.mode + (f" ({self.bus.fallback_reason})" if getattr(self.bus, "fallback_reason", "") else "")}
        st = self.state
        state = ({"state": "ONLINE" if st.healthy else "DEGRADED", "detail": "redis" + (f" ({st.last_error})" if not st.healthy else "")}
                 if st.mode == "redis" else {"state": "FALLBACK", "detail": "memory" + (f" ({st.fallback_reason})" if st.fallback_reason else "")})
        comps = {"bus": bus, "state": state, **self.status}
        if self.mirror is not None:
            comps["neo4j"] = {"state": "ONLINE" if self.mirror.healthy else "DEGRADED", "detail": f"queued {len(self.mirror.queue)}" + (f" ({self.mirror.last_error})" if not self.mirror.healthy else "")}
        core_ok = comps["database"]["state"] != "OFFLINE"
        overall = "OPERATIONAL" if core_ok and all(c["state"] in ("ONLINE", "DISABLED", "FALLBACK") for c in comps.values()) \
            else "DEGRADED" if core_ok else "DOWN"
        mode = ("full-ai" if self.agent_enabled and self.llm.available else
                "ml-only" if self.bundle else "rules-only") + ("" if self.bus.mode == "kafka" else "+offline-bus")
        return {"status": overall, "mode": mode, "components": comps}

    def metrics_text(self) -> str:
        s = self.snapshot()
        L = []

        def m(name: str, typ: str, help_: str, samples: list[tuple[str, float]]) -> None:
            L.append(f"# HELP {name} {help_}")
            L.append(f"# TYPE {name} {typ}")
            L.extend(f"{name}{lbl} {val}" for lbl, val in samples)
        m("aegis_events_total", "counter", "Click events scored", [("", s["total_events"])])
        m("aegis_flagged_total", "counter", "Events flagged HIGH or above", [("", s["flagged"])])
        m("aegis_rejected_total", "counter", "Clicks rejected because the entity is blocked", [("", s["rejected"])])
        m("aegis_decisions_total", "counter", "Decisions by risk level", [(f'{{level="{k}"}}', v) for k, v in sorted(self.levels.items())])
        m("aegis_blocked_users", "gauge", "Currently blocked users", [("", s["blocked_users"])])
        m("aegis_active_users", "gauge", "Users active in the last minute", [("", s["active_users"])])
        m("aegis_events_per_second", "gauge", "Event throughput (10 s window)", [("", s["events_per_sec"])])
        m("aegis_detection_latency_ms", "gauge", "Ingest-to-decision latency (ms)",
          [('{quantile="0.5"}', s["latency_ms"]["p50"]), ('{quantile="0.95"}', s["latency_ms"]["p95"]), ('{quantile="avg"}', s["latency_ms"]["avg"])])
        m("aegis_consumer_lag", "gauge", "Unprocessed events on the click topic", [("", s["bus"]["lag"])])
        m("aegis_drift_events_total", "counter", "Page-Hinkley drift detections", [("", s["drift_events"])])
        m("aegis_online_updates_total", "counter", "Online learner updates", [("", s["online_learned"])])
        m("aegis_model_info", "gauge", "Production model version", [(f'{{version="{s["model_version"]}"}}', 1)])
        m("aegis_component_up", "gauge", "Component health (1 = ONLINE/DISABLED/FALLBACK)",
          [(f'{{component="{k}"}}', 1 if v["state"] in ("ONLINE", "DISABLED", "FALLBACK") else 0) for k, v in self.health()["components"].items()])
        mon = self.monitor()
        cum = mon["cumulative"]
        tp, fp, fn = cum["tp"], cum["fp"], cum["fn"]
        m("aegis_quality_precision", "gauge", "Cumulative precision vs simulated ground truth", [("", round(tp / (tp + fp), 4) if tp + fp else 0)])
        m("aegis_quality_recall", "gauge", "Cumulative recall vs simulated ground truth", [("", round(tp / (tp + fn), 4) if tp + fn else 0)])
        if mon.get("available"):
            m("aegis_feature_psi_max", "gauge", "Max feature PSI vs training", [("", max(mon["feature_psi"].values()))])
            m("aegis_score_psi", "gauge", "ML score PSI vs validation", [("", mon["score"]["psi"])])
        return "\n".join(L) + "\n"

    def recent_decisions(self, n: int = 100) -> list[dict]:
        return [d.model_dump() for d in list(self.recent)[-n:]][::-1]


def _v(arr, i):
    return None if arr is None else float(arr[i])
