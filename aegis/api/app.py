"""FastAPI backend: REST + WebSocket + the two web frontends.

Security: JWT auth with roles (viewer < analyst < admin), per-IP rate limiting, strict pydantic validation,
CORS allow-list, security headers, audit log. Fraud-related fields are never taken from the browser:
simulated clicks are built server-side from the user pool and ground-truth labels are stripped from input.
"""

import asyncio
import os
import random
import re
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from aegis.config import ROOT, Settings, load_settings
from aegis.detection.explain import explanation_text, local_explanation
from aegis.detection.models import Registry
from aegis.detection import patterns
from aegis.detection.reasons import explain_event
from aegis.pipeline import GROUP, Pipeline
from aegis.schemas import ClickEvent, Decision
from aegis.security.auth import (KeyVault, RateLimiter, create_token, decode_token, has_role, hash_password,
                                 mask_ip, verify_password)
from aegis.simulator.manager import KINDS, SimulationManager
from aegis.simulator.traffic import ADS, AD_CAMPAIGN, BOT_UA, UserPool, _event
from aegis.store.db import Store
from aegis.store.state import StateRateLimiter, make_state
from aegis.streaming.bus import make_bus
from aegis.training import ensure_models, train_and_register

WEB = ROOT / "web"
PROVIDERS = {"disabled", "grok", "openai", "claude", "ollama"}


# ------------------------------------------------------------------ request models
class LoginIn(BaseModel):
    email: str = Field(max_length=120)
    password: str = Field(max_length=200)


class ClickIn(BaseModel):
    user_id: str = Field(pattern=r"^[A-Za-z0-9_\-.:]{1,64}$")
    ad_id: str = Field(pattern=r"^[A-Za-z0-9_\-.:]{1,64}$")
    count: int = Field(1, ge=1, le=200)
    profile: str = Field("normal", pattern="^(normal|rapid|bot)$")


class SimIn(BaseModel):
    number_of_users: Optional[int] = Field(None, ge=1, le=500)
    click_rate: Optional[float] = Field(None, gt=0, le=2000)
    duration: Optional[float] = Field(60.0, gt=0, le=600)
    target_ad: Optional[str] = Field(None, max_length=32)
    target_campaign: Optional[str] = Field(None, max_length=32)
    intensity: Optional[float] = Field(1.0, gt=0, le=20)


class BlockIn(BaseModel):
    entity_type: str = Field(pattern="^(user|device|ip)$")
    entity_id: str = Field(min_length=1, max_length=64)
    reason: str = Field("manual block", max_length=200)


class FeedbackIn(BaseModel):
    event_id: str
    label: int = Field(ge=0, le=1)


class SimulationSaveIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    notes: str = ""
    tags: str | list[str] | None = None


class PatternIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=60)
    description: str = ""
    action: str = "label"
    signature: dict


class AlertStatusIn(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved)$")


class AISettingsIn(BaseModel):
    provider: str
    api_key: Optional[str] = Field(None, max_length=400)
    model: str = Field("", max_length=80)
    temperature: float = Field(0.2, ge=0, le=1)
    enabled: bool = True


class SystemSettingsIn(BaseModel):
    medium: Optional[float] = Field(None, gt=0, lt=1)
    high: Optional[float] = Field(None, gt=0, lt=1)
    critical: Optional[float] = Field(None, gt=0, le=1)
    block_min_hits: Optional[int] = Field(None, ge=1, le=20)
    auto_block: Optional[bool] = None


class ResetIn(BaseModel):
    scopes: list[str] = Field(default_factory=list, max_length=20)
    confirm: bool = False
    preset: str = Field("", max_length=40)

    @field_validator("scopes")
    @classmethod
    def _known(cls, v: list[str]) -> list[str]:
        from aegis.store.db import Store
        bad = [s for s in v if s not in Store.ALL_SCOPES and s not in Store.PRESETS]
        if bad:
            raise ValueError(f"unknown scope(s): {', '.join(bad)}")
        return v


class Hub:
    """WebSocket fan-out. Safe to call from any thread."""

    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    def add(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.clients.add(q)
        return q

    def remove(self, q: asyncio.Queue) -> None:
        self.clients.discard(q)

    def broadcast(self, msg: dict) -> None:
        if self.loop is None or not self.clients:
            return
        self.loop.call_soon_threadsafe(self._push, msg)

    def _push(self, msg: dict) -> None:
        for q in list(self.clients):
            if not q.full():
                q.put_nowait(msg)


def compact(d: Decision) -> dict:
    return {"id": d.event_id, "ts": d.timestamp, "user": d.user_id, "ad": d.ad_id, "campaign": d.campaign_id,
            "risk": d.risk, "level": d.level, "action": d.action, "blocked": d.blocked_now, "scores": d.scores,
            "ip": d.ip_mask, "device": d.device_id, "rules": d.rules_fired, "lat": d.latency_ms,
            "conf": d.confidence, "factors": d.top_factors[:5],
            "reason": d.reason, "reason_title": d.reason_title}


def create_app(settings: Settings | None = None, bundle: Any = "auto", pool_seed: int | None = None) -> FastAPI:
    s = settings or load_settings()
    if s.get("app.env") == "production" and s.secret_key.startswith("dev-insecure"):
        raise RuntimeError("SECRET_KEY must be set in production")

    db_note = ""
    store = None
    url = os.environ.get("DATABASE_URL") or s.get("app.database_url", "")
    if url:
        try:
            store = Store(url)
        except Exception as exc:  # noqa: BLE001 - unreachable Postgres must not stop the platform
            db_note = f"postgres unavailable ({type(exc).__name__}); using sqlite"
    if store is None:
        store = Store(s.resolve_path("app.db_path") if s.get("app.db_path") != ":memory:" else ":memory:")
        if db_note:
            store.system_event("fallback", db_note)
    bus = make_bus(s.get("bus.kafka_bootstrap", ""), s.get("bus.buffer", 100_000))
    bnd = ensure_models(s, store) if bundle == "auto" else bundle
    state = make_state(os.environ.get("REDIS_URL") or s.get("state.redis_url", ""))
    mirror = None
    if os.environ.get("NEO4J_URI") or s.get("graph.neo4j_uri", ""):
        try:
            from aegis.detection.graph_neo4j import Neo4jMirror
            mirror = Neo4jMirror(os.environ.get("NEO4J_URI") or s.get("graph.neo4j_uri"), os.environ.get("NEO4J_USER", "neo4j"),
                                 os.environ.get("NEO4J_PASSWORD", ""))
            mirror.start()
        except Exception as exc:  # noqa: BLE001 - optional integration
            store.system_event("fallback", f"neo4j unavailable: {type(exc).__name__}")
    pipe = Pipeline(s, store=store, bus=bus, bundle=bnd, state=state, graph_mirror=mirror)
    vault = KeyVault(s.master_key)
    if state.mode == "redis":   # shared across workers
        limiter, login_limiter = StateRateLimiter(state, s.get("security.rate_limit_per_min", 12000)), StateRateLimiter(state, s.get("security.login_rate_limit_per_min", 30))
    else:
        limiter, login_limiter = RateLimiter(s.get("security.rate_limit_per_min", 12000)), RateLimiter(s.get("security.login_rate_limit_per_min", 30), burst=10)
    rng = random.Random(pool_seed if pool_seed is not None else s.get("app.seed", 42))
    pool = UserPool(s.get("app.seed_users", 60), rng)
    hub = Hub()
    sim = SimulationManager(pipe.submit, pool, store, seed=s.get("app.seed", 42))
    iters = s.get("security.pbkdf2_iterations", 120_000)
    for email, role, env, default in (("admin@aegis.local", "admin", "ADMIN_PASSWORD", "admin123"),
                                      ("analyst@aegis.local", "analyst", "ANALYST_PASSWORD", "analyst123"),
                                      ("viewer@aegis.local", "viewer", "VIEWER_PASSWORD", "viewer123")):
        if not store.get_user(email):
            store.add_user(email, role, hash_password(os.environ.get(env, default), iters))

    def _load_ai() -> None:
        row = store._one("SELECT * FROM api_settings ORDER BY updated DESC LIMIT 1")
        if row:
            try:
                key = vault.decrypt(row["encrypted_key"]) if row["encrypted_key"] else None
                pipe.configure_llm(row["provider"], key, row["model"], row["temperature"], bool(row["enabled"]))
            except Exception:  # noqa: BLE001 - corrupt/rotated key: stay in fallback mode
                pipe.status["agent"] = {"state": "DEGRADED", "detail": "stored API key unreadable"}
        elif os.environ.get("LLM_API_KEY") and s.get("agent.provider") != "disabled":
            pipe.agent_enabled = bool(s.get("agent.enabled"))
            pipe._refresh_agent_status()

    _load_ai()
    pipe.listeners.append(lambda ds: hub.broadcast({"type": "decisions", "items": [compact(d) for d in ds[-200:]]}))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        hub.loop = asyncio.get_running_loop()
        pipe.warm_explainer()   # SHAP JIT warm-up off the request path (server only)

        async def pump_loop() -> None:
            while True:
                try:
                    if bus.mode != "memory" or bus.lag(pipe.topics["clicks"], GROUP) > 0:
                        await run_in_threadpool(pipe.pump)
                except Exception as exc:  # noqa: BLE001
                    store.system_event("error", f"pump: {type(exc).__name__}")
                await asyncio.sleep(0.05)

        async def retention_loop() -> None:
            cfg = s.get("app.retention", {}) or {}
            while True:
                await asyncio.sleep(max(1.0, float(cfg.get("sweep_minutes", 10)) * 60))
                try:
                    await run_in_threadpool(lambda: store.prune(cfg.get("days", 7), cfg.get("max_events", 500_000),
                                                                cfg.get("audit_days", 90), cfg.get("keep_simulations", 50)))
                except Exception as exc:  # noqa: BLE001
                    store.system_event("error", f"retention: {type(exc).__name__}")

        async def stats_loop() -> None:
            while True:
                await asyncio.sleep(1.0)
                try:
                    if pipe.online:
                        pipe.online.commit(time.time(), delay=60.0)
                    pipe.sync_blocklist()
                    snap = pipe.snapshot()
                    state.publish_stats(snap)
                    hub.broadcast({"type": "stats", "stats": snap, "health": pipe.health(),
                                   "alerts_open": len(store.list_alerts("open", 500)), "sims": sim.status()[:3]})
                except Exception:  # noqa: BLE001
                    pass

        tasks = [asyncio.create_task(pump_loop()), asyncio.create_task(stats_loop()), asyncio.create_task(retention_loop())]
        yield
        sim.stop()
        for t in tasks:
            t.cancel()
        if mirror is not None:
            mirror.stop()
        bus.close()
        store.close()

    app = FastAPI(title="AegisClick", version="1.0.0", lifespan=lifespan)
    app.state.pipeline, app.state.store, app.state.sim, app.state.settings, app.state.pool = pipe, store, sim, s, pool
    app.add_middleware(CORSMiddleware, allow_origins=s.get("security.cors_origins", []), allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def guard(request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        if request.url.path.startswith("/api/") and not limiter.allow(client):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        resp = await call_next(request)
        csp = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
               "connect-src 'self' ws: wss:; img-src 'self' data:")
        if request.url.path in ("/docs", "/redoc"):  # Swagger UI is served from a CDN; relax only for these two pages
            csp = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                   "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
                   "connect-src 'self'; worker-src blob:")
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                             "Referrer-Policy": "no-referrer", "Content-Security-Policy": csp})
        return resp

    # ------------------------------------------------------------------ auth
    async def user_dep(request: Request) -> dict:
        if not s.get("app.auth_enabled", True):
            return {"sub": "dev@local", "role": "admin"}
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else request.query_params.get("token", "")
        try:
            return decode_token(s.secret_key, token)
        except jwt.PyJWTError:
            raise HTTPException(401, "invalid or missing token") from None

    def require(role: str):
        async def dep(user: dict = Depends(user_dep)) -> dict:
            if not has_role(user.get("role", ""), role):
                raise HTTPException(403, f"requires role {role}")
            return user
        return dep

    Viewer, Analyst, Admin = (Annotated[dict, Depends(require(r))] for r in ("viewer", "analyst", "admin"))

    @app.post("/api/auth/login")
    async def login(body: LoginIn, request: Request):
        if not login_limiter.allow(request.client.host if request.client else "x"):
            raise HTTPException(429, "too many login attempts")
        u = store.get_user(body.email.lower().strip())
        if not u or not verify_password(body.password, u["password_hash"]):
            raise HTTPException(401, "invalid credentials")
        store.audit(u["email"], "login")
        return {"token": create_token(s.secret_key, u["email"], u["role"], s.get("security.jwt_ttl_minutes", 480)),
                "role": u["role"], "email": u["email"]}

    @app.get("/api/me")
    async def me(user: Viewer):
        return {"email": user["sub"], "role": user["role"]}

    # ------------------------------------------------------------------ health (public)
    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/status")
    async def status():
        return pipe.health() | {"stats": pipe.snapshot()}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics():
        return pipe.metrics_text()

    # ------------------------------------------------------------------ users / ads / clicks
    @app.get("/api/ads")
    async def ads(user: Viewer):
        return [{"ad_id": a, "campaign_id": AD_CAMPAIGN[a]} for a in ADS]

    @app.get("/api/users")
    async def users(user: Viewer, limit: int = Query(200, le=500)):
        out = []
        for u in pool.users[:limit]:
            ls = pipe.last_seen.get(u.user_id)
            out.append({"user_id": u.user_id, "device_id": u.device_id, "ip": mask_ip(u.ip), "country": u.country,
                        "user_agent": u.ua[:48], "account_age_days": round(u.account_age, 1),
                        "blocked": u.user_id in pipe.blocked_users, "risk": ls[3].risk if ls else 0.0,
                        "level": ls[3].level if ls else "LOW", "external": False})
        pool_ids = set(pool.by_id)
        ext = [(k, v) for k, v in list(pipe.last_seen.items())[-60:] if k not in pool_ids][::-1][:40]
        for uid, (e, f, vec, d) in ext:
            out.append({"user_id": uid, "device_id": e.device_id, "ip": mask_ip(e.ip_address), "country": e.country,
                        "user_agent": e.user_agent[:48], "account_age_days": e.account_age_days,
                        "blocked": uid in pipe.blocked_users, "risk": d.risk, "level": d.level, "external": True})
        return out

    @app.post("/api/clicks")
    async def click(body: ClickIn, user: Analyst):
        ident = pool.by_id.get(body.user_id)
        if ident is None or body.ad_id not in AD_CAMPAIGN:
            raise HTTPException(404, "unknown user or ad")
        gap = {"normal": 0.0, "rapid": 0.05, "bot": 1.0}[body.profile]
        n = body.count if body.profile != "normal" else 1
        now = time.time()
        r = random.Random()
        if body.profile == "bot":
            ident = type(ident)(**{**ident.__dict__, "ua": BOT_UA[0]})
        events = [_event(r, ident, now - (n - 1 - i) * gap, body.ad_id, label=0, attack=f"manual_{body.profile}")
                  for i in range(n)]
        acks = pipe.submit([e.public() for e in events])
        ls = pipe.last_seen.get(body.user_id)
        return {"accepted": sum(a["status"] == "accepted" for a in acks),
                "rejected": sum(a["status"] == "rejected" for a in acks),
                "blocked": body.user_id in pipe.blocked_users,
                "risk": ls[3].risk if ls else 0.0, "level": ls[3].level if ls else "LOW",
                "decision": compact(ls[3]) if ls else None}

    @app.post("/api/events")
    async def ingest(events: Annotated[list[ClickEvent], Field(max_length=1000)], user: Analyst):
        return {"results": pipe.submit([e.public() for e in events])}

    # ------------------------------------------------------------------ simulations
    @app.post("/api/simulation/stop")
    async def sim_stop(user: Analyst):
        n = sim.stop()
        store.audit(user["sub"], "sim_stop", "", str(n))
        return {"stopped": n}

    @app.get("/api/simulation/status")
    async def sim_status(user: Viewer):
        return sim.status()

    @app.post("/api/simulation/{kind}")
    async def sim_start(kind: str, body: SimIn, user: Analyst):
        if kind.replace("-", "_") not in KINDS:
            raise HTTPException(404, f"unknown simulation; choose one of {sorted(KINDS)}")
        store.audit(user["sub"], "sim_start", kind, body.model_dump_json())
        return sim.start(kind, body.model_dump())

    @app.get("/api/simulations")
    async def sims(user: Viewer):
        return store.list_simulations()

    @app.post("/api/simulations/{sim_id}/replay")
    async def replay(sim_id: int, user: Analyst, speed: float = Query(1.0, gt=0, le=100)):
        try:
            return sim.replay(sim_id, speed)
        except KeyError:
            raise HTTPException(404, "simulation not found") from None

    # ------------------------------------------------------------------ fraud views
    @app.get("/api/fraud/events")
    async def fraud_events(user: Viewer, limit: int = Query(100, le=500), min_risk: float = 0.0):
        return [d for d in pipe.recent_decisions(500) if d["risk"] >= min_risk][:limit]

    @app.get("/api/fraud/events/{event_id}")
    async def fraud_event(event_id: str, user: Viewer):
        r = store.get_prediction(event_id)
        if not r:
            raise HTTPException(404, "event not found")
        vec = pipe.vectors.get(event_id)
        method = "sampled-shapley (stored at detection time)" if r.get("factors") else "rules only"
        if vec is not None and pipe.bundle is not None and (not r.get("factors") or pipe.explain_method == "shap-library"):
            res = await run_in_threadpool(lambda: local_explanation(pipe.bundle, vec, backend=pipe.explain_backend))
            r["factors"], method = res["factors"], res["method"] + " on the live ensemble (computed on demand)"
        r["explanation_text"] = explanation_text(r["factors"] or [])
        r["explanation_method"] = method
        if not r.get("reason"):        # rows written before reasons existed
            why = explain_event(r)
            r["reason"], r["reason_title"] = why["reason"], why["title"]
            r["reason_detail"] = why["detail"]
        return r

    @app.get("/api/fraud/users/{user_id}")
    async def fraud_user(user_id: str, user: Viewer):
        ls = pipe.last_seen.get(user_id)
        hist = store.user_events(user_id, 100)
        if not ls and not hist:
            raise HTTPException(404, "user not found")
        out: dict[str, Any] = {"user_id": user_id, "blocked": user_id in pipe.blocked_users,
                               "events": hist, "recommendations": [r for r in store.list_recommendations(None, 200)
                                                                   if r["user_id"] == user_id][:5]}
        if ls:
            e, f, vec, d = ls
            out |= {"profile": {"device_id": e.device_id, "ip": mask_ip(e.ip_address), "country": e.country,
                                "user_agent": e.user_agent[:80], "account_age_days": e.account_age_days},
                    "features": f, "decision": compact(d), "graph": pipe.graph.export(user_id=user_id, limit=60)}
        return out

    @app.get("/api/fraud/top-users")
    async def top_users(user: Viewer, limit: int = Query(10, le=50)):
        return store.top_risk_users(limit)

    @app.get("/api/analytics/timeline")
    async def timeline(user: Viewer, window: str = Query("5m", pattern="^(1m|5m|1h|24h)$")):
        return await run_in_threadpool(store.timeline, window)

    @app.get("/api/analytics/devices")
    async def devices(user: Viewer, since_minutes: float = Query(0, ge=0)):
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return await run_in_threadpool(store.device_types, since)

    @app.get("/api/campaigns")
    async def campaigns(user: Viewer, since_minutes: float = Query(0, ge=0)):
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        rows = await run_in_threadpool(store.campaign_stats, s.get("campaigns.cpc", {}) or {}, float(s.get("campaigns.default_cpc", 9.0)), since)
        return {"currency": "INR", "note": "spend is simulated: clicks x configured cost-per-click", "campaigns": rows,
                "totals": {"clicks": sum(r["clicks"] for r in rows), "spend": round(sum(r["spend"] for r in rows), 2),
                           "wasted": round(sum(r["wasted"] for r in rows), 2)}}

    @app.get("/api/campaigns/{campaign_id}")
    async def campaign(campaign_id: str, user: Viewer, since_minutes: float = Query(0, ge=0)):
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return await run_in_threadpool(store.campaign_detail, campaign_id, since)

    @app.get("/api/stats/shared")
    async def shared_stats(user: Viewer):
        return {"state": state.stats(), "stats": state.get_stats()}

    @app.get("/api/monitor")
    async def monitor(user: Viewer):
        return await run_in_threadpool(pipe.monitor)

    @app.post("/api/monitor/baseline/reset")
    async def monitor_reset(user: Admin):
        pipe.reset_drift_baseline()
        store.audit(user["sub"], "drift_baseline_reset")
        return {"ok": True}

    @app.get("/api/rules")
    async def rules_get(user: Viewer):
        return pipe.rules_config()

    @app.put("/api/rules")
    async def rules_put(body: dict, user: Admin):
        try:
            return pipe.apply_rules(body, by=user["sub"])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/admin/prune")
    async def prune(user: Admin, days: float | None = Query(None, gt=0, le=3650)):
        cfg = s.get("app.retention", {}) or {}
        out = await run_in_threadpool(lambda: store.prune(days or cfg.get("days", 7), cfg.get("max_events", 500_000),
                                                           cfg.get("audit_days", 90), cfg.get("keep_simulations", 50)))
        store.audit(user["sub"], "prune", "", str(out))
        return out

    # ------------------------------------------------------------------ reset / clear
    def _clearable(role: str) -> set[str]:
        """Scopes this role may clear. Viewers may look at counts but never clear."""
        return {"admin": set(Store.ALL_SCOPES), "analyst": set(Store.ANALYST_SCOPES)}.get(role, set())

    def _scopes_for(body_scopes: list[str], preset: str, role: str) -> list[str]:
        """Expand a preset, reject unknown scopes and refuse scopes above the caller's role."""
        if preset:
            if preset not in Store.PRESETS:
                raise HTTPException(400, f"unknown preset '{preset}'")
            scopes = list(Store.PRESETS[preset])
        else:
            scopes = list(dict.fromkeys(body_scopes))
        if not scopes:
            raise HTTPException(400, "no scopes selected")
        allowed = _clearable(role)
        forbidden = [x for x in scopes if x not in allowed]
        if forbidden:
            raise HTTPException(403, f"admin role required for: {', '.join(forbidden)}")
        return scopes

    @app.get("/api/admin/reset/scopes")
    async def reset_scopes(user: Viewer):
        """Catalogue shown on the Data and Reset page: what each scope clears and who may run it."""
        return {"scopes": [{"id": s, "admin_only": s in Store.ADMIN_SCOPES} for s in Store.ALL_SCOPES],
                "presets": [{"id": k, "scopes": list(v), "admin_only": bool(set(v) & set(Store.ADMIN_SCOPES))}
                            for k, v in Store.PRESETS.items()],
                "preserved": ["users", "audit_log", "model_versions", "api_settings"],
                "role": user["role"], "clearable": sorted(_clearable(user["role"]))}

    @app.get("/api/admin/reset/preview")
    async def reset_preview(user: Viewer, scopes: str = Query("", max_length=400),
                            preset: str = Query("", max_length=40)):
        if preset:
            if preset not in Store.PRESETS:
                raise HTTPException(400, f"unknown preset '{preset}'")
            want = list(Store.PRESETS[preset])
        else:
            want = [x for x in scopes.split(",") if x] or list(Store.ALL_SCOPES)
        unknown = [x for x in want if x not in Store.ALL_SCOPES]
        if unknown:
            raise HTTPException(400, f"unknown scope(s): {', '.join(unknown)}")
        allowed = _clearable(user["role"])
        preview = await run_in_threadpool(pipe.reset_preview, [x for x in want if x in allowed])
        return {**preview, "requested": want, "denied": [x for x in want if x not in allowed]}

    @app.post("/api/admin/reset")
    async def reset(body: ResetIn, request: Request, user: Analyst):
        if not body.confirm:
            raise HTTPException(400, "confirm must be true to clear data")
        scopes = _scopes_for(body.scopes, body.preset, user["role"])
        out = await run_in_threadpool(pipe.reset, scopes, user["sub"], body.preset)
        hub.broadcast({"type": "reset", "scopes": scopes, "preset": body.preset, "ts": out["ts"]})
        if "rules_override" in out["deleted"]:
            hub.broadcast({"type": "rules", "rules": pipe.rules_config(), "ts": time.time()})
        out["role"] = user["role"]
        return out

    @app.get("/api/graph-db/{user_id}")
    async def graph_db(user_id: str, user: Viewer):
        if pipe.mirror is None:
            raise HTTPException(503, "neo4j mirror not configured (set NEO4J_URI)")
        try:
            return {"component": await run_in_threadpool(pipe.mirror.component, user_id),
                    "neighbourhood": await run_in_threadpool(pipe.mirror.neighbourhood, user_id), "mirror": pipe.mirror.stats()}
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(502, f"neo4j query failed: {type(exc).__name__}") from None

    @app.get("/api/graph/{user_id}")
    async def graph(user_id: str, user: Viewer):
        return pipe.graph.export(user_id=user_id, limit=150)

    @app.get("/api/analytics")
    async def analytics(user: Viewer, since_minutes: float = Query(0, ge=0), campaign: str | None = None,
                        country: str | None = None, min_level: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")):
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return await run_in_threadpool(store.analytics, since, campaign, country, min_level)

    # ------------------------------------------------------------------ incidents
    def clean_simulation_name(v) -> str:
        """A saved-attack name is shown in lists and exports, so keep it plain and short."""
        s = re.sub(r"[^A-Za-z0-9 _\-]", "", str(v or "")).strip()[:60]
        if not s:
            raise HTTPException(400, "name must contain letters or digits")
        return s

    def clean_notes(v) -> str:
        return re.sub(r"[\x00-\x1f]", " ", str(v or "")).strip()[:400]

    def clean_tags(v) -> str:
        if v is None:
            return ""
        if isinstance(v, list):
            v = ",".join(str(x) for x in v)
        parts = [re.sub(r"[^A-Za-z0-9_\-]", "", p)[:20] for p in str(v).split(",")]
        return ",".join([p for p in parts if p][:10])

    def clean_import_event(e: dict) -> dict:
        """Import is untrusted input: rebuild the event from scratch, keeping only known fields."""
        if not isinstance(e, dict):
            raise HTTPException(400, "each imported event must be an object")
        out = {}
        for k, cast in (("user_id", str), ("ad_id", str), ("campaign_id", str), ("device_id", str),
                        ("ip_address", str), ("user_agent", str), ("ts", float), ("label", str)):
            v = e.get(k)
            if v is None or v == "":
                continue
            try:
                out[k] = cast(v)
            except (TypeError, ValueError):
                raise HTTPException(400, f"event field '{k}' is invalid") from None
        if not out.get("user_id") or not out.get("ad_id"):
            raise HTTPException(400, "each imported event needs at least user_id and ad_id")
        for k in ("user_id", "ad_id", "campaign_id", "device_id", "ip_address", "user_agent"):
            if k in out:
                out[k] = out[k][:120]
        # provenance is server-owned: an import never gets to claim a source or a run id
        out["source"] = "import"
        out["label"] = out.get("label") or "fraud"
        return out

    @app.get("/api/incidents")
    async def incidents(user: Viewer, status: str | None = Query(None, pattern="^(open|closed)$"),
                        limit: int = Query(50, le=200)):
        rows = store.list_incidents(limit, status)
        for r in rows:
            r["classification"] = r.get("classification") or "Unclassified activity"
            r["entities_preview"] = [f"{e['entity_type']}:{e['entity_id']}"
                                     for e in store.incident_entities(int(r["id"]))[:6]]
        return rows

    @app.get("/api/incidents/{incident_id}")
    async def incident_detail(incident_id: int, user: Viewer):
        inc = store.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        events = []
        for eid in inc.get("event_ids") or []:
            r = store.get_prediction(eid)
            if r:
                events.append(r)
        entities = inc.get("entities") or []
        users = [e["entity_id"] for e in entities if e["entity_type"] == "user"]
        # combined view of the incident: who, what, when, and the strongest reasons
        reasons: dict[str, int] = {}
        rules: dict[str, int] = {}
        for ev in events:
            key = (ev.get("reason_title") or "Unclassified").strip()
            reasons[key] = reasons.get(key, 0) + 1
            for r in (ev.get("rules") or []):
                rules[r] = rules.get(r, 0) + 1
        inc["combined"] = {
            "events": len(events),
            "users": users,
            "devices": [e["entity_id"] for e in entities if e["entity_type"] == "device"],
            "ips": [e["entity_id"] for e in entities if e["entity_type"] == "ip"],
            "campaigns": inc.get("campaigns") or [],
            "first_seen": inc.get("first_seen"),
            "last_seen": inc.get("last_seen"),
            "peak_risk": inc.get("peak_risk") or 0.0,
            "levels": {lv: sum(1 for ev in events if ev.get("level") == lv)
                       for lv in ("HIGH", "CRITICAL") if any(ev.get("level") == lv for ev in events)},
            "reasons": sorted(({"title": k, "n": v} for k, v in reasons.items()), key=lambda x: -x["n"])[:5],
            "rules": sorted(({"rule": k, "n": v} for k, v in rules.items()), key=lambda x: -x["n"])[:8],
            "wasted_spend": inc.get("wasted_spend") or 0.0,
        }
        inc["events"] = events
        inc["classification"] = inc.get("classification") or "Unclassified activity"
        return inc

    @app.post("/api/incidents/{incident_id}/block-all")
    async def incident_block_all(incident_id: int, user: Analyst, confirm: bool = False):
        """Block every entity attached to an incident. Requires an explicit confirmation flag."""
        if not confirm:
            raise HTTPException(400, "blocking every entity in an incident requires confirm=true")
        inc = store.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        done = []
        for e in inc.get("entities") or []:
            if pipe.is_blocked_entity(e["entity_type"], e["entity_id"]):
                continue
            why = f"incident #{incident_id}: {inc.get('classification') or 'suspicious activity'}"
            detail = {"incident_id": incident_id, "title": inc.get("classification"),
                      "reason": inc.get("summary") or why, "entity_type": e["entity_type"],
                      "entity_id": e["entity_id"], "peak_risk": e.get("peak_risk")}
            pipe.block_entity(e["entity_type"], e["entity_id"], why, float(e.get("peak_risk") or 1.0),
                              by=user["sub"], reason_detail=detail)
            done.append(f"{e['entity_type']}:{e['entity_id']}")
        store.audit(user["sub"], "incident_block_all", str(incident_id), f"{len(done)} entities")
        pipe.bus.publish(pipe.topics["blocks"], {"type": "INCIDENT_BLOCKED", "incident_id": incident_id,
                                                 "entities": done, "by": user["sub"], "ts": time.time()},
                         key=str(incident_id))
        return {"ok": True, "blocked": done, "count": len(done)}

    # ------------------------------------------------------------------ Step 6: combined + targeted analysis
    @app.get("/api/analysis/combined")
    async def analysis_combined(user: Viewer, since_minutes: float = Query(60, ge=0, le=43200),
                                min_risk: float = Query(0.0, ge=0.0, le=1.0), limit: int = Query(40, le=200)):
        """Everything happening right now, merged: worst clusters per source, totals, trend."""
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return store.combined_attacks(since=since, min_risk=min_risk, limit=limit)

    @app.get("/api/analysis/target")
    async def analysis_target(user: Viewer, since_minutes: float = Query(1440, ge=0, le=43200),
                              limit: int = Query(40, le=200)):
        """Targeted Analysis: who is being targeted, which campaigns, and what it costs."""
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return store.targeted_analysis(since=since, limit=limit)

    @app.get("/api/analysis/search")
    async def analysis_search(user: Viewer, q: str = Query(..., min_length=1, max_length=80),
                              limit: int = Query(20, le=50)):
        """One search box over users, campaigns, adverts, devices, incidents and alerts."""
        return {"q": q, **store.search_everything(q.strip(), limit)}

    # ------------------------------------------------------------------ Step 7: event log + saved attacks
    @app.get("/api/logs/events")
    async def log_events(user: Viewer, level: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
                         user_id: str | None = None, campaign_id: str | None = None, source: str | None = None,
                         run_id: str | None = None, q: str | None = None, since_minutes: float = Query(0, ge=0),
                         limit: int = Query(100, le=1000)):
        since = time.time() - since_minutes * 60 if since_minutes else 0.0
        return store.log_events(level=level, user_id=user_id, campaign_id=campaign_id, source=source,
                                run_id=run_id, q=q, since=since, limit=limit)

    @app.get("/api/simulations/saved")
    async def simulations_saved(user: Viewer, limit: int = Query(100, le=500)):
        """Saved Attacks: named, re-runnable scenarios, newest first."""
        return store.named_simulations(saved_only=True, limit=limit)

    @app.post("/api/simulations/{sim_id}/save")
    async def simulation_save(sim_id: int, body: SimulationSaveIn, user: Analyst):
        """Give a stored simulation a name so it can be replayed later."""
        name = clean_simulation_name(body.name)
        if not store.get_simulation_events(sim_id) and not store.list_simulations(200):
            raise HTTPException(404, "simulation not found")
        row = store._one("SELECT duration, actors_n FROM attack_simulations WHERE id=?", (sim_id,))
        if not row:
            raise HTTPException(404, "simulation not found")
        store.save_simulation(sim_id, name, clean_notes(body.notes), clean_tags(body.tags), user["sub"],
                              float(row.get("duration") or 0.0), int(row.get("actors_n") or 0))
        store.audit(user["sub"], "simulation_save", str(sim_id), name)
        return {"ok": True, "id": sim_id, "name": name}

    @app.delete("/api/simulations/{sim_id}")
    async def simulation_delete(sim_id: int, user: Analyst, confirm: bool = False):
        if not confirm:
            raise HTTPException(400, "deleting a saved attack requires confirm=true")
        if not store.delete_simulation(sim_id):
            raise HTTPException(404, "simulation not found")
        store.audit(user["sub"], "simulation_delete", str(sim_id), "")
        return {"ok": True}

    @app.post("/api/simulations/{sim_id}/duplicate")
    async def simulation_duplicate(sim_id: int, user: Analyst, speed: float = Query(1.0, ge=0.1, le=50)):
        """Run an existing scenario again without touching the stored copy."""
        events = store.get_simulation_events(sim_id)
        if not events:
            raise HTTPException(404, "simulation not found or empty")
        row = store._one("SELECT kind FROM attack_simulations WHERE id=?", (sim_id,)) or {}
        out = sim.replay(sim_id, speed)
        store.audit(user["sub"], "simulation_duplicate", str(sim_id), f"{row.get('kind')} @ {speed}x")
        return {"ok": True, "replayed": out, "kind": row.get("kind"), "events": len(events)}

    @app.get("/api/simulations/compare")
    async def simulations_compare(user: Viewer, a: int, b: int):
        """Compare two stored scenarios: level counts side by side."""
        if a == b:
            raise HTTPException(400, "pick two different simulations")
        out = store.compare_simulations(a, b)
        if not out["a"].get("id") or not out["b"].get("id"):
            raise HTTPException(404, "one of the simulations was not found")
        return out

    @app.get("/api/simulations/{sim_id}/export")
    async def simulation_export(sim_id: int, user: Viewer):
        """JSON export of a stored scenario, so it can be shared or replayed offline."""
        row = store._one("SELECT kind, params, name, notes, tags, duration, actors_n, events "
                         "FROM attack_simulations WHERE id=?", (sim_id,))
        if not row:
            raise HTTPException(404, "simulation not found")
        events = store.get_simulation_events(sim_id) or []
        payload = {"schema": "aegis.saved_attack.v1", "id": sim_id, "kind": row.get("kind"),
                   "name": row.get("name"), "notes": row.get("notes"), "tags": row.get("tags"),
                   "duration": row.get("duration"), "actors_n": row.get("actors_n"),
                   "events": events}
        store.audit(user["sub"], "simulation_export", str(sim_id), f"{len(events)} events")
        return payload

    @app.post("/api/simulations/import")
    async def simulation_import(body: dict, user: Analyst):
        """Import a previously exported scenario as a new saved attack."""
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        kind = str(body.get("kind") or "")[:40]
        events = body.get("events")
        if not kind or not isinstance(events, list) or not events:
            raise HTTPException(400, "import needs a kind and a non-empty events list")
        if len(events) > 100_000:
            raise HTTPException(400, "import is limited to 100000 events")
        clean = [clean_import_event(e) for e in events[:100_000]]
        sim_id = store.add_simulation(kind, {}, clean)
        name = clean_simulation_name(body.get("name") or f"imported-{sim_id}")
        store.save_simulation(sim_id, name, clean_notes(body.get("notes")), clean_tags(body.get("tags")),
                              user["sub"], float(body.get("duration") or 0.0), len(clean))
        store.audit(user["sub"], "simulation_import", str(sim_id), f"{len(clean)} events")
        return {"ok": True, "id": sim_id, "name": name, "events": len(clean)}

    # ------------------------------------------------------------------ Step 8: pattern library
    @app.get("/api/patterns")
    async def patterns_list(user: Viewer, include_hits: bool = True):
        """Pattern Library. Built-in signatures are read-only; saved patterns are analyst-editable."""
        counts = store.pattern_hit_counts() if include_hits else {}
        out = []
        for p in store.list_patterns():
            p["hits"] = counts.get(p["id"], 0)
            out.append(p)
        return {"patterns": out, "builtins": patterns.builtins(), "max": patterns.MAX_PATTERNS}

    @app.post("/api/patterns/preview")
    async def patterns_preview(body: dict, user: Analyst):
        """Dry-run a signature against stored events. Nothing is saved, nothing is blocked."""
        try:
            sig = patterns.validate_signature(body.get("signature") or {})
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        samples = store.log_events(level="CRITICAL", limit=500) + store.log_events(level="HIGH", limit=500)
        return patterns.preview(sig, [{"event_id": s.get("event_id"), "user_id": s.get("user_id"),
                                       "features": s.get("features")} for s in samples])

    @app.post("/api/patterns")
    async def patterns_create(body: PatternIn, user: Analyst):
        """Save a pattern. Patterns only label activity; they never block on their own."""
        if len(store.list_patterns()) >= patterns.MAX_PATTERNS:
            raise HTTPException(409, f"the library is limited to {patterns.MAX_PATTERNS} patterns")
        try:
            clean = patterns.validate_pattern(body.name, body.description, body.signature, body.action)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        pid = store.add_pattern(clean["name"], clean["description"], clean["action"],
                                clean["signature"], user["sub"])
        store.audit(user["sub"], "pattern_create", str(pid), clean["name"])
        return {"ok": True, "id": pid, "pattern": store.get_pattern(pid)}

    @app.put("/api/patterns/{pattern_id}")
    async def patterns_update(pattern_id: int, body: PatternIn, user: Analyst):
        if not store.get_pattern(pattern_id):
            raise HTTPException(404, "pattern not found")
        try:
            clean = patterns.validate_pattern(body.name, body.description, body.signature, body.action)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        store.update_pattern(pattern_id, clean["name"], clean["description"], clean["action"],
                             clean["signature"], user["sub"])
        store.audit(user["sub"], "pattern_update", str(pattern_id), clean["name"])
        return {"ok": True, "pattern": store.get_pattern(pattern_id)}

    @app.delete("/api/patterns/{pattern_id}")
    async def patterns_delete(pattern_id: int, user: Analyst, confirm: bool = False):
        if not confirm:
            raise HTTPException(400, "deleting a pattern requires confirm=true")
        if not store.delete_pattern(pattern_id):
            raise HTTPException(404, "pattern not found")
        store.audit(user["sub"], "pattern_delete", str(pattern_id), "")
        return {"ok": True}

    @app.get("/api/patterns/{pattern_id}/hits")
    async def patterns_hits(pattern_id: int, user: Viewer, limit: int = Query(50, le=200)):
        if not store.get_pattern(pattern_id):
            raise HTTPException(404, "pattern not found")
        return store.pattern_hits(pattern_id, limit)

    # ------------------------------------------------------------------ alerts / blocklist / feedback
    @app.get("/api/alerts")
    async def alerts(user: Viewer, status: str | None = None, limit: int = Query(100, le=500)):
        return store.list_alerts(status, limit)

    @app.post("/api/alerts/{alert_id}/status")
    async def alert_status(alert_id: int, body: AlertStatusIn, user: Analyst):
        if not store.set_alert_status(alert_id, body.status):
            raise HTTPException(404, "alert not found")
        store.audit(user["sub"], "alert_status", str(alert_id), body.status)
        return {"ok": True}

    @app.get("/api/blocked")
    async def blocked(user: Viewer, active_only: bool = True):
        return store.list_blocked(active_only)

    @app.post("/api/blocked")
    async def block(body: BlockIn, user: Analyst):
        pipe.block_entity(body.entity_type, body.entity_id, body.reason, 1.0, by=user["sub"])
        return {"ok": True}

    @app.delete("/api/blocked/{etype}/{eid}")
    async def unblock(etype: str, eid: str, user: Analyst, confirm: bool = False):
        if not confirm:
            raise HTTPException(400, "manual unblock requires confirm=true")
        if not pipe.unblock_entity(etype, eid, by=user["sub"]):
            raise HTTPException(404, "not in blocklist")
        return {"ok": True}

    @app.post("/api/feedback")
    async def feedback(body: FeedbackIn, user: Analyst):
        if not pipe.feedback(body.event_id, body.label, user["sub"]):
            raise HTTPException(404, "event vector not available or online learner disabled")
        return {"ok": True, "online_learned": pipe.online.n_learned if pipe.online else 0}

    # ------------------------------------------------------------------ agent
    @app.post("/api/investigate/{user_id}")
    async def investigate(user_id: str, user: Analyst):
        if user_id not in pipe.last_seen:
            raise HTTPException(404, "no recent activity for user")
        rep = await run_in_threadpool(pipe.investigate, user_id)
        store.audit(user["sub"], "investigate", user_id, rep["mode"])
        return rep

    @app.get("/api/recommendations")
    async def recs(user: Viewer, status: str | None = None):
        return store.list_recommendations(status)

    @app.post("/api/recommendations/{rec_id}/{decision}")
    async def rec_decide(rec_id: int, decision: str, user: Analyst):
        r = store.get_recommendation(rec_id)
        if not r or decision not in ("approve", "reject"):
            raise HTTPException(404, "recommendation not found")
        if decision == "approve" and r["action"] == "block":  # human-in-the-loop: only a person executes it
            pipe.block_entity("user", r["user_id"], f"approved recommendation #{rec_id}: {r['attack_type']}",
                              r["confidence"], by=user["sub"])
        store.set_recommendation_status(rec_id, "approved" if decision == "approve" else "rejected")
        store.audit(user["sub"], f"recommendation_{decision}", str(rec_id))
        return {"ok": True}

    # ------------------------------------------------------------------ models
    @app.get("/api/models")
    async def models(user: Viewer):
        reg = Registry(s.resolve_path("app.models_dir")).describe()
        b = pipe.bundle
        return {"registry": reg, "production": reg.get("production"), "loaded": b.version if b else None,
                "importance": b.importance if b else {}, "shap_importance": b.shap_importance if b else {}, "explain_method": pipe.explain_method, "online": {"learned": pipe.online.n_learned if pipe.online else 0,
                                                                    "drift_events": pipe.drift_events},
                "layers": {k: v["state"] for k, v in pipe.status.items()}}

    @app.post("/api/models/retrain")
    async def retrain(user: Admin, quick: bool = True):
        b = await run_in_threadpool(lambda: train_and_register(s, quick=quick, store=store, log=lambda *_: None))
        pipe.set_bundle(b)
        store.audit(user["sub"], "retrain", b.version)
        return {"version": b.version, "metrics": b.metrics}

    @app.post("/api/models/rollback")
    async def rollback(user: Admin):
        reg = Registry(s.resolve_path("app.models_dir"))
        v = reg.rollback()
        if not v:
            raise HTTPException(400, "no previous version")
        pipe.set_bundle(reg.load(v))
        store.audit(user["sub"], "rollback", v)
        return {"production": v}

    # ------------------------------------------------------------------ settings
    @app.get("/api/settings/ai")
    async def ai_get(user: Admin):
        return {"provider": pipe.llm.provider, "model": pipe.llm.model, "temperature": pipe.llm.temperature,
                "enabled": pipe.agent_enabled, "has_key": bool(pipe.llm.api_key), "status": pipe.status["agent"]}

    @app.put("/api/settings/ai")
    async def ai_put(body: AISettingsIn, user: Admin):
        if body.provider not in PROVIDERS:
            raise HTTPException(422, f"provider must be one of {sorted(PROVIDERS)}")
        row = store.get_user(user["sub"])
        uid = row["id"] if row else 0
        enc = vault.encrypt(body.api_key) if body.api_key else None
        store.set_ai_settings(uid, body.provider, enc, body.model, body.temperature, body.enabled)
        pipe.configure_llm(body.provider, body.api_key, body.model, body.temperature, body.enabled)
        store.audit(user["sub"], "ai_settings", body.provider)
        return {"ok": True, "has_key": bool(pipe.llm.api_key), "status": pipe.status["agent"]}  # key never echoed

    @app.post("/api/settings/ai/test")
    async def ai_test(user: Admin):
        ok, msg = await run_in_threadpool(pipe.llm.test)
        return {"ok": ok, "message": msg}

    @app.get("/api/settings/system")
    async def sys_get(user: Viewer):
        return {**s.get("risk.levels"), "block_min_hits": s.get("risk.block_min_hits"),
                "auto_block": s.get("risk.auto_block"), "rules": s.get("rules")}

    @app.put("/api/settings/system")
    async def sys_put(body: SystemSettingsIn, user: Admin):
        lv = dict(s.get("risk.levels"))
        lv.update({k: v for k, v in body.model_dump().items() if k in lv and v is not None})
        if not (0 < lv["medium"] < lv["high"] < lv["critical"] <= 1):
            raise HTTPException(422, "thresholds must satisfy 0 < medium < high < critical <= 1")
        s.set("risk.levels", lv)
        pipe.risk.levels = lv
        if body.block_min_hits is not None:
            s.set("risk.block_min_hits", body.block_min_hits)
        if body.auto_block is not None:
            s.set("risk.auto_block", body.auto_block)
        store.audit(user["sub"], "system_settings", "", body.model_dump_json())
        return {"ok": True, **lv}

    @app.get("/api/audit")
    async def audit(user: Admin):
        return store.audit_log(200)

    @app.get("/api/pipeline")
    async def pipeline_view(user: Viewer):
        snap = pipe.snapshot()
        return {"health": pipe.health(), "stats": snap, "topics": bus.stats(), "system_events": store.system_events(20)}

    # ------------------------------------------------------------------ websocket
    @app.websocket("/ws")
    async def ws(websocket: WebSocket, token: str = ""):
        if s.get("app.auth_enabled", True):
            try:
                decode_token(s.secret_key, token)
            except jwt.PyJWTError:
                await websocket.close(code=4401)
                return
        await websocket.accept()
        q = hub.add()
        try:
            await websocket.send_json({"type": "hello", "stats": pipe.snapshot(), "health": pipe.health(),
                                       "recent": [compact(d) for d in list(pipe.recent)[-100:]]})
            while True:
                await websocket.send_json(await q.get())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.remove(q)

    # ------------------------------------------------------------------ frontends
    @app.get("/", include_in_schema=False)
    async def control():
        return FileResponse(WEB / "control.html")

    @app.get("/sim", include_in_schema=False)
    async def simulator():
        return FileResponse(WEB / "sim.html")

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app


def app_factory() -> FastAPI:  # `uvicorn aegis.api.app:app_factory --factory`
    return create_app()
