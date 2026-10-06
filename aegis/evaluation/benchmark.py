"""Load / latency benchmark -> reports/benchmark.json. Measures the real pipeline (no mocks).

 * batch throughput (events/s) for several batch sizes
 * single-event decision latency distribution (p50/p95/p99)
 * HTTP ingestion: POST /api/events through the full ASGI stack (auth, validation, bus, pipeline, DB)
"""
from __future__ import annotations

import json
import time
import warnings

import numpy as np

from aegis.config import ROOT, load_settings
from aegis.pipeline import Pipeline
from aegis.simulator.traffic import build_episode
from aegis.store.db import Store
from aegis.training import ensure_models


def _fresh(settings, bundle) -> Pipeline:
    s = settings.copy()
    return Pipeline(s, store=Store(":memory:"), bundle=bundle)


def run(n_users: int = 1500, http_events: int = 4000) -> dict:
    s = load_settings()
    bundle = ensure_models(s)
    events = build_episode(901, n_users=n_users)
    out: dict = {"events": len(events), "model_version": bundle.version if bundle else "none"}

    thr = {}
    for bs in (1, 50, 200, 1000):
        pipe = _fresh(s, bundle)
        sub = events[: (3000 if bs == 1 else len(events))]
        t0 = time.perf_counter()
        for i in range(0, len(sub), bs):
            pipe.process_events(sub[i:i + bs])
        thr[str(bs)] = len(sub) / (time.perf_counter() - t0)
    out["throughput_events_per_s_by_batch"] = thr

    pipe = _fresh(s, bundle)
    lat = []
    for e in events[:3000]:
        t0 = time.perf_counter()
        pipe.process_events([e])
        lat.append((time.perf_counter() - t0) * 1000)
    out["single_event_latency_ms"] = {f"p{q}": float(np.percentile(lat, q)) for q in (50, 95, 99)} | {"mean": float(np.mean(lat))}

    from fastapi.testclient import TestClient
    from aegis.api.app import create_app
    s2 = s.copy()
    s2.set("app.db_path", ":memory:")
    s2.set("security.rate_limit_per_min", 10_000_000)
    s2.set("ml.explain_backend", "shapley")   # keep SHAP-library JIT warm-up out of the throughput measurement (see README)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with TestClient(create_app(s2, bundle=bundle)) as c:
            tok = c.post("/api/auth/login", json={"email": "analyst@aegis.local", "password": "analyst123"}).json()["token"]
            h = {"Authorization": "Bearer " + tok}
            payload = [e.public().model_dump() for e in build_episode(902, n_users=800)[:http_events]]
            t0 = time.perf_counter()
            lats = []
            for i in range(0, len(payload), 100):
                t1 = time.perf_counter()
                r = c.post("/api/events", json=payload[i:i + 100], headers=h)
                assert r.status_code == 200, r.text
                lats.append((time.perf_counter() - t1) * 1000)
            dt = time.perf_counter() - t0
            snap = c.get("/status").json()["stats"]
    out["http_ingest"] = {"events": len(payload), "events_per_s": len(payload) / dt, "batch100_latency_ms_p50": float(np.percentile(lats, 50)),
                          "batch100_latency_ms_p95": float(np.percentile(lats, 95)), "pipeline_detection_latency_ms": snap["latency_ms"]}
    path = ROOT / "reports" / "benchmark.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    r = run()
    t = r["throughput_events_per_s_by_batch"]
    print("[benchmark] events/s by batch: " + ", ".join(f"{k}:{v:,.0f}" for k, v in t.items()))
    l = r["single_event_latency_ms"]
    print(f"[benchmark] single-event latency ms p50={l['p50']:.2f} p95={l['p95']:.2f} p99={l['p99']:.2f}")
    h = r["http_ingest"]
    print(f"[benchmark] HTTP ingest {h['events_per_s']:,.0f} ev/s | detection latency {h['pipeline_detection_latency_ms']}")
