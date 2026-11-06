# AegisClick Architecture

## Overview

AegisClick is a real-time ad-click fraud detection and investigation platform. It ingests click events, scores them through a multi-layer fusion engine (rules, ML, anomaly, graph, online learning), correlates suspicious activity into incidents and alerts, and provides an analyst console for triage, investigation, and blocking.

## Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy (SQLite/PostgreSQL), PyJWT, cryptography (Fernet)
- **ML**: scikit-learn (MLP, HGB, IsolationForest, LogisticRegression), optional XGBoost/LightGBM
- **Frontend**: Vanilla JS SPA (`web/control.html`), hash-based routing, WebSocket live stream
- **Storage**: SQLite (dev) / PostgreSQL (prod), in-memory state (MemoryState/RedisState)
- **Messaging**: In-memory bus (dev) / Kafka/Redis (prod)

## Request Flow

```
Click Event → Ingest API → Feature Engine → Rule Engine → ML Models → Anomaly → Graph → Fusion/Risk → Action → Store + Bus → WebSocket → Console
```

## Key Modules

| Module | Responsibility |
|--------|---------------|
| `aegis/api/app.py` | FastAPI app, all REST + WebSocket endpoints, auth middleware, RBAC |
| `aegis/pipeline.py` | Orchestration: click → feature → score → action → store → publish |
| `aegis/detection/models.py` | ModelBundle: training, prediction, PSI drift, registry |
| `aegis/detection/rules.py` | Rule engine: configurable conditions, weights |
| `aegis/detection/risk.py` | Fusion (weighted blend) + action decision (ALLOW/MONITOR/FLAG/BLOCK/REJECT) |
| `aegis/detection/graph.py` | NetworkX graph: shared device/IP/subnet edges, component scoring |
| `aegis/detection/online.py` | River SGD online learner |
| `aegis/detection/anomaly.py` | IsolationForest anomaly detection |
| `aegis/detection/patterns.py` | Analyst-authored pattern signatures |
| `aegis/detection/reasons.py` | Plain-English explanation generation |
| `aegis/simulator/manager.py` | Simulation manager: profiles, replay, saved attacks |
| `aegis/store/db.py` | SQLite/PostgreSQL persistence, migrations |
| `aegis/store/state.py` | In-memory/Redis hot state, rate limiting, active users |
| `aegis/security/auth.py` | JWT, PBKDF2 passwords, RBAC, KeyVault (Fernet), RateLimiter |
| `aegis/config.py` | YAML config + env overrides, secrets from env only |

## Security

- JWT bearer tokens (HS256), 8-hour TTL
- PBKDF2 password hashing (120k iterations default)
- RBAC: viewer (read) < analyst (operate) < admin (settings/destructive)
- Rate limiting: per-IP token bucket (memory) or Redis-backed (shared)
- KeyVault: Fernet AES-128-CBC + HMAC for LLM API keys
- CSP, X-Frame-Options, X-Content-Type-Options headers
- SQL parameterization throughout
- Public click payloads cannot set labels, attack_type, source, or run_id

## Data Flow

1. **Ingest**: `/api/clicks` (single) or `/api/events` (batch) — strips server-owned provenance
2. **Score**: Rules → ML (NN+GBT ensemble) → Anomaly (IsolationForest) → Graph → Online (River)
3. **Fusion**: Weighted blend with auto-renormalization on component failure
4. **Action**: ALLOW/MONITOR/FLAG/BLOCK/REJECT with audit trail
5. **Correlate**: Incidents (auto-correlation by user/device/IP/subnet/campaign+attack)
6. **Alert**: HIGH/CRITICAL decisions → Alert Center
7. **Block**: Auto (CRITICAL) + Manual, entity-type aware
8. **Stream**: WebSocket broadcasts decisions, stats, health to console

## Database

SQLite (dev) / PostgreSQL (prod). Additive migrations. Tables: users, click_events, fraud_predictions, fraud_alerts, blocked_entities, incidents, incident_entities, patterns, pattern_hits, attack_simulations, recommendations, model_versions, audit_log, system_events, settings_kv, api_settings.

## Frontend

Single-page app (`web/control.html`) with hash-based routing. 19 views. WebSocket live stream. No frontend framework — vanilla JS for zero build step.

## Deployment

- Dev: `python scripts/run_dualstack.py` (dual-stack socket, SQLite)
- Prod: Set `APP_ENV=production`, `SECRET_KEY`, `MASTER_KEY`, `DATABASE_URL`, `ADMIN_PASSWORD`, etc. Fails startup if secrets are weak or missing.
- Docker: `docker compose up --build -d` (PostgreSQL, Redis, Kafka, app, Prometheus, Grafana)