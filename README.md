# AegisClick — Real-Time Ad Fraud Intelligence Platform

> **One command to rule them all:** `docker compose up --build -d`

## What is AegisClick?

AegisClick is a **real-time ad fraud detection and investigation platform** that ingests click events, scores them through a multi-layer fusion engine (rules, ML, anomaly, graph, online learning), correlates suspicious activity into incidents, and gives analysts a complete console to triage, investigate, and block fraud at scale.

Built for **sub-10ms latency** at 10k+ events/sec on modest hardware.

---

## Quick Start

```bash
# 1. Clone & enter
git clone <repo> && cd aegisclick

# 2. One command starts everything (PostgreSQL, Redis, Kafka, app, Prometheus, Grafana)
docker compose up --build -d

# 3. Open the console
open http://localhost:8000
# Login: admin@aegis.local / admin123  (or analyst@aegis.local / analyst123)
```

**That's it.** The stack self-initializes: migrations run, seed users created, models trained on synthetic data, simulator seeded.

---

## Architecture Overview

```
┌─────────────┐    Click Events (HTTP/Kafka)    ┌──────────────────┐
│  Simulator  │ ──────────────────────────────▶ │   Ingest API     │
│  (load gen) │                                  │  (FastAPI)       │
└─────────────┘                                  └────────┬─────────┘
                                                          │
                    ┌─────────────────────────────────────┼─────────────────────┐
                    ▼                                     ▼                     ▼
            ┌───────────────┐                   ┌─────────────────┐   ┌────────────────┐
            │  Rule Engine  │                   │   ML Models     │   │  Graph Engine  │
            │ (configurable │                   │ (NN + GBT +     │   │ (shared device,│
            │  conditions)  │                   │  Online learner)│   │  IP, subnet)   │
            └───────┬───────┘                   └────────┬────────┘   └───────┬────────┘
                    │                                    │                     │
                    └────────────────────────────────────┼─────────────────────┘
                                                         ▼
                                                ┌──────────────────┐
                                                │  Fusion / Risk   │
                                                │  (weighted blend)│
                                                └────────┬─────────┘
                                                         ▼
                                                ┌──────────────────┐
                                                │  Action Engine   │
                                                │ (ALLOW/MONITOR/  │
                                                │  FLAG/BLOCK/     │
                                                │  REJECT)         │
                                                └────────┬─────────┘
                                                         ▼
                    ┌────────────────────────────────────┼─────────────────────┐
                    ▼                                    ▼                     ▼
            ┌───────────────┐                  ┌─────────────────┐    ┌────────────────┐
            │  Incidents    │                  │   Alerts        │    │  Blocklist     │
            │ (correlation) │                  │  (HIGH/CRITICAL)│    │  (auto+manual) │
            └───────────────┘                  └─────────────────┘    └────────────────┘
                    │                                    │                     │
                    └────────────────────────────────────┼─────────────────────┘
                                                         ▼
                                                ┌──────────────────┐
                                                │   Console UI     │
                                                │ (Investigations, │
                                                │  Analytics,     │
                                                │  Patterns, etc.) │
                                                └──────────────────┘
```

**Key Technologies**: FastAPI, SQLAlchemy (SQLite/PostgreSQL), LightGBM + PyTorch, NetworkX, Redis Streams, Kafka, Prometheus/Grafana, vanilla JS frontend.

---

## Features

| Area | Capability |
|------|------------|
| **Ingest** | `/api/clicks` (single), `/api/events` (batch) — strips server-owned provenance |
| **Scoring** | Rules, ML (NN+GBT), Anomaly (IsolationForest), Graph (shared device/IP/subnet), Online (River) |
| **Fusion** | Weighted blend, auto-renormalization on component failure |
| **Actions** | ALLOW, MONITOR, FLAG, BLOCK, REJECT — with audit trail |
| **Incidents** | Auto-correlation by user/device/IP/subnet/campaign+attack; auto-close after idle window |
| **Alerts** | HIGH/CRITICAL decisions → Alert Center with acknowledgment workflow |
| **Blocklist** | Auto (CRITICAL) + Manual; entity-type aware (user/device/IP/subnet/campaign) |
| **Investigations** | Per-user timeline, graph (shared edges), recommendations, block actions |
| **Analytics** | Combined (clusters by campaign/ad/device), Targeted (victims + wasted spend), Campaign drill-down |
| **Event Logs** | Full decision feed with filters (level, user, campaign, source, run_id, text search) |
| **Patterns** | Analyst-authored signatures (2+ conditions, max 200), preview against history, hit tracking |
| **Saved Attacks** | Named scenarios, replay at 1x–50x, duplicate, compare, export/import JSON |
| **Simulator** | Profiles (burst, bot, click_farm, mimicry...), targeting, duration, intensity |
| **Models** | Train/retrain/rollback, PSI drift monitoring, feature importance |
| **Settings** | Thresholds, retention, login limits, AI provider (OpenAI/Grok/Claude/Ollama), keys vault |
| **Reset** | Scoped clear (events, alerts, incidents, blocklist, learning, patterns, saved attacks) — never clears users/audit/models/keys |
| **RBAC** | Viewer (read), Analyst (operate), Admin (settings/destructive) |
| **Observability** | Prometheus metrics, health endpoint, websocket live stream, structured logs |

---

## Console Guide

| View | Route | Purpose |
|------|-------|---------|
| **Start Here** | `#/start` | Task-oriented entry point |
| **Command Center** | `#/command` | Live decision stream, KPIs, pause/filter |
| **Alert Center** | `#/alerts` | HIGH/CRITICAL alerts, acknowledge, block-all |
| **Investigations** | `#/investigation/user/U001` | Per-user timeline, graph, recommendations |
| **Incidents** | `#/incidents` | Merged clusters, block-all, timeline |
| **Combined Analysis** | `#/analysis/combined` | Cross-layer clusters, totals, trend |
| **Targeted Analysis** | `#/analysis/target/campaign/C12` | Victims, campaigns, wasted spend |
| **Campaign Analytics** | `#/campaigns` | Campaign-level performance |
| **Event Logs** | `#/logs/events` | Full decision feed, filters, CSV export |
| **Pattern Library** | `#/analysis/patterns` | Create/preview signatures, hit counts |
| **Saved Attacks** | `#/attack/saved` | Named scenarios, replay, compare, import/export |
| **Search** | `#/search?q=U001` | Cross-index search (users, campaigns, ads, devices, incidents, alerts) |
| **Model Monitor** | `#/models` | PSI drift, importance, retrain/rollback |
| **Pipeline** | `#/pipeline` | Component health, weights, latency |
| **Blocklist** | `#/blocklist` | Active blocks, unblock, incident linkage |
| **Rules** | `#/rules` | Create/edit/toggle conditions, weights |
| **Settings** | `#/settings` | Thresholds, retention, AI, keys, login limits |
| **Data & Reset** | `#/settings/data` | Scoped clear with preview, presets, audit |

**Keyboard shortcuts**: `⌘K` command palette, `?` page help, `Esc` close modals, `Space` pause stream, digits `1-9` nav, `/` filter.

---

## API Reference (Key Endpoints)

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `POST` | `/api/clicks` | Public | Single click (strips provenance) |
| `POST` | `/api/events` | Public | Batch clicks |
| `GET` | `/api/fraud/events` | Viewer | Decision feed with filters |
| `GET` | `/api/fraud/events/{id}` | Viewer | Single decision with explanation |
| `GET` | `/api/fraud/users/{id}` | Viewer | User timeline + graph |
| `POST` | `/api/investigate/{id}` | Analyst | LLM investigation report |
| `GET` | `/api/incidents` | Viewer | Incident list (status filter) |
| `GET` | `/api/incidents/{id}` | Viewer | Incident detail + combined view |
| `POST` | `/api/incidents/{id}/block-all` | Analyst | Block all entities (confirm) |
| `GET` | `/api/alerts` | Viewer | Alert list |
| `POST` | `/api/alerts/{id}/status` | Analyst | Acknowledge/resolve |
| `GET` | `/api/blocked` | Viewer | Active blocks |
| `POST` | `/api/blocked` | Analyst | Manual block |
| `DELETE` | `/api/blocked/{type}/{id}` | Analyst | Unblock (confirm) |
| `GET` | `/api/analysis/combined` | Viewer | Cross-layer clusters |
| `GET` | `/api/analysis/target` | Viewer | Targeted analysis |
| `GET` | `/api/analysis/search` | Viewer | Cross-index search |
| `GET` | `/api/logs/events` | Viewer | Event log with filters |
| `GET` | `/api/patterns` | Viewer | Pattern library |
| `POST` | `/api/patterns` | Analyst | Create pattern |
| `PUT` | `/api/patterns/{id}` | Analyst | Update pattern |
| `DELETE` | `/api/patterns/{id}` | Analyst | Delete pattern |
| `POST` | `/api/patterns/preview` | Analyst | Dry-run against history |
| `GET` | `/api/simulations/saved` | Viewer | Saved attacks list |
| `POST` | `/api/simulations/{id}/save` | Analyst | Name a simulation |
| `POST` | `/api/simulations/import` | Analyst | Import JSON |
| `GET` | `/api/simulations/{id}/export` | Viewer | Export JSON |
| `POST` | `/api/simulations/{id}/replay` | Analyst | Replay at speed |
| `GET` | `/api/simulations/compare` | Viewer | Side-by-side |
| `POST` | `/api/simulation/{kind}` | Analyst | Start simulation |
| `POST` | `/api/simulation/stop` | Analyst | Stop all |
| `POST` | `/api/models/retrain` | Admin | Retrain |
| `POST` | `/api/models/rollback` | Admin | Rollback |
| `POST` | `/api/admin/reset` | Admin | Scoped clear (preview first) |

---

## Configuration

Edit `configs/config.yaml` or use the Settings page:

```yaml
risk:
  medium_threshold: 0.35
  high_threshold: 0.65
  critical_threshold: 0.85
  auto_block: true

app:
  db_path: "aegis.db"           # or postgres://user:pass@host:5432/db
  models_dir: "models"
  retention_days: 7
  seed: 42

security:
  rate_limit_per_min: 12000
  login_rate_limit_per_min: 30
  pbkdf2_iterations: 120000

bus:
  kafka_bootstrap: "kafka:9092"
  buffer: 100000

agent:
  enabled: false
  provider: "disabled"   # openai|grok|claude|ollama|disabled
  model: "gpt-4o-mini"
  temperature: 0.1
```

**Environment variables** (Docker):
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis connection string  
- `KAFKA_BOOTSTRAP` — Kafka brokers
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` — Optional graph mirror
- `SECRET_KEY` — JWT signing (required in production)
- `LLM_API_KEY` — For AI agent

---

## Simulator Profiles

| Profile | Description |
|---------|-------------|
| `normal` | Human-like clicks, realistic intervals |
| `random` | Uniform random noise |
| `burst` | Rapid click burst (configurable rate) |
| `bot` | Scripted timing, high velocity |
| `click_farm` | Distributed users, shared device/IP |
| `ip_rotation` | Single user, many IPs |
| `device_farm` | Many users, one device |
| `low_and_slow` | Low rate, long duration |
| `campaign_hopping` | Jumps across campaigns |
| `mimicry` | Human-like with subtle anomalies |

**Scenario targeting**: `target_users` (comma-separated), `target_campaign`, `attack_type` (for labeling).

---

## Development

```bash
# Run tests (unit + browser)
python -m pytest -q
python -m pytest -m browser -q

# Lint
ruff check aegis tests

# Type check
mypy aegis

# Train model manually
python -m aegis.data.dataset
python -m aegis.detection.models

# Run simulator standalone
python -m aegis.simulator.traffic
```

---

## Production Checklist

- [ ] Set `SECRET_KEY` in `.env` (32+ random chars)
- [ ] Use PostgreSQL (`DATABASE_URL`)
- [ ] Configure Redis (`REDIS_URL`)
- [ ] Configure Kafka (`KAFKA_BOOTSTRAP`)
- [ ] Set `LLM_API_KEY` if using AI agent
- [ ] Disable `agent.enabled: false` if not using LLM
- [ ] Set `security.pbkdf2_iterations` appropriately
- [ ] Configure log rotation / log aggregation
- [ ] Set up Prometheus/Grafana dashboards
- [ ] Run `scripts/verify.py` after deploy

---

## License

MIT — Use freely, contribute back.