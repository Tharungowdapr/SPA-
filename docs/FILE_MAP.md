# File Map — AegisClick

Generated: 2025

## Root

```
aegisclick/
├── README.md
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── configs/
│   └── config.yaml
├── aegis/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py              # FastAPI app, all endpoints
│   │   └── dependencies.py
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── investigator.py     # LLM investigation agent
│   │   └── llm.py              # LLM provider abstraction
│   ├── config.py               # Settings management
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── models.py           # LightGBM + PyTorch models
│   │   ├── rules.py            # Rule engine
│   │   ├── anomaly.py          # IsolationForest anomaly
│   │   ├── graph.py            # NetworkX graph engine
│   │   ├── online.py           # River online learner
│   │   ├── explain.py          # SHAP + rule factors
│   │   ├── reasons.py          # Plain-English explanations
│   │   ├── patterns.py         # Pattern library classifier
│   │   └── risk.py             # Fusion + action engine
│   ├── schemas.py              # Pydantic models (ClickEvent, Decision, etc.)
│   ├── simulator/
│   │   ├── __init__.py
│   │   ├── manager.py          # SimulationManager
│   │   └── traffic.py          # Profile generators
│   ├── security/
│   │   ├── __init__.py
│   │   └── auth.py             # JWT, PBKDF2, rate limiting
│   ├── streaming/
│   │   ├── __init__.py
│   │   ├── bus.py              # Kafka/Redis/Memory bus
│   │   └── features.py         # Feature engineering
│   ├── store/
│   │   ├── __init__.py
│   │   ├── db.py               # SQLite/PostgreSQL store + migrations
│   │   └── state.py            # In-memory state (hot vectors, etc.)
│   └── pipeline.py             # Main orchestration (click → decision)
├── web/
│   ├── control.html            # Main console (SPA, hash routing)
│   ├── sim.html                # Simulator UI
│   ├── common.js               # Shared helpers (api, auth, ws)
│   └── app.css                 # Styles
├── tests/
│   ├── conftest.py
│   ├── browser_helpers.py
│   ├── browser_server.py
│   ├── test_migrations.py
│   ├── test_persistence.py
│   ├── test_reset.py
│   ├── test_reset_browser.py
│   ├── test_reasons.py
│   ├── test_reasons_browser.py
│   ├── test_incidents.py
│   ├── test_analysis_patterns.py
│   └── test_simulator.py
├── scripts/
│   └── verify.py
└── docs/
    └── FILE_MAP.md
```

## Module Table

| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `aegis.pipeline` | Main orchestration | `Pipeline.process_events()`, `Pipeline._score()`, `Pipeline._act()` |
| `aegis.detection.models` | ML models | `ModelBundle.train()`, `ModelBundle.predict()`, `ModelBundle.psi()` |
| `aegis.detection.rules` | Rule engine | `RuleEngine.eval()`, `validate_rules()` |
| `aegis.detection.anomaly` | IsolationForest | `AnomalyDetector.fit()`, `AnomalyDetector.score()` |
| `aegis.detection.graph` | Graph engine | `GraphEngine.add_edge()`, `GraphEngine.component()`, `GraphEngine.score()` |
| `aegis.detection.online` | River learner | `OnlineLearner.learn_one()`, `OnlineLearner.predict_one()` |
| `aegis.detection.risk` | Fusion + action | `RiskEngine.fuse()`, `RiskEngine.decide()` |
| `aegis.detection.reasons` | Explanations | `explain_decision()`, `explain_event()`, `_safe_format()` |
| `aegis.detection.patterns` | Pattern library | `classify()`, `validate_signature()`, `signature_matches()` |
| `aegis.detection.explain` | SHAP + factors | `local_explanation()`, `rule_factors()`, `explanation_text()` |
| `aegis.agent.investigator` | LLM agent | `Investigator.investigate()` |
| `aegis.agent.llm` | LLM abstraction | `LLMManager.complete()` |
| `aegis.simulator.manager` | Simulation manager | `SimulationManager.start()`, `replay()`, `stop()` |
| `aegis.simulator.traffic` | Traffic generators | `UserPool`, `ClickEvent`, profile functions |
| `aegis.store.db` | Persistence | `Store.save_batch()`, `Store.add_incident()`, `Store.add_pattern()`, `Store.log_events()` |
| `aegis.store.state` | Hot state | `MemoryState.vectors`, `MemoryState.add()`, `MemoryState.prune()` |
| `aegis.streaming.bus` | Message bus | `InMemoryBus`, `KafkaBus`, `RedisBus` |
| `aegis.streaming.features` | Feature eng | `FeatureEngine.compute()`, `vectorize()` |
| `aegis.security.auth` | Auth | `create_token()`, `decode_token()`, `hash_password()`, `RateLimiter` |
| `aegis.config` | Settings | `Settings.get()`, `Settings.set()`, `Settings.copy()` |
| `aegis.api.app` | FastAPI app | `create_app()`, all route handlers |
| `aegis.schemas` | Pydantic models | `ClickEvent`, `Decision`, `Recommendation`, `SimulationSaveIn`, `PatternIn` |

## Database Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `users` | Seed users | `user_id`, `email`, `role`, `password_hash`, `created` |
| `click_events` | Raw clicks | `event_id`, `ts`, `user_id`, `ad_id`, `campaign_id`, `device_id`, `ip_hash`, `ip_mask`, `country`, `label`, `attack_type`, `source`, `run_id` |
| `fraud_predictions` | Decisions | `event_id`, `ts`, `user_id`, `risk`, `level`, `action`, `confidence`, `scores`, `rules`, `model_version`, `latency_ms`, `factors`, `classification`, `classification_source`, `reason`, `reason_title` |
| `fraud_alerts` | Alerts | `id`, `ts`, `severity`, `title`, `user_id`, `campaign_id`, `status`, `details`, `incident_id` |
| `blocked_entities` | Blocks | `entity_type`, `entity_id`, `reason`, `score`, `ts`, `active`, `blocked_by`, `fraud_clicks`, `reason_detail` |
| `incidents` | Correlated clusters | `id`, `first_seen`, `last_seen`, `status`, `classification`, `confidence`, `campaigns`, `users_n`, `devices_n`, `ips_n`, `events_n`, `peak_risk`, `summary`, `run_id` |
| `incident_entities` | Incident members | `incident_id`, `entity_type`, `entity_id`, `first_seen`, `last_seen`, `flagged`, `peak_risk`, `blocked` |
| `patterns` | Analyst signatures | `id`, `name`, `description`, `action`, `signature`, `examples_n`, `created_by`, `created`, `updated`, `enabled` |
| `pattern_hits` | Pattern matches | `pattern_id`, `ts`, `event_id`, `user_id`, `device_id` |
| `attack_simulations` | Saved runs | `id`, `ts`, `kind`, `params`, `events`, `events_json`, `name`, `notes`, `tags`, `created_by`, `duration`, `actors_n` |
| `recommendations` | LLM actions | `id`, `ts`, `user_id`, `type`, `score`, `action`, `source`, `details`, `status` |
| `model_versions` | ML artifacts | `version`, `trained_at`, `status`, `metrics` |
| `audit_log` | Admin actions | `id`, `ts`, `actor`, `action`, `target`, `detail` |
| `system_events` | Internal events | `id`, `ts`, `kind`, `message` |
| `settings_kv` | Config | `key`, `value`, `updated` |
| `api_settings` | AI keys | `id`, `provider`, `model`, `encrypted_key`, `temperature`, `enabled`, `updated` |

## API Endpoints (Selected)

| Method | Path | Handler |
|--------|------|---------|
| `POST` | `/api/clicks` | `ingest_click` |
| `POST` | `/api/events` | `ingest_events` |
| `GET` | `/api/fraud/events` | `list_events` |
| `GET` | `/api/fraud/events/{id}` | `event_detail` |
| `GET` | `/api/fraud/users/{id}` | `user_investigation` |
| `POST` | `/api/investigate/{id}` | `investigate_user` |
| `GET` | `/api/incidents` | `list_incidents` |
| `GET` | `/api/incidents/{id}` | `incident_detail` |
| `POST` | `/api/incidents/{id}/block-all` | `incident_block_all` |
| `GET` | `/api/alerts` | `alerts` |
| `POST` | `/api/alerts/{id}/status` | `alert_status` |
| `GET` | `/api/blocked` | `blocked` |
| `POST` | `/api/blocked` | `block_entity` |
| `DELETE` | `/api/blocked/{etype}/{eid}` | `unblock_entity` |
| `GET` | `/api/analysis/combined` | `analysis_combined` |
| `GET` | `/api/analysis/target` | `analysis_target` |
| `GET` | `/api/analysis/search` | `analysis_search` |
| `GET` | `/api/logs/events` | `log_events` |
| `GET` | `/api/patterns` | `patterns_list` |
| `POST` | `/api/patterns` | `patterns_create` |
| `PUT` | `/api/patterns/{id}` | `patterns_update` |
| `DELETE` | `/api/patterns/{id}` | `patterns_delete` |
| `POST` | `/api/patterns/preview` | `patterns_preview` |
| `GET` | `/api/patterns/{id}/hits` | `patterns_hits` |
| `GET` | `/api/simulations/saved` | `simulations_saved` |
| `POST` | `/api/simulations/{id}/save` | `simulation_save` |
| `DELETE` | `/api/simulations/{id}` | `simulation_delete` |
| `POST` | `/api/simulations/{id}/duplicate` | `simulation_duplicate` |
| `GET` | `/api/simulations/compare` | `simulations_compare` |
| `GET` | `/api/simulations/{id}/export` | `simulation_export` |
| `POST` | `/api/simulations/import` | `simulation_import` |
| `POST` | `/api/simulation/{kind}` | `start_simulation` |
| `POST` | `/api/simulation/stop` | `stop_simulation` |
| `GET` | `/api/simulation/status` | `simulation_status` |
| `GET` | `/api/models` | `models_list` |
| `POST` | `/api/models/retrain` | `retrain_model` |
| `POST` | `/api/models/rollback` | `rollback_model` |
| `GET` | `/api/admin/reset/scopes` | `reset_scopes` |
| `GET` | `/api/admin/reset/preview` | `reset_preview` |
| `POST` | `/api/admin/reset` | `reset_execute` |
| `POST` | `/api/auth/login` | `login` |
| `GET` | `/api/me` | `me` |
| `GET` | `/health` | `health` |
| `GET` | `/metrics` | `metrics` |

## Frontend Views (control.html)

| View Key | Route | Description |
|----------|-------|-------------|
| `start` | `#/start` | Start Here landing page |
| `cmd` | `#/command` | Command Center (live stream) |
| `alerts` | `#/alerts` | Alert Center |
| `user` | `#/investigation/user` | User investigation |
| `incidents` | `#/incidents` | Incident list |
| `incident` | `#/incident/{id}` | Incident detail |
| `analytics` | `#/analysis/combined` | Combined analysis |
| `target` | `#/analysis/target/campaign/{id}` | Targeted analysis |
| `campaigns` | `#/campaigns` | Campaign analytics |
| `logs` | `#/logs/events` | Event logs |
| `patterns` | `#/analysis/patterns` | Pattern library |
| `patternDetail` | `#/analysis/patterns/{id}` | Pattern editor |
| `saved` | `#/attack/saved` | Saved attacks list |
| `savedDetail` | `#/attack/saved/{id}` | Saved attack detail |
| `search` | `#/search?q=...` | Universal search |
| `models` | `#/models` | Model monitor |
| `pipeline` | `#/pipeline` | Pipeline health |
| `blocklist` | `#/blocklist` | Blocklist |
| `rules` | `#/rules` | Rule editor |
| `settings` | `#/settings` | System settings |
| `datarst` | `#/settings/data` | Data & Reset |

## Configuration Keys (config.yaml)

```yaml
app:
  db_path: "aegis.db"
  models_dir: "models"
  retention_days: 7
  seed: 42
  env: "development"

security:
  rate_limit_per_min: 12000
  login_rate_limit_per_min: 30
  pbkdf2_iterations: 120000
  secret_key: "dev-insecure-change-in-production"

risk:
  medium_threshold: 0.35
  high_threshold: 0.65
  critical_threshold: 0.85
  auto_block: true
  weights:
    rules: 0.25
    ml: 0.35
    anomaly: 0.15
    graph: 0.15
    online: 0.10

bus:
  kafka_bootstrap: "kafka:9092"
  buffer: 100000

state:
  redis_url: "redis://redis:6379/0"
  hot_window: 1200
  max_vectors: 20000

graph:
  neo4j_uri: ""
  max_depth: 2

online:
  window: 500
  step: 0.01

anomaly:
  contamination: 0.01

agent:
  enabled: false
  provider: "disabled"
  model: "gpt-4o-mini"
  temperature: 0.1

app:
  retention:
    events_days: 7
    alerts_days: 30
    incidents_days: 90
    recommendations_days: 30
    simulations_days: 30
    patterns_days: 365
```

## Test Inventory

| File | Tests | Markers |
|------|-------|---------|
| `test_migrations.py` | 8 | - |
| `test_persistence.py` | 12 | - |
| `test_reset.py` | 15 | - |
| `test_reset_browser.py` | 6 | `browser` |
| `test_reasons.py` | 12 | - |
| `test_reasons_browser.py` | 9 | `browser` |
| `test_incidents.py` | 14 | - |
| `test_analysis_patterns.py` | 16 | - |
| `test_simulator.py` | 8 | - |
| **Total** | **115+** | **15 browser** |

---

*Generated by `scripts/verify.py`*