# AegisClick — Combined Project Report

Real-time advertisement click-fraud detection platform: streaming, hybrid ML, graph intelligence,
online learning, explainability, optional agentic investigation, security and a Bloomberg-style
control center.

---

## 1. Source Analysis (the four input documents)

| # | Document | Contributes |
|---|----------|-------------|
| 1 | Fail-safe production prompt | Every advanced module optional; graceful degradation; `/health` `/status` `/metrics`; JWT + RBAC; AES-encrypted LLM key; provider abstraction; human-in-the-loop; system modes (Full / ML-only / Offline demo / Local AI) |
| 2 | Research master prompt | 7 attack types; Kafka topics; streaming features; graph intelligence; River-style online learning + drift; fusion engine; LangGraph-style investigator; closed-loop adaptation |
| 3 | Platform spec | Two frontends (Ad Simulator + Control Center); Kafka -> stream engine -> fraud engine; rules + supervised ML + anomaly; hybrid risk; SHAP-style explanations; auto-blocking; replay; analytics; model monitoring; DB design; testing; latency metric |
| 4 | UI/UX prompt | Dark terminal UI, KPI strip, live event stream (pause/filter), event drawer, risk bars, explainability panel, pipeline view, blocklist, alerts, command palette, keyboard shortcuts |

### Conflicts / overlaps resolved

| Topic | Conflict | Decision |
|-------|----------|----------|
| Stream engine | Doc 3: Apache Flink; Doc 2: Kafka Streams | Python stateful sliding-window processor with Flink-equivalent semantics (sliding/tumbling windows, keyed state, dedup, event-time). Kafka is the optional transport. |
| Agent | Doc 2: LangGraph; Doc 1: optional LLM | Provider-abstracted investigator (Grok/OpenAI/Claude/Ollama over HTTP). Tool-calling loop over read-only tools. Deterministic rule-based fallback when no key. |
| Online learning | River | `SGDClassifier.partial_fit` online model + Page-Hinkley/ADWIN-style drift detector (no heavy dependency). |
| Graph DB | Neo4j / PyG | NetworkX in-process graph (shared device/IP/campaign communities). |
| Database | PostgreSQL + Redis | SQLite (stdlib) default, in-process state for hot counters; schema is relational and portable. |
| Models | XGBoost/LightGBM | "Simple models" requested: Logistic Regression, **MLP neural network** (scikit-learn), Histogram Gradient Boosting; Isolation Forest for anomaly. XGBoost/LightGBM can slot into the registry. |
| Explainability | SHAP | Exact linear contributions for LR; occlusion (baseline-substitution) attribution for MLP/GBM. Real model deltas, never fabricated text. |
| Frontend stack | Doc 3: Next.js/React/TS/Tailwind | Dependency-free vanilla JS served by FastAPI (zero build step, runs offline, fewer moving parts for a laptop demo). Same screens and behaviours. |
| Dataset | "search and include" | Built-in labeled simulator (7 attacks) + loader for the public **TalkingData AdTracking** dataset (see section 5). |

---

## 2. System Architecture

```
 Ad Simulator UI (/sim)         Control Center UI (/)
        |                               ^
        v  POST /api/clicks             | WebSocket /ws
   +-----------------------------------------------+
   |                   FastAPI                      |
   |  auth(JWT/RBAC) | rate-limit | validation      |
   +----------------------+------------------------+
                          v
                 EventBus (optional Kafka)
        Kafka available? --yes--> topics: ad-click-events, fraud-predictions,
                          |                fraud-alerts, user-block-events
                          +--no---> in-memory queue (replayable)
                          v
              Stream Processor (keyed sliding windows)
                          v
   +--------- Fraud Engine (each layer optional) ---------+
   | Rules | LogReg | MLP | Isolation Forest | Graph | Online |
   +------------------------+------------------------------+
                            v
                   Hybrid Risk Fusion
        LOW / MEDIUM / HIGH / CRITICAL -> ALLOW / MONITOR / FLAG / BLOCK
                            v
   SQLite store | block-list | alerts | explanations | audit log
                            v
        Optional Agent (LLM) -> recommendations only, human approval
```

### Fail-safe matrix

| Component down | Behaviour |
|----------------|-----------|
| Kafka | In-memory bus; `bus.mode` shown in `/status` |
| ML model files missing | Auto-train on simulator data at startup; else rules-only with LOW confidence |
| Anomaly model | Score omitted, weights renormalised |
| Graph | Graph score omitted |
| Online learner | Static models continue; error logged |
| LLM / no key | Rule-based explanation text; agent status DISABLED |
| DB write failure | Event still scored and streamed; error counted |

Weights are renormalised over **available** layers; confidence = LOW/MEDIUM/HIGH by layer coverage.

---

## 3. Modules

| Module | File | Purpose |
|--------|------|---------|
| Config | `aegis/config.py` | YAML + env settings, thresholds, weights |
| Schemas | `aegis/schemas.py` | `ClickEvent`, `Decision` (extensible `event_type`) |
| Simulator | `aegis/simulator/traffic.py` | Normal + 7 attacks (burst, bot, click farm, IP rotation, device farm, low-and-slow, campaign hopping, mimicry) |
| Dataset | `aegis/data/dataset.py` | Labeled dataset builder, TalkingData adapter |
| Bus | `aegis/streaming/bus.py` | In-memory / Kafka with fallback |
| Features | `aegis/streaming/features.py` | 1m/5m/1h windows, intervals, burst, entropy, device/IP reuse |
| Rules | `aegis/detection/rules.py` | Configurable rule engine |
| Models | `aegis/detection/models.py` | LR, MLP, HGB, IsolationForest + registry/versioning |
| Online | `aegis/detection/online.py` | Incremental learner + drift detection |
| Graph | `aegis/detection/graph.py` | Shared device/IP community score |
| Explain | `aegis/detection/explain.py` | Global importance + local attribution |
| Risk | `aegis/detection/risk.py` | Fusion, levels, actions |
| Agent | `aegis/agent/investigator.py` | Provider abstraction + fallback |
| Security | `aegis/security/auth.py` | JWT, PBKDF2, RBAC, Fernet key vault |
| Store | `aegis/store/db.py` | Users, events, predictions, alerts, blocklist, models, audit |
| Pipeline | `aegis/pipeline.py` | Orchestrator, health, metrics |
| API | `aegis/api/app.py` | REST + WebSocket + static UIs |
| Evaluation | `aegis/evaluation/*` | Metrics, plots, scenario tests, benchmark |

---

## 4. Feature Set (streaming, per click, keyed by user/device/ip)

`clicks_1m, clicks_5m, clicks_1h, avg_interval, min_interval, interval_std, burst_score,
timing_entropy, unique_ads, unique_ips_per_device, unique_devices_per_ip, unique_users_per_device,
repeat_ad_ratio, campaign_ctr_dev, geo_mismatch, ua_bot_flag, account_age_days`

---

## 5. Datasets

1. **Built-in simulator (default, reproducible, seeded).** Labeled legit + 8 fraud behaviours; used for train / validation / test with a **scenario-held-out** split for a fair unseen-attack test.
2. **TalkingData AdTracking Fraud Detection (Kaggle, ~185M clicks, ~0.25% attributed).** Fields: `ip, app, device, os, channel, click_time, attributed_time, is_attributed`. Requires a Kaggle login (not downloadable in automated environments). Place `train.csv` or `train_sample.csv` in `data/raw/` and run `make talkingdata`.
   **Caveat:** the label `is_attributed` is *app download*, a conversion proxy, not a ground-truth fraud label. The adapter reports AUC for predicting conversion using frequency/time-delta features and is presented as an external benchmark, not as fraud accuracy.

---

## 6. ML Design

| Layer | Model | Role |
|-------|-------|------|
| Baseline | Logistic Regression (balanced) | Interpretable baseline |
| Neural network | MLP (64-32, early stopping) | Primary non-linear scorer |
| Tree model | HistGradientBoosting | Strong tabular comparison |
| Anomaly | Isolation Forest (fit on legit only) | Unseen patterns |
| Online | SGD log-loss + `partial_fit` | Adapts to drift |
| Graph | Connected-component fan-out | Coordinated farms |

Metrics: Precision, Recall, F1, ROC-AUC, PR-AUC, FPR, FNR, confusion matrix, per-attack recall,
detection latency. **No numbers are hard-coded; all come from `make evaluate` into `reports/`.**

---

## 7. Risk Fusion

```
risk = sum(w_i * s_i) / sum(w_i)   over available layers
default w: rules 0.25, ml 0.40, anomaly 0.15, graph 0.20
0-0.30 LOW/ALLOW   0.30-0.70 MEDIUM/MONITOR   0.70-0.90 HIGH/FLAG   >=0.90 CRITICAL/BLOCK
```
A hard rule hit (known-bad IP / impossible click rate) floors the risk at HIGH.

---

## 8. Security

JWT (HS256) with roles `admin / analyst / viewer`; PBKDF2-SHA256 password hashing; Fernet (AES-128-CBC + HMAC)
encryption of stored LLM API keys, never returned by API; IPs stored as salted hash alongside display mask;
per-IP token-bucket rate limiting; Pydantic validation; CORS allow-list; audit log; agent has read-only
tools and may only write *recommendations*; blocking by the agent requires human approval.
Poisoning defense: online learner only learns from analyst-confirmed labels or high-confidence agreement, with delayed commit.

---

## 9. UI Plan

`/` Control Center (dark terminal): header status, KPI strip, live stream (pause/filter), event drawer
with attributions, risk timeline, alerts, blocklist, pipeline status, model panel, command palette (Ctrl/Cmd+K),
shortcuts (Space, Esc, /, 1-5). `/sim` Ad Network Simulator: users, ads, normal click, attack launchers,
intensity, status badges that turn BLOCKED live.

---

## 10. Execution Modes

| Mode | Config | Description |
|------|--------|-------------|
| Offline demo | default | In-memory bus, rules + ML |
| ML only | `AGENT_ENABLED=false` | No LLM |
| Full | Kafka + LLM key | Everything |
| Local AI | `LLM_PROVIDER=ollama` | No API cost |

---

## 11. Verification Plan

Unit tests (features, rules, risk, security, bus, simulator), integration tests (API -> pipeline -> block ->
reject), scenario tests (each attack detected above threshold), load benchmark (events/s, p50/p95 latency),
`make verify` smoke test. Run results are written to `reports/`.

---

## 12. Honest Limitations

- Flink, Neo4j, Postgres, Redis, Prometheus/Grafana are replaced by in-process equivalents for portability; the interfaces (bus, store) allow swapping.
- Simulated-data metrics reflect the simulator, not production traffic. Mimicry/low-and-slow attacks are the hardest and are reported separately.
- TalkingData label is a conversion proxy (section 5).
- Kafka mode is implemented via `kafka-python` and verified only structurally here (no broker in the build sandbox); `docker-compose.yml` provides a broker.

---

## 13. Roadmap

Phase 1 simulator+schema -> 2 bus -> 3 features -> 4 rules -> 5 ML -> 6 fusion -> 7 explain -> 8 API/WS ->
9 blocking -> 10 UI -> 11 evaluation -> 12 packaging. (Built in this order.)


---

## 14. As-Built Verification (measured; reproduce with `make test evaluate verify`)

| check | result |
|---|---|
| Tests, core install (no optional libraries) | 64 passed, 6 skipped (real-backend tests skip when the backend is absent) |
| Tests, all backends (real PostgreSQL, Redis, local Flink cluster, Prometheus) | 76 passed |
| End-to-end smoke (`make verify`) | real server process: HTTP, auth, attack, auto-block, rejection, alerts, attribution all passed |
| Clean-room install | unzip -> `make setup` -> tests -> verify -> evaluate, in a fresh directory |
| Held-out test PR-AUC by model | LogReg 0.9370, MLP 0.9789, HistGB 0.9813, XGBoost 0.9852, LightGBM 0.9814, ensemble (MLP+HistGB) 0.9824 |
| Ensemble at 0.5 | precision 0.889, recall 0.955, F1 0.921, FPR 0.0123 |
| Full pipeline (fusion + auto-block), flag decision | precision 0.9918, recall 0.9131, F1 0.9508, FPR 0.0008; legitimate users auto-blocked: 0 |
| Throughput (single process) | 101 ev/s one-by-one; 2,476 ev/s batch 200; 2,980 ev/s batch 1000 |
| Latency | single event p50 9.8 ms, p95 12.6 ms; HTTP ingest 1,661 ev/s (detection p50 20 ms, p95 38 ms) |

Full tables (per layer, per attack, per actor, unseen-attack generalisation) are in `reports/EVALUATION.md`.
Throughput is lower than in the first build because of added monitoring, shared-state and persistence bookkeeping.

### Findings worth knowing
- A first model version reached unrealistically high scores because the simulator leaked fraud through account age; the simulator was corrected and everything re-measured.
- Models trained only on 5 attack types generalise **poorly** to the 3 unseen ones; this is why the platform fuses several layers and supports online learning (evaluation report, section C).
- Campaign-hopping is the weakest attack at event level although every actor is eventually flagged.
- Metrics are on simulator data. They demonstrate the pipeline, not production accuracy.

---

## 15. Audit Addendum and Completion Round

### Fixed after audit
Declared Python >=3.10 although pinned numpy/pandas/scikit-learn need 3.11 (now 3.11+); `/docs` blocked by the CSP (relaxed for that page
only); delayed pseudo-label learning was documented but not wired (now wired, opt-in, analyst feedback overrides); added `campaigns`,
`advertisements`, `devices` tables; CSV export/replay offline mode; toast flood on mass auto-block; real-browser (Chromium) UI tests.

### Gaps closed in the completion round
| gap | now | verification |
|---|---|---|
| PostgreSQL | full `Store` dialect layer (`postgresql://`), automatic SQLite fallback | whole persistence layer + pipeline + API run against a real PostgreSQL |
| Redis | `RedisState` (block-list, rate limiter, active users, counters, shared stats), fail-open on outage | real Redis, two pipelines sharing a block-list, outage test |
| Flink | PyFlink job with keyed event-time state | parity with the Python engine on a real local Flink cluster (diff < 1e-6) |
| Neo4j | write-behind graph mirror + Cypher queries | fake-driver tests (live Neo4j not available) |
| Grafana/Prometheus | rich `/metrics`, alert rules, provisioned 10-panel dashboard, compose profiles | promtool + every dashboard query executed on a real Prometheus; Grafana rendering not tested |
| XGBoost / LightGBM | trained and evaluated next to the other models | evaluation tables |
| SHAP | real SHAP library backend (permutation, additive) + TreeSHAP global importance | additivity tests; falls back to built-in Shapley |
| LangGraph | StateGraph workflow (gather -> classify -> optional LLM refine -> finalize) | same report as the loop; LLM-failure degradation |
| Campaign spend, timelines, device types, drift + precision charts, rule editor | new endpoints + UI screens | API tests + real-browser run |
| Replay distortion | event time preserved, only emission accelerated | unit test |
| Retention | configurable sweep + admin endpoint | unit/API tests (SQLite and PostgreSQL) |

### Findings during the round
- The first drift monitor compared live traffic with short, non-steady-state training episodes and raised false DRIFT alarms on clean traffic. It now compares against a reference window captured after warm-up (training skew is shown separately). Separately verified: 4 hours of purely legitimate traffic produce no false-alarm growth.
- Precision/recall over time requires ground truth, so it only works for built-in simulations (client-submitted events are stripped of labels by design).

### Still not done
Next.js/React/TypeScript/Tailwind frontend (vanilla JS kept; see README). Not exercised against live services: Kafka broker + Flink Kafka I/O, Neo4j, Grafana rendering, real LLM providers.
