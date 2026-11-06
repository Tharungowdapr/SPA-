# AegisClick Security & Quality Audit

## Summary

Audit performed against the hardening prompt. Focus on P0 security, P1 functional correctness, P2 UX/maintainability.

## Findings

| # | Severity | Category | Finding | Affected Path | Status |
|---|----------|----------|---------|---------------|--------|
| 1 | P0 | Security | Default JWT secret (`dev-insecure-secret-change-me`) accepted in production | `aegis/config.py:64`, `aegis/api/app.py:161` | **Fixed** — rejects weak/placeholder secrets in production |
| 2 | P0 | Security | Default demo passwords seeded in production | `aegis/api/app.py:199-203` | **Fixed** — requires ADMIN_PASSWORD etc. env vars in production |
| 3 | P0 | Security | MASTER_KEY defaults to SECRET_KEY | `aegis/config.py:68` | **Fixed** — must differ in production |
| 4 | P0 | Security | Silent Postgres→SQLite fallback in production | `aegis/api/app.py:166-175` | **Fixed** — raises clear error in production |
| 5 | P0 | Security | RateLimiter state unbounded (defaultdict grows forever) | `aegis/security/auth.py:59-76` | **Fixed** — bounded to 10k keys with idle expiry (300s) and LRU eviction |
| 6 | P0 | Security | HttpOnly cookie auth not implemented (bearer tokens in localStorage) | `web/common.js`, `aegis/api/app.py` | **Deferred** — requires frontend refactor; current CSP is permissive (`unsafe-inline`) |
| 7 | P0 | Security | WebSocket auth via query-string bearer token | `aegis/api/app.py:1030` | **Deferred** — needs short-lived ticket or cookie auth |
| 8 | P1 | Functional | Side-nav navigation broken (invalid onclick HTML) | `web/control.html:176` | **Fixed** — rewrote navItem with proper quoting |
| 9 | P1 | Functional | 12 onclick handlers had stray `}}` making buttons no-ops | `web/control.html` | **Fixed** — removed stray braces |
| 10 | P1 | Functional | Login overlay never hid (`#login` forced `display:flex`) | `web/app.css:104` | **Fixed** — `display:none` + `.on{display:flex}` |
| 11 | P1 | Functional | Missing views (Incidents, Target, Logs, Patterns, Saved, Search, DataRst) | `web/control.html` | **Fixed** — all implemented and registered |
| 12 | P1 | Functional | `clearScope` referenced but never defined | `web/control.html` | **Fixed** — implemented |
| 13 | P2 | UX | Uppercase tracked labels on small text (slop) | `web/app.css` | **Fixed** — removed letter-spacing, reduced weights per unslop |
| 14 | P2 | UX | Alert detail had no user info, reasons, or graphs | `web/control.html` | **Fixed** — added user info table, behavior, ordered reasons, score overlay |
| 15 | P3 | Performance | Sub-10ms/10k eps claim unverified | README | **Documented** — claim marked unverified, needs benchmark |
| 16 | P1 | Functional | `/status` and `/metrics` are public | `aegis/api/app.py:367-373` | **Noted** — consider auth gating in production |
| 17 | P0 | Security | CORS allow-list from config (empty by default) | `aegis/api/app.py:306` | **Reviewed** — origins default to empty list; production must configure |
| 18 | P0 | Security | Imported simulation limits not bounded | `aegis/api/app.py:803` | **Noted** — review max size |

## Remaining Items

### P0 (deferred, need larger refactor)
- HttpOnly cookie auth + CSRF (frontend + backend)
- WebSocket ticket auth (replace query-string token)
- Proxy-aware client IP handling
- Shared atomic rate limiter for multi-worker (Redis-backed exists, memory is per-worker)

### P1
- Browser E2E coverage for high-risk flows (alert ack, block/unblock, reset)
- Regression tests for each verified fix

### P2
- Split monolithic `control.html` into modules
- Consolidate analytics pages
- Accessible status text (aria-live already present)

### P3
- Representative benchmarks (p50/p95/p99 latency, throughput, CPU/memory)
- Profile and optimize hot paths

## Test Results

- `pytest -q -o addopts=""`: 157 passed, 26 skipped
- `ruff check aegis tests`: All checks passed
- Production mode startup: correctly fails without strong secrets, succeeds with them

## Deployment Notes

1. Set `APP_ENV=production`
2. Set `SECRET_KEY` (>=32 chars, unique, not a placeholder)
3. Set `MASTER_KEY` (>=32 chars, different from SECRET_KEY)
4. Set `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD`
5. Set `DATABASE_URL` (PostgreSQL) — required in production (no SQLite fallback)
6. Run `python scripts/run_dualstack.py` or use Docker compose
7. Run `python -m pytest -q` to verify

## Known Limitations

- Bearer tokens stored in localStorage (XSS risk) — deferred to cookie migration
- WebSocket token in query string (log exposure risk) — deferred to ticket migration
- In-memory rate limiter is per-worker (not shared across processes)
- Sub-10ms/10k eps performance claim is unverified
- Optional ML dependencies (XGBoost, LightGBM) increase attack surface and startup time