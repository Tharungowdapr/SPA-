"""Persistence (SQLite, stdlib). Relational schema mirrors the PostgreSQL design in the spec and is portable.

All access goes through one connection guarded by a lock; bulk writes are batched in transactions.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

FLAG_SUM = "SUM(CASE WHEN p.action IN ('FLAG','BLOCK') THEN 1 ELSE 0 END)"
DEVICE_TYPE_SQL = ("CASE WHEN LOWER(d.user_agent) LIKE '%curl%' OR LOWER(d.user_agent) LIKE '%python%' OR LOWER(d.user_agent) LIKE '%headless%' "
                   "OR LOWER(d.user_agent) LIKE '%scrapy%' OR LOWER(d.user_agent) LIKE '%wget%' OR LOWER(d.user_agent) LIKE '%bot%' THEN 'Bot/script' "
                   "WHEN LOWER(d.user_agent) LIKE '%iphone%' OR LOWER(d.user_agent) LIKE '%android%' OR LOWER(d.user_agent) LIKE '%mobile%' THEN 'Mobile' "
                   "WHEN LOWER(d.user_agent) LIKE '%windows%' OR LOWER(d.user_agent) LIKE '%macintosh%' OR LOWER(d.user_agent) LIKE '%x11%' THEN 'Desktop' "
                   "ELSE 'Unknown' END")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, role TEXT, password_hash TEXT, created REAL);
CREATE TABLE IF NOT EXISTS api_settings(user_id INTEGER PRIMARY KEY, provider TEXT, encrypted_key TEXT, model TEXT,
  temperature REAL, enabled INTEGER, updated REAL);
CREATE TABLE IF NOT EXISTS campaigns(campaign_id TEXT PRIMARY KEY, first_seen REAL);
CREATE TABLE IF NOT EXISTS advertisements(ad_id TEXT PRIMARY KEY, campaign_id TEXT REFERENCES campaigns(campaign_id), first_seen REAL);
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, user_id TEXT, user_agent TEXT, country TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS click_events(event_id TEXT PRIMARY KEY, ts REAL, user_id TEXT, ad_id TEXT, campaign_id TEXT,
  publisher_id TEXT, device_id TEXT, ip_hash TEXT, ip_mask TEXT, country TEXT, label INTEGER, attack_type TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON click_events(ts);
CREATE INDEX IF NOT EXISTS ix_ev_user ON click_events(user_id);
CREATE INDEX IF NOT EXISTS ix_ev_campaign ON click_events(campaign_id);
CREATE TABLE IF NOT EXISTS fraud_predictions(event_id TEXT PRIMARY KEY, ts REAL, user_id TEXT, risk REAL, level TEXT,
  action TEXT, confidence TEXT, scores TEXT, rules TEXT, model_version TEXT, latency_ms REAL, factors TEXT);
CREATE INDEX IF NOT EXISTS ix_pred_ts ON fraud_predictions(ts);
CREATE INDEX IF NOT EXISTS ix_pred_user ON fraud_predictions(user_id);
CREATE TABLE IF NOT EXISTS fraud_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT, title TEXT,
  user_id TEXT, campaign_id TEXT, status TEXT DEFAULT 'open', details TEXT);
CREATE TABLE IF NOT EXISTS blocked_entities(entity_type TEXT, entity_id TEXT, reason TEXT, score REAL, ts REAL,
  active INTEGER DEFAULT 1, blocked_by TEXT, fraud_clicks INTEGER DEFAULT 0, PRIMARY KEY(entity_type, entity_id));
CREATE TABLE IF NOT EXISTS model_versions(version TEXT PRIMARY KEY, trained_at REAL, status TEXT, metrics TEXT);
CREATE TABLE IF NOT EXISTS attack_simulations(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, params TEXT,
  events INTEGER, events_json TEXT);
CREATE TABLE IF NOT EXISTS recommendations(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user_id TEXT, summary TEXT,
  attack_type TEXT, confidence REAL, action TEXT, source TEXT, status TEXT DEFAULT 'pending', details TEXT);
CREATE TABLE IF NOT EXISTS system_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS settings_kv(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, first_seen REAL, last_seen REAL,
  status TEXT DEFAULT 'open', classification TEXT, confidence REAL, campaigns TEXT, users_n INTEGER DEFAULT 0,
  devices_n INTEGER DEFAULT 0, ips_n INTEGER DEFAULT 0, events_n INTEGER DEFAULT 0, flagged_n INTEGER DEFAULT 0,
  blocked_n INTEGER DEFAULT 0, peak_risk REAL DEFAULT 0, wasted_spend REAL DEFAULT 0, summary TEXT, run_id TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_last ON incidents(last_seen);
CREATE INDEX IF NOT EXISTS ix_inc_run ON incidents(run_id);
CREATE TABLE IF NOT EXISTS incident_entities(incident_id INTEGER, entity_type TEXT, entity_id TEXT, first_seen REAL,
  last_seen REAL, events INTEGER DEFAULT 0, flagged INTEGER DEFAULT 0, peak_risk REAL DEFAULT 0,
  blocked INTEGER DEFAULT 0, PRIMARY KEY(incident_id, entity_type, entity_id));
CREATE INDEX IF NOT EXISTS ix_inc_ent ON incident_entities(incident_id);
CREATE TABLE IF NOT EXISTS patterns(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT,
  action TEXT DEFAULT 'label', signature TEXT, examples_n INTEGER DEFAULT 0, created_by TEXT, created REAL,
  updated REAL, hits INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, last_seen REAL);
CREATE TABLE IF NOT EXISTS pattern_hits(id INTEGER PRIMARY KEY AUTOINCREMENT, pattern_id INTEGER, ts REAL,
  event_id TEXT, user_id TEXT, incident_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_ph_pattern ON pattern_hits(pattern_id);
"""

# Columns added after the first release. Applied by Store._migrate() so databases created by
# an earlier version keep working; each is added only when missing.
NEW_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "click_events": [("source", "TEXT"), ("run_id", "TEXT")],
    "fraud_predictions": [("features", "TEXT"), ("classification", "TEXT"), ("classification_source", "TEXT"),
                          ("reason", "TEXT"), ("reason_title", "TEXT")],
    "fraud_alerts": [("incident_id", "INTEGER")],
    "blocked_entities": [("reason_detail", "TEXT")],
    "attack_simulations": [("name", "TEXT"), ("notes", "TEXT"), ("tags", "TEXT"), ("created_by", "TEXT"),
                           ("duration", "REAL"), ("actors_n", "INTEGER")],
}


_REPLACE_TABLES = {   # table -> (columns, primary-key columns) for INSERT OR REPLACE -> ON CONFLICT DO UPDATE
    "settings_kv": (["key", "value"], ["key"]),
    "api_settings": (["user_id", "provider", "encrypted_key", "model", "temperature", "enabled", "updated"], ["user_id"]),
    "model_versions": (["version", "trained_at", "status", "metrics"], ["version"]),
    "blocked_entities": (["entity_type", "entity_id", "reason", "score", "ts", "active", "blocked_by", "fraud_clicks", "reason_detail"],
                         ["entity_type", "entity_id"]),
}
_RETURNING_ID = ("fraud_alerts", "attack_simulations", "recommendations", "incidents", "patterns", "pattern_hits")


def to_pg(sql: str) -> str:
    """Translate the SQLite-flavoured statements used by Store to PostgreSQL."""
    t = sql.strip()
    m = re.match(r"(?is)INSERT OR REPLACE INTO (\w+)\s*(?:\((.*?)\))?\s*VALUES\((.*)\)$", t)
    if m:
        table, listed, vals = m.group(1), m.group(2), m.group(3)
        cols, pk = _REPLACE_TABLES[table]
        cols = [c.strip() for c in listed.split(",")] if listed else list(cols)
        sets = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in pk)
        t = f"INSERT INTO {table}({', '.join(cols)}) VALUES({vals}) ON CONFLICT ({', '.join(pk)}) DO UPDATE SET {sets}"
    elif re.match(r"(?is)INSERT OR IGNORE INTO", t):
        t = re.sub(r"(?is)INSERT OR IGNORE INTO", "INSERT INTO", t, count=1) + " ON CONFLICT DO NOTHING"
    t = t.replace("%", "%%").replace("?", "%s")
    m = re.match(r"(?is)INSERT INTO (\w+)", t)
    if m and m.group(1) in _RETURNING_ID and "RETURNING" not in t.upper():
        t += " RETURNING id"
    return t


def pg_schema(schema: str) -> list[str]:
    s = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("id INTEGER PRIMARY KEY,", "id BIGSERIAL PRIMARY KEY,")
    s = re.sub(r"\bREAL\b", "DOUBLE PRECISION", s)
    return [x.strip() for x in s.split(";") if x.strip()]


class _PgCursor:
    def __init__(self, cur: Any, returning: bool):
        self._cur, self.rowcount = cur, cur.rowcount
        self.lastrowid = None
        if returning:
            row = cur.fetchone()
            self.lastrowid = row["id"] if row else None

    def fetchall(self) -> list[dict]:
        return self._cur.fetchall() if self._cur.description else []

    def fetchone(self) -> dict | None:
        return self._cur.fetchone() if self._cur.description else None


class _PgConn:
    """sqlite3-like facade over psycopg so Store runs unchanged on PostgreSQL."""

    def __init__(self, dsn: str):
        import psycopg
        from psycopg.rows import dict_row
        self.conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5)

    def execute(self, sql: str, args: Iterable = ()) -> _PgCursor:
        q = to_pg(sql)
        try:
            cur = self.conn.execute(q, tuple(args))
        except Exception:
            self.conn.rollback()
            raise
        return _PgCursor(cur, q.endswith("RETURNING id"))

    def executemany(self, sql: str, seq: Iterable) -> None:
        try:
            with self.conn.cursor() as cur:
                cur.executemany(to_pg(sql), [tuple(x) for x in seq])
        except Exception:
            self.conn.rollback()
            raise

    def executescript(self, schema: str) -> None:
        for stmt in pg_schema(schema):
            self.conn.execute(stmt)
        self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.dialect = "postgres" if self.path.startswith(("postgres://", "postgresql://")) else "sqlite"
        self.lock = threading.RLock()
        if self.dialect == "postgres":
            self.conn = _PgConn(self.path)
            with self.lock:
                self.conn.executescript(SCHEMA)
        else:
            if self.path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            with self.lock:
                if self.path != ":memory:":
                    self.conn.execute("PRAGMA journal_mode=WAL")
                    self.conn.execute("PRAGMA synchronous=NORMAL")
                self.conn.executescript(SCHEMA)
                self.conn.commit()
        self._migrate()
        self.errors = 0

    # ------------------------------------------------------------------ helpers
    def _table_columns(self, table: str) -> set[str]:
        """Existing column names for `table`, for either dialect."""
        if self.dialect == "postgres":
            rows = self._all("SELECT column_name AS name FROM information_schema.columns WHERE table_name = ?", (table,))
        else:
            rows = self._all(f"PRAGMA table_info({table})")
        return {str(r["name"]) for r in rows}

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created. Safe to run on every open."""
        added: list[str] = []
        with self.lock:
            for table, cols in NEW_COLUMNS.items():
                have = self._table_columns(table)
                if not have:
                    continue
                for name, decl in cols:
                    if name not in have:
                        self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                        added.append(f"{table}.{name}")
            self.conn.commit()
        self.migrations_applied = added

    def _exec(self, sql: str, args: Iterable = ()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.conn.execute(sql, tuple(args))
            self.conn.commit()
            return cur

    def _all(self, sql: str, args: Iterable = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(args)).fetchall()]

    def _one(self, sql: str, args: Iterable = ()) -> dict | None:
        rows = self._all(sql, args)
        return rows[0] if rows else None

    def ping(self) -> bool:
        try:
            self._one("SELECT 1")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ users / settings
    def add_user(self, email: str, role: str, password_hash: str) -> None:
        self._exec("INSERT OR IGNORE INTO users(email,role,password_hash,created) VALUES(?,?,?,?)",
                   (email, role, password_hash, time.time()))

    def get_user(self, email: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE email=?", (email,))

    def set_ai_settings(self, user_id: int, provider: str, encrypted_key: str | None, model: str,
                        temperature: float, enabled: bool) -> None:
        old = self._one("SELECT encrypted_key FROM api_settings WHERE user_id=?", (user_id,))
        key = encrypted_key if encrypted_key is not None else (old or {}).get("encrypted_key")
        self._exec("INSERT OR REPLACE INTO api_settings VALUES(?,?,?,?,?,?,?)",
                   (user_id, provider, key, model, temperature, int(enabled), time.time()))

    def get_ai_settings(self, user_id: int) -> dict | None:
        return self._one("SELECT * FROM api_settings WHERE user_id=?", (user_id,))

    # ------------------------------------------------------------------ events & predictions
    def save_batch(self, rows: list[tuple[dict, dict]]) -> None:
        """rows: [(event_dict, decision_dict)] written atomically."""
        if not rows:
            return
        try:
            with self.lock:
                self.conn.executemany("INSERT OR IGNORE INTO campaigns VALUES(?,?)", {(e["campaign_id"], e["timestamp"]) for e, _ in rows})
                self.conn.executemany("INSERT OR IGNORE INTO advertisements VALUES(?,?,?)", {(e["ad_id"], e["campaign_id"], e["timestamp"]) for e, _ in rows})
                self.conn.executemany(
                    "INSERT INTO devices VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen",
                    {(e["device_id"], e["user_id"], e["user_agent"][:120], e["country"], e["timestamp"], e["timestamp"]) for e, _ in rows})
                self.conn.executemany(
                    "INSERT OR IGNORE INTO click_events(event_id,ts,user_id,ad_id,campaign_id,publisher_id,device_id,ip_hash,"
                    "ip_mask,country,label,attack_type,source,run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(e["event_id"], e["timestamp"], e["user_id"], e["ad_id"], e["campaign_id"], e["publisher_id"],
                      e["device_id"], e["ip_hash"], d["ip_mask"], e["country"], e.get("label"), e.get("attack_type"),
                      e.get("source") or "live", e.get("run_id"))
                     for e, d in rows])
                self.conn.executemany(
                    "INSERT OR IGNORE INTO fraud_predictions(event_id,ts,user_id,risk,level,action,confidence,scores,rules,"
                    "model_version,latency_ms,factors,features,classification,classification_source,reason,reason_title) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(d["event_id"], d["timestamp"], d["user_id"], d["risk"], d["level"], d["action"], d["confidence"],
                      json.dumps(d["scores"]), json.dumps(d["rules_fired"]), d["model_version"], d["latency_ms"],
                      json.dumps(d["top_factors"]) if d["top_factors"] else None,
                      json.dumps(d.get("features")) if d.get("features") else None,
                      d.get("classification"), d.get("classification_source"),
                      d.get("reason"), d.get("reason_title")) for _, d in rows])
                self.conn.commit()
        except Exception:
            self.errors += 1
            raise

    def user_events(self, user_id: str, limit: int = 100) -> list[dict]:
        return self._all(
            "SELECT p.event_id, p.ts, p.risk, p.level, p.action, p.reason, p.reason_title, e.ad_id, e.campaign_id, e.country, e.ip_mask, e.device_id "
            "FROM fraud_predictions p JOIN click_events e USING(event_id) WHERE p.user_id=? ORDER BY p.ts DESC LIMIT ?",
            (user_id, limit))

    def get_prediction(self, event_id: str) -> dict | None:
        r = self._one("SELECT p.*, e.ad_id, e.campaign_id, e.device_id, e.ip_mask, e.country, e.label, e.attack_type "
                      "FROM fraud_predictions p JOIN click_events e USING(event_id) WHERE p.event_id=?", (event_id,))
        if r:
            for k in ("scores", "rules", "factors"):
                r[k] = json.loads(r[k]) if r.get(k) else None
        return r

    def recent_predictions(self, limit: int = 100, min_risk: float = 0.0) -> list[dict]:
        return self._all("SELECT * FROM fraud_predictions WHERE risk>=? ORDER BY ts DESC LIMIT ?", (min_risk, limit))

    def top_risk_users(self, limit: int = 10) -> list[dict]:
        return self._all("SELECT user_id, MAX(risk) AS max_risk, AVG(risk) AS avg_risk, COUNT(*) AS clicks, "
                         "SUM(CASE WHEN action IN ('FLAG','BLOCK') THEN 1 ELSE 0 END) AS flagged FROM fraud_predictions GROUP BY user_id "
                         "ORDER BY max_risk DESC, flagged DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------ alerts
    def add_alert(self, severity: str, title: str, user_id: str | None, campaign_id: str | None, details: dict) -> int:
        cur = self._exec("INSERT INTO fraud_alerts(ts,severity,title,user_id,campaign_id,details) VALUES(?,?,?,?,?,?)",
                         (time.time(), severity, title, user_id, campaign_id, json.dumps(details)))
        return int(cur.lastrowid)

    def list_alerts(self, status: str | None = None, limit: int = 100) -> list[dict]:
        q, a = "SELECT * FROM fraud_alerts", []
        if status:
            q += " WHERE status=?"
            a.append(status)
        rows = self._all(q + " ORDER BY id DESC LIMIT ?", (*a, limit))
        for r in rows:
            r["details"] = json.loads(r["details"]) if r["details"] else {}
        return rows

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        return self._exec("UPDATE fraud_alerts SET status=? WHERE id=?", (status, alert_id)).rowcount > 0

    # ------------------------------------------------------------------ blocklist
    def block(self, entity_type: str, entity_id: str, reason: str, score: float, by: str = "engine",
              fraud_clicks: int = 0, reason_detail: dict | None = None) -> None:
        self._exec("INSERT OR REPLACE INTO blocked_entities(entity_type,entity_id,reason,score,ts,active,blocked_by,"
                   "fraud_clicks,reason_detail) VALUES(?,?,?,?,?,1,?,?,?)",
                   (entity_type, entity_id, reason, score, time.time(), by, fraud_clicks,
                    json.dumps(reason_detail) if reason_detail else None))

    def unblock(self, entity_type: str, entity_id: str) -> bool:
        return self._exec("UPDATE blocked_entities SET active=0 WHERE entity_type=? AND entity_id=?",
                          (entity_type, entity_id)).rowcount > 0

    def list_blocked(self, active_only: bool = True, limit: int = 500) -> list[dict]:
        q = "SELECT * FROM blocked_entities" + (" WHERE active=1" if active_only else "") + " ORDER BY ts DESC LIMIT ?"
        rows = self._all(q, (limit,))
        for r in rows:
            r["reason_detail"] = json.loads(r["reason_detail"]) if r.get("reason_detail") else None
        return rows

    # ------------------------------------------------------------------ incidents
    def add_incident(self, first_seen: float, last_seen: float, classification: str | None, confidence: float,
                     run_id: str | None = None) -> int:
        cur = self._exec("INSERT INTO incidents(first_seen,last_seen,status,classification,confidence,campaigns,run_id) "
                         "VALUES(?,?,'open',?,?,'',?)", (first_seen, last_seen, classification, confidence, run_id))
        return int(cur.lastrowid)

    def add_incident_entity(self, incident_id: int, entity_type: str, entity_id: str, ts: float, flagged: int,
                            peak_risk: float, blocked: int) -> None:
        with self.lock:
            old = self.conn.execute(
                "SELECT first_seen, last_seen, events, flagged, peak_risk, blocked FROM incident_entities "
                "WHERE incident_id=? AND entity_type=? AND entity_id=?", (incident_id, entity_type, entity_id)
            ).fetchone()
            if old:
                row = (min(old["first_seen"], ts), max(old["last_seen"], ts), old["events"] + 1,
                       old["flagged"] + flagged, max(old["peak_risk"] or 0.0, peak_risk), old["blocked"] + blocked)
                self.conn.execute(
                    "UPDATE incident_entities SET first_seen=?, last_seen=?, events=?, flagged=?, peak_risk=?, blocked=? "
                    "WHERE incident_id=? AND entity_type=? AND entity_id=?", (*row, incident_id, entity_type, entity_id))
            else:
                self.conn.execute(
                    "INSERT INTO incident_entities(incident_id,entity_type,entity_id,first_seen,last_seen,events,"
                    "flagged,peak_risk,blocked) VALUES(?,?,?,?,?,1,?,?,?)",
                    (incident_id, entity_type, entity_id, ts, ts, flagged, peak_risk, blocked))
            self.conn.commit()

    def incident_entities(self, incident_id: int) -> list[dict]:
        return self._all("SELECT * FROM incident_entities WHERE incident_id=? ORDER BY flagged DESC, events DESC",
                         (incident_id,))

    def add_incident_campaign(self, incident_id: int, campaign_id: str | None) -> None:
        """Keep the denormalised campaign list on the incident row (comma separated, sorted)."""
        if not campaign_id:
            return
        row = self._one("SELECT campaigns FROM incidents WHERE id=?", (incident_id,)) or {}
        camps = sorted({c for c in (row.get("campaigns") or "").split(",") if c} | {campaign_id})
        self._exec("UPDATE incidents SET campaigns=? WHERE id=?", (",".join(camps), incident_id))

    def incident_event_ids(self, incident_id: int, limit: int = 200) -> list[str]:
        rows = self._all(
            "SELECT p.event_id FROM fraud_predictions p JOIN incident_entities e ON e.entity_id=p.user_id "
            "AND e.entity_type='user' WHERE e.incident_id=? AND p.level IN ('HIGH','CRITICAL') "
            "ORDER BY p.ts DESC LIMIT ?", (incident_id, limit))
        return [r["event_id"] for r in rows]

    def _incident_row(self, r: dict) -> dict:
        r["campaigns"] = [c for c in (r.get("campaigns") or "").split(",") if c]
        return r

    CLOSE_AFTER_S = 300.0

    def list_incidents(self, limit: int = 100, status: str | None = None, run_id: str | None = None,
                       now: float | None = None) -> list[dict]:
        # An incident counts as closed once it has been idle past the window, even if no sweeper has
        # rewritten the row yet, so the filter has to use the same rule as _with_live_status.
        t = now if now is not None else time.time()
        idle_before = t - self.CLOSE_AFTER_S
        live = "(status='open' AND last_seen>=?)"
        dead = "(status='closed' OR (status='open' AND last_seen<?))"
        q, a = "SELECT * FROM incidents WHERE 1=1", []
        if status == "open":
            q += " AND " + live
            a.append(idle_before)
        elif status == "closed":
            q += " AND " + dead
            a.append(idle_before)
        if run_id:
            q += " AND run_id=?"
            a.append(run_id)
        rows = [self._incident_row(r) for r in self._all(q + " ORDER BY last_seen DESC LIMIT ?", (*a, limit))]
        return [self._with_live_status(r, t) for r in rows]

    def _with_live_status(self, r: dict, now: float | None = None) -> dict:
        """An incident with no new activity inside the window reads as closed, without a background job."""
        t = now if now is not None else time.time()
        if r.get("status") == "open" and t - (r.get("last_seen") or 0) > self.CLOSE_AFTER_S:
            r["status"] = "closed"
            r["idle_s"] = round(t - (r.get("last_seen") or 0), 1)
        return r

    def get_incident(self, incident_id: int) -> dict | None:
        r = self._one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not r:
            return None
        r = self._with_live_status(self._incident_row(r))
        r["entities"] = self.incident_entities(incident_id)
        r["event_ids"] = self.incident_event_ids(incident_id)
        r["alerts"] = [dict(a, details=json.loads(a["details"]) if a.get("details") else {})
                       for a in self._all("SELECT * FROM fraud_alerts WHERE incident_id=? ORDER BY ts", (incident_id,))]
        return r

    def candidate_incidents(self, since: float) -> list[dict]:
        """Open incidents that are still inside the merge window."""
        return [self._incident_row(r) for r in self._all(
            "SELECT * FROM incidents WHERE status='open' AND last_seen>=? ORDER BY last_seen DESC", (since,))]

    def update_incident(self, incident_id: int, last_seen: float, status: str | None = None,
                        peak_risk: float | None = None, run_id: str | None = None,
                        summary: str | None = None) -> None:
        sets, args = ["last_seen=?"], [last_seen]
        if status:
            sets.append("status=?")
            args.append(status)
        if summary:
            sets.append("summary=?"), args.append(summary[:400])
        if peak_risk is not None:
            # Keep the worst score seen; compare in Python so the SQL stays portable.
            old = self._one("SELECT peak_risk FROM incidents WHERE id=?", (incident_id,)) or {}
            sets.append("peak_risk=?"), args.append(max(old.get("peak_risk") or 0.0, peak_risk))
        if run_id:
            sets.append("run_id=?"), args.append(run_id)
        self._exec(f"UPDATE incidents SET {', '.join(sets)} WHERE id=?", (*args, incident_id))

    def refresh_incident_counts(self, incident_id: int) -> None:
        """Recompute the denormalised counters and campaign list from incident_entities."""
        self._exec(
            "UPDATE incidents SET "
            "users_n=(SELECT COUNT(*) FROM incident_entities e WHERE e.incident_id=incidents.id AND e.entity_type='user'), "
            "devices_n=(SELECT COUNT(*) FROM incident_entities e WHERE e.incident_id=incidents.id AND e.entity_type='device'), "
            "ips_n=(SELECT COUNT(*) FROM incident_entities e WHERE e.incident_id=incidents.id AND e.entity_type='ip'), "
            "events_n=(SELECT COALESCE(SUM(e.events),0) FROM incident_entities e WHERE e.incident_id=incidents.id), "
            "flagged_n=(SELECT COALESCE(SUM(e.flagged),0) FROM incident_entities e WHERE e.incident_id=incidents.id), "
            "blocked_n=(SELECT COALESCE(SUM(e.blocked),0) FROM incident_entities e WHERE e.incident_id=incidents.id), "
            "peak_risk=COALESCE((SELECT MAX(e.peak_risk) FROM incident_entities e WHERE e.incident_id=incidents.id),0) "
            "WHERE id=?", (incident_id,))

    def set_alert_incident(self, alert_id: int, incident_id: int | None) -> None:
        self._exec("UPDATE fraud_alerts SET incident_id=? WHERE id=?", (incident_id, alert_id))

    # ------------------------------------------------------------------ patterns
    PATTERN_COLS = "id, name, description, action, signature, examples_n, created_by, created, updated, hits, enabled, last_seen"

    def _pattern_row(self, r: dict) -> dict:
        r["signature"] = json.loads(r["signature"]) if r.get("signature") else {}
        r["enabled"] = bool(r["enabled"])
        return r

    def list_patterns(self, enabled_only: bool = False) -> list[dict]:
        q = "SELECT * FROM patterns" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY name"
        return [self._pattern_row(r) for r in self._all(q)]

    def get_pattern(self, pattern_id: int) -> dict | None:
        r = self._one("SELECT * FROM patterns WHERE id=?", (pattern_id,))
        return self._pattern_row(r) if r else None

    def add_pattern(self, name: str, description: str, action: str, signature: dict, created_by: str,
                    examples_n: int = 0) -> int:
        now = time.time()
        cur = self._exec("INSERT INTO patterns(name,description,action,signature,examples_n,created_by,created,updated,"
                         "enabled) VALUES(?,?,?,?,?,?,?,?,1)",
                         (name, description, action, json.dumps(signature), examples_n, created_by, now, now))
        return int(cur.lastrowid)

    def update_pattern(self, pattern_id: int, name: str, description: str, action: str, signature: dict,
                       enabled: bool = True, examples_n: int | None = None) -> bool:
        sets, args = ["name=?", "description=?", "action=?", "signature=?", "enabled=?", "updated=?"], \
                     [name, description, action, json.dumps(signature), int(enabled), time.time()]
        if examples_n is not None:
            sets.append("examples_n=?")
            args.append(examples_n)
        return self._exec(f"UPDATE patterns SET {', '.join(sets)} WHERE id=?", (*args, pattern_id)).rowcount > 0

    def delete_pattern(self, pattern_id: int) -> bool:
        with self.lock:
            self.conn.execute("DELETE FROM pattern_hits WHERE pattern_id=?", (pattern_id,))
            cur = self.conn.execute("DELETE FROM patterns WHERE id=?", (pattern_id,))
            self.conn.commit()
            return cur.rowcount > 0

    def add_pattern_hit(self, pattern_id: int, ts: float, event_id: str, user_id: str,
                        incident_id: int | None = None) -> None:
        with self.lock:
            self.conn.execute("INSERT INTO pattern_hits(pattern_id,ts,event_id,user_id,incident_id) VALUES(?,?,?,?,?)",
                              (pattern_id, ts, event_id, user_id, incident_id))
            self.conn.execute("UPDATE patterns SET hits=hits+1, last_seen=? WHERE id=?", (ts, pattern_id))
            self.conn.commit()

    def pattern_hits(self, pattern_id: int, limit: int = 50) -> list[dict]:
        return self._all("SELECT * FROM pattern_hits WHERE pattern_id=? ORDER BY ts DESC LIMIT ?", (pattern_id, limit))

    def pattern_hit_counts(self, since: float = 0.0) -> dict[str, int]:
        return {str(r["pattern_id"]): int(r["n"]) for r in self._all(
            "SELECT pattern_id, COUNT(*) n FROM pattern_hits WHERE ts>=? GROUP BY pattern_id", (since,))}

    def patterns_matching(self, event_id: str) -> list[dict]:
        return self._all("SELECT p.* FROM patterns p JOIN pattern_hits h ON h.pattern_id = p.id "
                         "WHERE h.event_id=? ORDER BY p.name", (event_id,))

    # ------------------------------------------------------------------ misc tables
    def add_simulation(self, kind: str, params: dict, events: list[dict]) -> int:
        cur = self._exec("INSERT INTO attack_simulations(ts,kind,params,events,events_json) VALUES(?,?,?,?,?)",
                         (time.time(), kind, json.dumps(params), len(events), json.dumps(events)))
        return int(cur.lastrowid)

    def list_simulations(self, limit: int = 50) -> list[dict]:
        return self._all("SELECT id, ts, kind, params, events FROM attack_simulations ORDER BY id DESC LIMIT ?", (limit,))

    def get_simulation(self, sim_id: int) -> dict | None:
        row = dict(self._one("SELECT * FROM attack_simulations WHERE id=?", (sim_id,)) or {})
        if not row:
            return None
        row["params"] = json.loads(row.get("params") or "{}")
        return row

    def get_simulation_events(self, sim_id: int) -> list[dict] | None:
        r = self._one("SELECT events_json FROM attack_simulations WHERE id=?", (sim_id,))
        return json.loads(r["events_json"]) if r else None

    def add_recommendation(self, user_id: str, summary: str, attack_type: str, confidence: float, action: str,
                           source: str, details: dict) -> int:
        cur = self._exec("INSERT INTO recommendations(ts,user_id,summary,attack_type,confidence,action,source,details) "
                         "VALUES(?,?,?,?,?,?,?,?)", (time.time(), user_id, summary, attack_type, confidence, action,
                                                     source, json.dumps(details)))
        return int(cur.lastrowid)

    def list_recommendations(self, status: str | None = None, limit: int = 50) -> list[dict]:
        q, a = "SELECT * FROM recommendations", []
        if status:
            q += " WHERE status=?"
            a.append(status)
        rows = self._all(q + " ORDER BY id DESC LIMIT ?", (*a, limit))
        for r in rows:
            r["details"] = json.loads(r["details"]) if r["details"] else {}
        return rows

    def get_recommendation(self, rec_id: int) -> dict | None:
        return self._one("SELECT * FROM recommendations WHERE id=?", (rec_id,))

    def set_recommendation_status(self, rec_id: int, status: str) -> None:
        self._exec("UPDATE recommendations SET status=? WHERE id=?", (status, rec_id))

    def get_kv(self, key: str) -> Any:
        r = self._one("SELECT value FROM settings_kv WHERE key=?", (key,))
        return json.loads(r["value"]) if r else None

    def set_kv(self, key: str, value: Any) -> None:
        self._exec("INSERT OR REPLACE INTO settings_kv VALUES(?,?)", (key, json.dumps(value)))

    # ------------------------------------------------------------------ Step 6/7: analysis + saved attacks
    def search_everything(self, q: str, limit: int = 20) -> dict:
        """One search box over users, campaigns, adverts, devices, incidents and alerts.

        Everything is derived from the event and prediction tables, which are the only records that
        carry the dimensions an analyst searches by.
        """
        like = f"%{q}%"
        rows = lambda sql, *a: [dict(r) for r in self._all(sql, a)]  # noqa: E731 - local shorthand
        return {
            "users": rows("SELECT user_id, COUNT(*) clicks, MAX(ts) last_seen, MAX(country) country "
                          "FROM click_events WHERE user_id LIKE ? GROUP BY user_id "
                          "ORDER BY clicks DESC LIMIT ?", like, limit),
            "campaigns": rows("SELECT campaign_id, COUNT(*) clicks, MAX(ts) last_seen FROM click_events "
                              "WHERE campaign_id LIKE ? GROUP BY campaign_id ORDER BY clicks DESC LIMIT ?",
                              like, limit),
            "ads": rows("SELECT ad_id, COUNT(*) clicks, MAX(ts) last_seen FROM click_events "
                        "WHERE ad_id LIKE ? GROUP BY ad_id ORDER BY clicks DESC LIMIT ?", like, limit),
            "devices": rows("SELECT device_id, COUNT(*) clicks, COUNT(DISTINCT user_id) users FROM click_events "
                            "WHERE device_id LIKE ? GROUP BY device_id ORDER BY clicks DESC LIMIT ?",
                            like, limit),
            "incidents": rows("SELECT id, classification, status, last_seen FROM incidents "
                              "WHERE classification LIKE ? ORDER BY last_seen DESC LIMIT ?", like, limit),
            "alerts": rows("SELECT id, user_id, severity, title, ts FROM fraud_alerts "
                           "WHERE user_id LIKE ? OR title LIKE ? ORDER BY ts DESC LIMIT ?", like, like, limit),
        }

    def combined_attacks(self, since: float = 0.0, min_risk: float = 0.0, limit: int = 40) -> dict:
        """Combine signals across layers: what is the worst of each kind, and what keeps recurring.

        Each cluster groups suspicious decisions by the strongest shared attribute (campaign, advert,
        device or network), so one row answers "which advert is behind all of this".
        """
        where, args = "f.risk>=?", (min_risk,)
        if since:
            where += " AND f.ts>=?"
            args = args + (since,)
        key = ("COALESCE(NULLIF(e.campaign_id,''), NULLIF(e.ad_id,''), NULLIF(e.device_id,''), 'unattributed')")
        clusters = [dict(r) for r in self._all(
            f"SELECT {key} k, COUNT(*) events, COUNT(DISTINCT f.user_id) users, "
            "COUNT(DISTINCT e.device_id) devices, COUNT(DISTINCT e.ip_mask) ips, "
            "ROUND(MAX(f.risk),3) peak_risk, ROUND(AVG(f.risk),3) avg_risk, "
            "SUM(CASE WHEN f.classification='critical' THEN 1 ELSE 0 END) criticals "
            f"FROM fraud_predictions f JOIN click_events e ON e.event_id=f.event_id WHERE {where} "
            "GROUP BY k HAVING events>=2 ORDER BY peak_risk DESC, events DESC LIMIT ?", (*args, limit))]
        kinds = {
            "incidents": [dict(r) for r in self._all(
                "SELECT status, COUNT(*) n FROM incidents GROUP BY status")],
            "alerts": [dict(r) for r in self._all(
                "SELECT severity, COUNT(*) n FROM fraud_alerts WHERE status='open' GROUP BY severity")],
            "blocked": [dict(r) for r in self._all(
                "SELECT entity_type, COUNT(*) n FROM blocked_entities WHERE active=1 GROUP BY entity_type")],
            "classifications": [dict(r) for r in self._all(
                "SELECT COALESCE(classification,'unclassified') k, COUNT(*) n FROM fraud_predictions "
                "WHERE risk>=? GROUP BY k ORDER BY n DESC", (min_risk,))],
            "totals": dict(self._one(
                "SELECT COUNT(*) decisions, COUNT(DISTINCT user_id) users, "
                "ROUND(MAX(risk),3) peak_risk, ROUND(AVG(risk),3) avg_risk "
                "FROM fraud_predictions WHERE risk>=?", (min_risk,)) or {}),
        }
        timeline = [dict(r) for r in self._all(
            "SELECT ts/300 bucket, COUNT(*) n, ROUND(MAX(risk),3) peak_risk FROM fraud_predictions "
            "WHERE risk>=? GROUP BY bucket ORDER BY bucket", (min_risk,))][-48:]
        return {"clusters": clusters, "kinds": kinds, "timeline": timeline,
                "worst": max([c["peak_risk"] or 0 for c in clusters] or [0.0])}

    def targeted_analysis(self, since: float = 0.0, limit: int = 40) -> dict:
        """Who is being targeted, by whom, and how much of it is going wrong."""
        s = " AND e.ts>=?" if since else ""
        a = (since,) if since else ()
        campaigns = [dict(r) for r in self._all(
            "SELECT e.campaign_id, COUNT(*) clicks, COUNT(DISTINCT e.user_id) users, "
            "ROUND(MAX(f.risk),3) peak_risk, "
            "SUM(CASE WHEN f.classification='critical' THEN 1 ELSE 0 END) criticals "
            "FROM click_events e JOIN fraud_predictions f ON f.event_id=e.event_id WHERE 1=1" + s +
            " GROUP BY e.campaign_id ORDER BY criticals DESC, clicks DESC LIMIT ?", (*a, limit))]
        victims = [dict(r) for r in self._all(
            "SELECT f.user_id, MAX(e.country) country, COUNT(*) clicks, ROUND(MAX(f.risk),3) peak_risk, "
            "COUNT(DISTINCT e.campaign_id) campaigns, COUNT(DISTINCT e.device_id) devices "
            "FROM fraud_predictions f JOIN click_events e ON e.event_id=f.event_id WHERE f.risk>=0.4" + s +
            " GROUP BY f.user_id ORDER BY peak_risk DESC, clicks DESC LIMIT ?", (*a, limit))]
        clean = [dict(r) for r in self._all(
            "SELECT e.campaign_id, COUNT(*) clicks, COUNT(DISTINCT e.user_id) users "
            "FROM click_events e JOIN fraud_predictions f ON f.event_id=e.event_id "
            "WHERE f.risk<0.4" + s + " GROUP BY e.campaign_id ORDER BY clicks DESC LIMIT ?", (*a, limit))]
        wasted = [c for c in campaigns if (c["criticals"] or 0) > 0]
        return {"campaigns": campaigns, "victims": victims, "clean": clean,
                "wasted_clicks": sum(c["clicks"] or 0 for c in wasted),
                "at_risk_users": len(victims)}

    def log_events(self, level: str | None = None, user_id: str | None = None, campaign_id: str | None = None,
                   source: str | None = None, run_id: str | None = None, q: str | None = None,
                   since: float = 0.0, limit: int = 100, before: float | None = None) -> list[dict]:
        """Event Log: every decision, filterable, newest first."""
        w, a = ["1=1"], []
        if level:
            w.append("f.level=?")
            a.append(level)
        if user_id:
            w.append("f.user_id=?")
            a.append(user_id)
        if campaign_id:
            w.append("e.campaign_id=?")
            a.append(campaign_id)
        if source:
            w.append("e.source=?")
            a.append(source)
        if run_id:
            w.append("e.run_id=?")
            a.append(run_id)
        if since:
            w.append("f.ts>=?")
            a.append(since)
        if before:
            w.append("f.ts<?")
            a.append(before)
        if q:
            w.append("(e.ad_id LIKE ? OR e.device_id LIKE ? OR f.reason_title LIKE ? OR f.user_id LIKE ?)")
            like = f"%{q}%"
            a += [like, like, like, like]
        return [dict(r) for r in self._all(
            "SELECT f.*, e.campaign_id, e.ad_id, e.device_id, e.ip_mask, e.source, e.run_id, e.label "
            "FROM fraud_predictions f JOIN click_events e ON e.event_id=f.event_id "
            f"WHERE {' AND '.join(w)} ORDER BY f.ts DESC LIMIT ?", (*a, min(int(limit), 1000)))]

    def save_simulation(self, sim_id: int, name: str, notes: str = "", tags: str | None = None,
                        created_by: str = "analyst", duration: float | None = None,
                        actors_n: int | None = None) -> bool:
        return bool(self._exec(
            "UPDATE attack_simulations SET name=?, notes=?, tags=?, created_by=?, duration=?, actors_n=? "
            "WHERE id=?", (name, notes, tags, created_by, duration, actors_n, sim_id)).rowcount)

    def delete_simulation(self, sim_id: int) -> bool:
        return bool(self._exec("DELETE FROM attack_simulations WHERE id=?", (sim_id,)).rowcount)

    def named_simulations(self, saved_only: bool = True, limit: int = 100) -> list[dict]:
        q = "SELECT * FROM attack_simulations WHERE name IS NOT NULL AND name<>''"
        if saved_only:
            q += " ORDER BY ts DESC"
        else:
            q += " OR name IS NULL OR name='' ORDER BY ts DESC"
        return [dict(r) for r in self._all(q + " LIMIT ?", (limit,))]

    def compare_simulations(self, a_id: int, b_id: int) -> dict:
        """Side-by-side level counts for two stored scenarios, matched on their event ids."""
        def stats(sim_id: int) -> dict:
            meta = dict(self._one("SELECT id, kind, name, duration, actors_n, events "
                                  "FROM attack_simulations WHERE id=?", (sim_id,)) or {})
            events = self.get_simulation_events(sim_id) or []
            ids = [str(e.get("event_id")) for e in events if e.get("event_id")]
            counts, peak = {}, 0.0
            if ids:
                q = ",".join("?" * len(ids))
                for r in self._all(f"SELECT level, COUNT(*) n, MAX(risk) peak FROM fraud_predictions "
                                   f"WHERE event_id IN ({q}) GROUP BY level", ids):
                    counts[r["level"]] = r["n"]
                    peak = max(peak, float(r["peak"] or 0))
            meta.update({"decisions": sum(counts.values()), "counts": counts, "peak_risk": peak,
                         "users": len({e.get("user_id") for e in events if e.get("user_id")})})
            return meta

        return {"a": stats(a_id), "b": stats(b_id)}

    def system_event(self, kind: str, message: str) -> None:
        self._exec("INSERT INTO system_events(ts,kind,message) VALUES(?,?,?)", (time.time(), kind, message))

    def system_events(self, limit: int = 50) -> list[dict]:
        return self._all("SELECT * FROM system_events ORDER BY id DESC LIMIT ?", (limit,))

    def audit(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        self._exec("INSERT INTO audit_log(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
                   (time.time(), actor, action, target, detail))

    def audit_log(self, limit: int = 100) -> list[dict]:
        return self._all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    def upsert_model_version(self, version: str, trained_at: float, status: str, metrics: dict) -> None:
        self._exec("INSERT OR REPLACE INTO model_versions VALUES(?,?,?,?)", (version, trained_at, status, json.dumps(metrics)))

    def model_versions(self) -> list[dict]:
        rows = self._all("SELECT * FROM model_versions ORDER BY trained_at DESC")
        for r in rows:
            r["metrics"] = json.loads(r["metrics"])
        return rows

    # ------------------------------------------------------------------ analytics
    def analytics(self, since: float = 0.0, campaign: str | None = None, country: str | None = None,
                  min_level: str | None = None) -> dict[str, Any]:
        where, args = ["p.ts>=?"], [since]
        if campaign:
            where.append("e.campaign_id=?"), args.append(campaign)
        if country:
            where.append("e.country=?"), args.append(country)
        if min_level:
            order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            lv = [k for k, v in order.items() if v >= order[min_level]]
            where.append(f"p.level IN ({','.join('?' * len(lv))})"), args.extend(lv)
        w = " AND ".join(where)
        base = f"FROM fraud_predictions p JOIN click_events e USING(event_id) WHERE {w}"
        flagged = FLAG_SUM
        tot = self._one(f"SELECT COUNT(*) n, COALESCE({flagged},0) flagged, AVG(p.latency_ms) lat {base}", args) or {}
        return {
            "totals": tot,
            "by_campaign": self._all(f"SELECT e.campaign_id k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1 ORDER BY flagged DESC", args),
            "by_country": self._all(f"SELECT e.country k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1 ORDER BY flagged DESC", args),
            "by_level": self._all(f"SELECT p.level k, COUNT(*) n {base} GROUP BY 1", args),
            "by_hour": self._all(f"SELECT CAST(p.ts/3600 AS INT)*3600 k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1 ORDER BY 1", args),
            "by_attack_ground_truth": self._all(f"SELECT COALESCE(e.attack_type,'unknown') k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1", args),
            "top_ips": self._all(f"SELECT e.ip_mask k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1 ORDER BY flagged DESC LIMIT 10", args),
            "top_devices": self._all(f"SELECT e.device_id k, COUNT(*) n, {flagged} flagged {base} GROUP BY 1 ORDER BY flagged DESC LIMIT 10", args),
        }

    # ------------------------------------------------------------------ timeline / devices / campaigns
    TIMELINE = {"1m": (60, 5), "5m": (300, 15), "1h": (3600, 60), "24h": (86400, 900)}   # window s, bucket s

    def timeline(self, window: str = "5m", now: float | None = None) -> dict:
        span, bucket = self.TIMELINE.get(window, self.TIMELINE["5m"])
        now = now or time.time()
        rows = self._all(
            f"SELECT CAST(p.ts / ? AS BIGINT) * ? AS t, COUNT(*) AS n, {FLAG_SUM} AS flagged, "
            "SUM(CASE WHEN p.action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked, AVG(p.risk) AS avg_risk, MAX(p.risk) AS max_risk "
            "FROM fraud_predictions p WHERE p.ts >= ? GROUP BY 1 ORDER BY 1", (bucket, bucket, now - span))
        return {"window": window, "bucket_s": bucket, "points": rows}

    def device_types(self, since: float = 0.0) -> list[dict]:
        return self._all(
            f"SELECT {DEVICE_TYPE_SQL} AS k, COUNT(*) AS n, {FLAG_SUM} AS flagged FROM fraud_predictions p "
            "JOIN click_events e USING(event_id) JOIN devices d ON d.device_id = e.device_id WHERE p.ts >= ? GROUP BY 1 ORDER BY n DESC", (since,))

    def campaign_stats(self, cpc: dict[str, float], default_cpc: float, since: float = 0.0) -> list[dict]:
        rows = self._all(
            f"SELECT e.campaign_id AS campaign_id, COUNT(*) AS clicks, {FLAG_SUM} AS suspicious, COUNT(DISTINCT e.user_id) AS users "
            "FROM fraud_predictions p JOIN click_events e USING(event_id) WHERE p.ts >= ? GROUP BY 1 ORDER BY clicks DESC", (since,))
        for r in rows:
            r["suspicious"] = int(r["suspicious"] or 0)
            price = cpc.get(r["campaign_id"], default_cpc)
            r.update(valid=r["clicks"] - r["suspicious"], cpc=price, spend=round(r["clicks"] * price, 2),
                     wasted=round(r["suspicious"] * price, 2), fraud_rate=r["suspicious"] / max(1, r["clicks"]))
        return rows

    def campaign_detail(self, campaign_id: str, since: float = 0.0) -> dict:
        base = "FROM fraud_predictions p JOIN click_events e USING(event_id) WHERE p.ts >= ? AND e.campaign_id = ?"
        a = (since, campaign_id)
        return {"top_users": self._all(f"SELECT e.user_id AS k, COUNT(*) AS n, {FLAG_SUM} AS flagged {base} GROUP BY 1 ORDER BY flagged DESC, n DESC LIMIT 8", a),
                "top_ips": self._all(f"SELECT e.ip_mask AS k, COUNT(*) AS n, {FLAG_SUM} AS flagged {base} GROUP BY 1 ORDER BY flagged DESC, n DESC LIMIT 8", a),
                "by_country": self._all(f"SELECT e.country AS k, COUNT(*) AS n, {FLAG_SUM} AS flagged {base} GROUP BY 1 ORDER BY n DESC", a)}

    # ------------------------------------------------------------------ reset / clear
    LEARNING_KV = ("thresholds", "learner_state", "pseudo_labels", "drift_baseline")
    RESET_TABLES = {"simulation_runs": ["attack_simulations"],
                    "events": ["click_events", "fraud_predictions"],
                    "alerts": ["fraud_alerts"],
                    "incidents": ["incident_entities", "incidents"],
                    "recommendations": ["recommendations"],
                    "blocklist": ["blocked_entities"],
                    "saved_attacks": ["attack_simulations"],
                    "patterns": ["pattern_hits", "patterns"]}
    ANALYST_SCOPES = ("simulation_runs", "events", "alerts", "incidents", "recommendations", "live_state")
    ADMIN_SCOPES = ("blocklist", "learning", "saved_attacks", "patterns")
    ALL_SCOPES = ANALYST_SCOPES + ADMIN_SCOPES
    PRESETS = {"reset_network": ("simulation_runs", "events", "alerts", "incidents", "recommendations",
                                 "blocklist", "learning"),
               "factory_reset": ("simulation_runs", "events", "alerts", "incidents", "recommendations",
                                 "blocklist", "learning", "saved_attacks", "patterns")}

    def _scope_count(self, scope: str) -> int:
        if scope == "live_state":      # in-memory only; the pipeline supplies the real number
            return 0
        if scope == "simulation_runs":
            return int(self._one("SELECT COUNT(*) n FROM attack_simulations WHERE name IS NULL")["n"])
        if scope == "saved_attacks":
            return int(self._one("SELECT COUNT(*) n FROM attack_simulations WHERE name IS NOT NULL")["n"])
        if scope == "learning":
            keys = ",".join("?" * len(self.LEARNING_KV))
            return int(self._one(f"SELECT COUNT(*) n FROM settings_kv WHERE key IN ({keys})",
                                 self.LEARNING_KV)["n"])
        return sum(int(self._one(f"SELECT COUNT(*) n FROM {t}")["n"]) for t in self.RESET_TABLES[scope])

    def reset_counts(self) -> dict[str, int]:
        """Rows each scope would remove. Safe to call at any time."""
        return {s: self._scope_count(s) for s in self.ALL_SCOPES}

    def execute_reset(self, scopes: tuple[str, ...] | list[str]) -> dict[str, int]:
        """Delete the rows behind `scopes` in one transaction. Never touches users, audit_log,
        model_versions or api_settings. Safe to run twice."""
        unknown = [s for s in scopes if s not in self.ALL_SCOPES]
        if unknown:
            raise ValueError(f"unknown scope(s): {', '.join(unknown)}")
        deleted = {s: 0 for s in self.ALL_SCOPES}
        with self.lock:
            for scope in scopes:
                if scope == "live_state":   # nothing persisted; Pipeline clears it in memory
                    continue
                if scope == "learning":
                    keys = ",".join("?" * len(self.LEARNING_KV))
                    deleted[scope] = self.conn.execute(
                        f"DELETE FROM settings_kv WHERE key IN ({keys})", self.LEARNING_KV).rowcount
                    continue
                if scope == "simulation_runs":
                    deleted[scope] = self.conn.execute("DELETE FROM attack_simulations WHERE name IS NULL").rowcount
                    continue
                if scope == "saved_attacks":
                    deleted[scope] = self.conn.execute("DELETE FROM attack_simulations WHERE name IS NOT NULL").rowcount
                    continue
                for t in self.RESET_TABLES[scope]:
                    deleted[scope] += self.conn.execute(f"DELETE FROM {t}").rowcount
            self.conn.commit()
        return {s: n for s, n in deleted.items() if s in scopes}

    def clear_rules_override(self) -> int:
        """Factory reset only: forget rule edits persisted through the Settings page."""
        return self._exec("DELETE FROM settings_kv WHERE key='rules_override'").rowcount

    # ------------------------------------------------------------------ retention
    def prune(self, days: float = 7.0, max_events: int = 500_000, audit_days: float = 90.0, keep_sims: int = 50,
              now: float | None = None) -> dict:
        """Delete data older than `days` and enforce a row cap on events/predictions. Returns deleted counts."""
        now = now or time.time()
        cutoff = now - days * 86400
        out = {}
        with self.lock:
            def run(name: str, sql: str, args: tuple = ()) -> None:
                out[name] = self.conn.execute(sql, args).rowcount
            run("predictions", "DELETE FROM fraud_predictions WHERE ts < ?", (cutoff,))
            run("events", "DELETE FROM click_events WHERE ts < ?", (cutoff,))
            n = self.conn.execute("SELECT COUNT(*) AS n FROM fraud_predictions").fetchone()["n"]
            if n > max_events:
                edge = self.conn.execute("SELECT ts FROM fraud_predictions ORDER BY ts DESC LIMIT 1 OFFSET ?", (max_events,)).fetchone()
                if edge:
                    run("predictions_cap", "DELETE FROM fraud_predictions WHERE ts <= ?", (edge["ts"],))
                    run("events_cap", "DELETE FROM click_events WHERE ts <= ?", (edge["ts"],))
            run("alerts", "DELETE FROM fraud_alerts WHERE ts < ? AND status = 'resolved'", (cutoff,))
            run("system_events", "DELETE FROM system_events WHERE ts < ?", (cutoff,))
            run("incidents", "DELETE FROM incidents WHERE last_seen < ? AND status != 'open'", (cutoff,))
            run("pattern_hits", "DELETE FROM pattern_hits WHERE ts < ?", (cutoff,))
            run("audit", "DELETE FROM audit_log WHERE ts < ?", (now - audit_days * 86400,))
            run("simulations", "DELETE FROM attack_simulations WHERE id NOT IN (SELECT id FROM attack_simulations ORDER BY id DESC LIMIT ?)", (keep_sims,))
            run("recommendations", "DELETE FROM recommendations WHERE ts < ? AND status != 'pending'", (cutoff,))
            self.conn.commit()
        return out

    def close(self) -> None:
        with self.lock:
            self.conn.close()
