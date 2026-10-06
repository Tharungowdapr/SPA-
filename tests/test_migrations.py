"""Schema migrations: an older database must gain the new columns and tables without losing data."""
from __future__ import annotations

import sqlite3
import time

import pytest

from aegis.store.db import NEW_COLUMNS, SCHEMA, Store

OLD_SCHEMA = """
CREATE TABLE click_events(event_id TEXT PRIMARY KEY, ts REAL, user_id TEXT, ad_id TEXT, campaign_id TEXT,
  publisher_id TEXT, device_id TEXT, ip_hash TEXT, ip_mask TEXT, country TEXT, label INTEGER, attack_type TEXT);
CREATE TABLE fraud_predictions(event_id TEXT PRIMARY KEY, ts REAL, user_id TEXT, risk REAL, level TEXT,
  action TEXT, confidence TEXT, scores TEXT, rules TEXT, model_version TEXT, latency_ms REAL, factors TEXT);
CREATE TABLE fraud_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT, title TEXT,
  user_id TEXT, campaign_id TEXT, status TEXT DEFAULT 'open', details TEXT);
CREATE TABLE blocked_entities(entity_type TEXT, entity_id TEXT, reason TEXT, score REAL, ts REAL,
  active INTEGER DEFAULT 1, blocked_by TEXT, fraud_clicks INTEGER DEFAULT 0, PRIMARY KEY(entity_type, entity_id));
CREATE TABLE attack_simulations(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, params TEXT,
  events INTEGER, events_json TEXT);
CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, role TEXT, password_hash TEXT, created REAL);
"""


@pytest.fixture()
def old_db(tmp_path):
    """A database created by the first release: old columns, no new tables."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA)
    con.execute("INSERT INTO click_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("evt_old", time.time(), "U1", "AD1", "C1", "PUB1", "D1", "iph", "10.0.0.0/24", "IN", 1, "bot"))
    con.execute("INSERT INTO fraud_alerts(ts,severity,title,user_id,campaign_id,details) VALUES(?,?,?,?,?,?)",
                (time.time(), "HIGH", "old alert", "U1", "C1", "{}"))
    con.execute("INSERT INTO blocked_entities VALUES(?,?,?,?,?,1,?,?)", ("user", "U1", "old", 0.9, time.time(), "engine", 3))
    con.execute("INSERT INTO attack_simulations(ts,kind,params,events,events_json) VALUES(?,?,?,?,?)",
                (time.time(), "bot_clique", "{}", 4, "[]"))
    con.execute("INSERT INTO users VALUES(?,?,?,?,?)", (1, "a@b.c", "admin", "x", time.time()))
    con.commit()
    con.close()
    return path


def test_old_database_gains_every_new_column(old_db):
    store = Store(old_db)
    try:
        for table, cols in NEW_COLUMNS.items():
            have = store._table_columns(table)
            for name, _ in cols:
                assert name in have, f"{table}.{name} missing after migration"
    finally:
        store.close()


def test_migration_keeps_existing_rows(old_db):
    store = Store(old_db)
    try:
        assert store._one("SELECT COUNT(*) n FROM click_events")["n"] == 1
        assert store._one("SELECT COUNT(*) n FROM fraud_alerts")["n"] == 1
        assert store._one("SELECT COUNT(*) n FROM users")["n"] == 1
        assert store.list_blocked()[0]["entity_id"] == "U1"
    finally:
        store.close()


def test_migration_adds_new_tables(old_db):
    store = Store(old_db)
    try:
        for table in ("incidents", "incident_entities", "patterns", "pattern_hits"):
            assert table in {r["name"] for r in store._all(
                "SELECT name FROM sqlite_master WHERE type='table'")}, table
    finally:
        store.close()


def test_migration_is_idempotent(old_db):
    first = Store(old_db)
    first.close()
    second = Store(old_db)
    try:
        # Nothing left to add the second time round.
        assert second.migrations_applied == []
        for table, cols in NEW_COLUMNS.items():
            for name, _ in cols:
                assert name in second._table_columns(table)
    finally:
        second.close()


def test_provenance_columns_readable(old_db):
    store = Store(old_db)
    try:
        row = store._one("SELECT source, run_id FROM click_events WHERE event_id='evt_old'")
        assert row["source"] is None and row["run_id"] is None
    finally:
        store.close()


def test_fresh_database_has_new_schema(tmp_path):
    store = Store(tmp_path / "fresh.db")
    try:
        for table, cols in NEW_COLUMNS.items():
            have = store._table_columns(table)
            for name, _ in cols:
                assert name in have
        assert store.list_patterns() == []
        assert store.list_incidents() == []
    finally:
        store.close()


def test_schema_defines_new_tables():
    for table in ("incidents", "incident_entities", "patterns", "pattern_hits"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in SCHEMA
