"""Real HTTP server for the browser tests. Rules-only so startup is fast and needs no model files.

Run with:  python -m uvicorn tests.browser_server:app --port <n>
AEGIS_TEST_DB points at the SQLite file to use; AEGIS_TEST_SEED_USERS sets the simulated user pool size.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.api.app import create_app  # noqa: E402
from aegis.config import load_settings  # noqa: E402

s = load_settings()
s.set("app.db_path", os.environ.get("AEGIS_TEST_DB", ":memory:"))
s.set("security.rate_limit_per_min", 10_000_000)
s.set("security.login_rate_limit_per_min", 10_000_000)
s.set("agent.enabled", False)
s.set("app.seed_users", int(os.environ.get("AEGIS_TEST_SEED_USERS", "20")))

app = create_app(s, bundle=None)
