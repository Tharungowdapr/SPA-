import os
import socket
import subprocess
import sys
import threading
import time
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore")

from aegis.config import load_settings  # noqa: E402
from aegis.data.dataset import standard_splits  # noqa: E402
from aegis.detection.models import train_bundle  # noqa: E402


@pytest.fixture(scope="session")
def base_settings():
    s = load_settings()
    s.set("app.db_path", ":memory:")
    return s


@pytest.fixture(scope="session")
def bundle(base_settings):
    d = standard_splits(base_settings.get("rules"), quick=True)
    return train_bundle(d["train"], d["val"], base_settings.get("ml"), version="vtest", compute_importance=False)


@pytest.fixture()
def settings(base_settings, tmp_path):
    s = base_settings.copy()
    s.set("app.models_dir", str(tmp_path / "models"))
    s.set("app.db_path", ":memory:")
    return s


# ------------------------------------------------------------------ browser tests
# Playwright is optional: it is imported inside the fixtures so a missing install only skips
# the tests marked `browser`, never the rest of the suite.
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    """uvicorn in a subprocess (rules-only) on a throwaway SQLite file."""
    db = tmp_path_factory.mktemp("browser") / "app.db"
    port = _free_port()
    env = {**os.environ, "AEGIS_TEST_DB": str(db), "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "tests.browser_server:app",
                             "--port", str(port), "--log-level", "warning"],
                            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    import urllib.error
    import urllib.request

    # Drain the server's output continuously: an undrained pipe fills up and blocks the server
    # mid-session, which shows up as random, unrelated timeouts much later in the run.
    server_log: list[str] = []

    def _drain() -> None:
        for line in proc.stdout:                      # type: ignore[union-attr]
            server_log.append(line)
            del server_log[:-400]
            if len(server_log) > 500:
                del server_log[:200]

    threading.Thread(target=_drain, daemon=True).start()

    for _ in range(150):
        if proc.poll() is not None:
            out = "".join(x.decode("utf-8", "replace") if isinstance(x, bytes) else x for x in server_log)
            raise RuntimeError(f"browser test server exited early:\n{out[-3000:]}")
        try:
            with urllib.request.urlopen(base + "/health", timeout=1) as r:
                if r.status == 200:
                    break
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("browser test server did not become healthy within 30s")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


class ConsoleLog:
    """Collects console errors and uncaught page errors so tests can assert a clean console."""

    def __init__(self):
        self.errors: list[str] = []
        self.page_errors: list[str] = []

    def attach(self, page) -> None:
        page.on("console", self._on_console)
        page.on("pageerror", lambda e: self.page_errors.append(str(e)))

    def _on_console(self, msg) -> None:
        if msg.type in ("error", "warning") and "favicon" not in msg.text.lower():
            self.errors.append(msg.text)

    def assert_clean(self) -> None:
        assert not self.page_errors, f"page errors: {self.page_errors}"
        assert not self.errors, f"console errors: {self.errors}"


@pytest.fixture(scope="session")
def browser():
    api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")
    with api.sync_playwright() as p:
        try:
            b = p.chromium.launch(args=["--no-sandbox"])
        except Exception as exc:  # noqa: BLE001 - no browser binary installed
            pytest.skip(f"chromium not available (run `playwright install chromium`): {exc}")
        yield b
        b.close()


@pytest.fixture()
def page(browser, live_server):
    log = ConsoleLog()
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.set_default_timeout(30_000)          # headless Chromium throttles rAF/timers; do not race it
    log.attach(pg)
    pg.console_log = log                  # type: ignore[attr-defined]
    pg.console_errors = log.errors        # type: ignore[attr-defined]
    pg.base_url = live_server             # type: ignore[attr-defined]
    pg.goto(live_server + "/", wait_until="domcontentloaded")
    yield pg
    ctx.close()
