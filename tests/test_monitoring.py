"""Monitoring assets: dashboard JSON is well-formed (always) and every PromQL query + alert rule is validated against a REAL
Prometheus scraping a live server (set AEGIS_PROMETHEUS_DIR to an extracted prometheus release, else that part is skipped)."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASH = json.loads((ROOT / "docker/grafana/dashboards/aegis.json").read_text())
PROM = os.environ.get("AEGIS_PROMETHEUS_DIR", "")


def exprs():
    return [t["expr"] for p in DASH["panels"] for t in p["targets"]]


def test_dashboard_structure():
    assert DASH["uid"] == "aegisclick" and len(DASH["panels"]) >= 10
    assert all(p["datasource"]["uid"] == "aegis-prom" and p["targets"] for p in DASH["panels"])
    assert len({p["id"] for p in DASH["panels"]}) == len(DASH["panels"])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.skipif(not PROM or not Path(PROM, "promtool").exists(), reason="set AEGIS_PROMETHEUS_DIR to run against real Prometheus")
def test_prometheus_config_rules_and_dashboard_queries(tmp_path):
    for cmd in (["check", "rules", str(ROOT / "docker/prometheus/alerts.yml")],):
        r = subprocess.run([str(Path(PROM, "promtool")), *cmd], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
    app_port, prom_port = free_port(), free_port()
    env = {**os.environ, "PYTHONPATH": str(ROOT), "AEGIS__APP__DB_PATH": str(tmp_path / "m.db"), "SECRET_KEY": "x"}
    app = subprocess.Popen([sys.executable, "-W", "ignore", "-m", "uvicorn", "aegis.api.app:app_factory", "--factory", "--port", str(app_port),
                            "--log-level", "warning"], cwd=ROOT, env=env)
    cfg = tmp_path / "prom.yml"
    cfg.write_text(f"""global: {{scrape_interval: 1s, evaluation_interval: 1s}}
rule_files: ["{ROOT}/docker/prometheus/alerts.yml"]
scrape_configs:
  - job_name: aegisclick
    static_configs: [{{targets: ["127.0.0.1:{app_port}"]}}]
""")
    assert subprocess.run([str(Path(PROM, "promtool")), "check", "config", str(cfg)], capture_output=True, text=True).returncode == 0
    prom = subprocess.Popen([str(Path(PROM, "prometheus")), f"--config.file={cfg}", f"--web.listen-address=127.0.0.1:{prom_port}",
                             f"--storage.tsdb.path={tmp_path / 'tsdb'}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{app_port}"
        for _ in range(120):
            try:
                urllib.request.urlopen(base + "/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)

        def call(path, body=None, tok=None):
            req = urllib.request.Request(base + path, method="POST" if body is not None else "GET", data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {})})
            return json.loads(urllib.request.urlopen(req, timeout=30).read())

        tok = call("/api/auth/login", {"email": "analyst@aegis.local", "password": "analyst123"})["token"]
        call("/api/simulation/burst", {"duration": 10, "intensity": 3}, tok)
        call("/api/simulation/normal", {"duration": 10, "click_rate": 20}, tok)
        time.sleep(14)  # let Prometheus scrape several times while traffic flows

        def q(expr):
            url = f"http://127.0.0.1:{prom_port}/api/v1/query?" + urllib.parse.urlencode({"query": expr})
            return json.loads(urllib.request.urlopen(url, timeout=10).read())

        for e in exprs():
            r = q(e)
            assert r["status"] == "success", (e, r)
            if "psi" not in e:  # drift gauges only exist after the warm-up reference window is captured
                assert r["data"]["result"], f"query returned no series: {e}"
        targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{prom_port}/api/v1/targets", timeout=5).read())
        assert targets["data"]["activeTargets"][0]["health"] == "up"
        rules = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{prom_port}/api/v1/rules", timeout=5).read())
        assert sum(len(g["rules"]) for g in rules["data"]["groups"]) == 4
    finally:
        prom.terminate()
        app.terminate()
