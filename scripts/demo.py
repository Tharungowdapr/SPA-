"""Scripted demo against a RUNNING server (make run): normal traffic, then attacks; prints live results.
Usage: python scripts/demo.py [--url http://localhost:8000] [--only bot]"""
import argparse
import json
import sys
import time
import urllib.request


def call(url, path, method="GET", body=None, token=None):
    req = urllib.request.Request(url + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--only", help="run just one attack kind")
    ap.add_argument("--email", default="analyst@aegis.local")
    ap.add_argument("--password", default="analyst123")
    a = ap.parse_args()
    try:
        tok = call(a.url, "/api/auth/login", "POST", {"email": a.email, "password": a.password})["token"]
    except Exception as exc:
        sys.exit(f"cannot reach {a.url}: {exc}\nstart the server first: make run")
    snap = lambda: call(a.url, "/status")["stats"]
    plan = [(a.only, {"duration": 30, "intensity": 3})] if a.only else [
        ("normal", {"duration": 20, "click_rate": 10}), ("bot", {"duration": 20, "intensity": 3}),
        ("click_farm", {"duration": 30, "intensity": 2}), ("ip_rotation", {"duration": 20, "intensity": 2})]
    for kind, params in plan:
        run = call(a.url, f"/api/simulation/{kind}", "POST", params, tok)
        print(f"\n>>> {kind}: {run['total']} events scheduled")
        end = time.time() + params["duration"] + 3
        while time.time() < end:
            time.sleep(3)
            s = snap()
            print(f"    events={s['total_events']:>6} flagged={s['flagged']:>5} blocked_users={s['blocked_users']:>4} "
                  f"rejected={s['rejected']:>5} p95={s['latency_ms']['p95']}ms")
    blocked = call(a.url, "/api/blocked", token=tok)
    alerts = call(a.url, "/api/alerts?status=open&limit=5", token=tok)
    print(f"\nblocked entities: {len(blocked)}; open alerts: {len(alerts)}")
    for al in alerts[:3]:
        print(f"  [{al['severity']}] {al['title']}")
    print("open the Control Center to inspect:", a.url + "/")


if __name__ == "__main__":
    main()
