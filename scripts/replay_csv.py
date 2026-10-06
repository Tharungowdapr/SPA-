"""Offline demo mode: replay a CSV of click events through the RUNNING server's real pipeline (/api/events).
Columns = ClickEvent fields (user_id, ad_id, campaign_id, device_id, ip_address, timestamp, ...). Timestamps are
shifted to 'now' keeping relative spacing; --speed N compresses time.  python scripts/replay_csv.py file.csv [--speed 20]"""
import argparse
import csv
import json
import sys
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--url", default="http://localhost:8000")
ap.add_argument("--speed", type=float, default=1.0)  # wall-clock speed-up only; event timestamps keep their original spacing
ap.add_argument("--email", default="analyst@aegis.local")
ap.add_argument("--password", default="analyst123")
a = ap.parse_args()


def call(path, body=None, tok=None):
    req = urllib.request.Request(a.url + path, method="POST", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


try:
    tok = call("/api/auth/login", {"email": a.email, "password": a.password})["token"]
except Exception as exc:
    sys.exit(f"cannot reach {a.url}: {exc} (start the server with `make run`)")
num = {"timestamp", "latitude", "longitude", "account_age_days"}
rows = []
for r in csv.DictReader(open(a.csv)):
    r = {k: (float(v) if k in num and v != "" else v) for k, v in r.items() if v not in ("", None) and k not in ("label", "attack_type")}
    rows.append(r)
rows.sort(key=lambda r: r["timestamp"])
t0, now = rows[0]["timestamp"], time.time()
sent = rej = 0
last = 0.0
start = time.time()
i = 0
while i < len(rows):
    due = (time.time() - start) * a.speed
    j = i
    while j < len(rows) and rows[j]["timestamp"] - t0 <= due and j - i < 500:
        rows[j]["timestamp"] = now + (rows[j]["timestamp"] - t0)   # event time keeps original spacing
        j += 1
    if j > i:
        res = call("/api/events", rows[i:j], tok)["results"]
        sent += len(res)
        rej += sum(x["status"] == "rejected" for x in res)
        i = j
        if time.time() - last > 0.5 or i >= len(rows):
            last = time.time()
            print(f"\rreplayed {sent}/{len(rows)}  rejected(blocked) {rej}", end="", flush=True)
    else:
        time.sleep(0.05)
print("\ndone")
