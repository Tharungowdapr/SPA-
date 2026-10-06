"""Optional Neo4j mirror of the fraud graph (users, devices, IP hashes, campaigns).

Scoring stays on the in-process GraphEngine (fast, always available). This mirror persists the graph in Neo4j so analysts
can explore it with Cypher / Bloom. It is write-behind (queue + background flush) and fully isolated: if Neo4j is down the
queue is bounded, the status turns DEGRADED, and detection is unaffected.
NOTE: verified with a fake driver (Cypher/params/failure handling); not exercised against a live Neo4j in the build sandbox.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

UPSERT = """
UNWIND $rows AS r
MERGE (u:User {id: r.user}) MERGE (d:Device {id: r.device}) MERGE (i:IP {id: r.ip}) MERGE (c:Campaign {id: r.campaign})
MERGE (u)-[:USED]->(d) MERGE (d)-[:FROM]->(i)
MERGE (u)-[k:CLICKED]->(c) ON CREATE SET k.n = 0 SET k.n = k.n + 1, k.last = r.ts
"""
COMPONENT = """
MATCH (u:User {id: $id})-[:USED|FROM*1..6]-(x) RETURN labels(x)[0] AS kind, count(DISTINCT x) AS n
"""
NEIGHBOURHOOD = """
MATCH p = (u:User {id: $id})-[:USED|FROM*1..4]-(x)
WITH DISTINCT x LIMIT $limit RETURN labels(x)[0] AS type, x.id AS id
"""


class Neo4jMirror:
    mode = "neo4j"

    def __init__(self, uri: str, user: str = "neo4j", password: str = "", driver: Any = None, batch: int = 200,
                 interval: float = 1.0, max_queue: int = 50_000):
        if driver is None:
            from neo4j import GraphDatabase  # type: ignore
            driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver, self.batch, self.interval = driver, batch, interval
        self.queue: deque = deque(maxlen=max_queue)
        self.healthy, self.last_error, self.dropped, self.written = True, "", 0, 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def add(self, user: str, device: str, ip_hash: str, campaign: str, ts: float) -> None:
        if len(self.queue) == self.queue.maxlen:
            self.dropped += 1
        self.queue.append({"user": user, "device": device, "ip": ip_hash, "campaign": campaign, "ts": ts})

    def flush(self) -> int:
        sent = 0
        while self.queue:
            rows = [self.queue.popleft() for _ in range(min(self.batch, len(self.queue)))]
            try:
                with self.driver.session() as sess:
                    sess.run(UPSERT, rows=rows)
                self.healthy, sent = True, sent + len(rows)
                self.written += len(rows)
            except Exception as exc:  # noqa: BLE001 - keep detection running; retry later
                self.healthy, self.last_error = False, f"{type(exc).__name__}: {str(exc)[:100]}"
                self.queue.extendleft(reversed(rows))
                break
        return sent

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.interval):
                self.flush()
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        self.flush()
        try:
            self.driver.close()
        except Exception:  # noqa: BLE001
            pass

    def component(self, user_id: str) -> dict:
        with self.driver.session() as sess:
            return {r["kind"]: r["n"] for r in sess.run(COMPONENT, id=user_id)}

    def neighbourhood(self, user_id: str, limit: int = 100) -> list[dict]:
        with self.driver.session() as sess:
            return [{"type": r["type"], "id": r["id"]} for r in sess.run(NEIGHBOURHOOD, id=user_id, limit=limit)]

    def stats(self) -> dict:
        return {"mode": self.mode, "healthy": self.healthy, "queued": len(self.queue), "written": self.written,
                "dropped": self.dropped, "last_error": self.last_error, "ts": time.time()}
