"""Event bus abstraction. Kafka when reachable, otherwise an in-memory log with the same semantics:
topics, partitions (key hash), offsets, consumer groups, replay. Falls back automatically and reports why.
"""
from __future__ import annotations

import json
import threading
import time
import zlib
from collections import defaultdict, deque
from typing import Any


class InMemoryBus:
    mode = "memory"

    def __init__(self, buffer: int = 100_000, partitions: int = 3, fallback_reason: str = ""):
        self.partitions = partitions
        self.fallback_reason = fallback_reason
        self._log: dict[str, deque] = defaultdict(lambda: deque(maxlen=buffer))
        self._base: dict[str, int] = defaultdict(int)      # offset of first retained message
        self._next: dict[str, int] = defaultdict(int)
        self._offsets: dict[tuple[str, str], int] = defaultdict(int)  # (group, topic) -> next offset
        self._lock = threading.Lock()
        self.published: dict[str, int] = defaultdict(int)

    def publish(self, topic: str, value: dict[str, Any], key: str | None = None) -> int:
        with self._lock:
            log = self._log[topic]
            if len(log) == log.maxlen:
                self._base[topic] += 1
            off = self._next[topic]
            self._next[topic] += 1
            part = zlib.crc32((key or "").encode()) % self.partitions if key else off % self.partitions
            log.append({"offset": off, "partition": part, "key": key, "ts": time.time(), "value": value})
            self.published[topic] += 1
            return off

    def consume(self, topic: str, group: str, max_messages: int = 500) -> list[dict]:
        with self._lock:
            log = self._log[topic]
            start = max(self._offsets[(group, topic)], self._base[topic])
            idx = start - self._base[topic]
            msgs = list(log)[idx: idx + max_messages] if idx < len(log) else []
            self._offsets[(group, topic)] = start + len(msgs)
            return msgs

    def seek_beginning(self, topic: str, group: str) -> None:
        with self._lock:
            self._offsets[(group, topic)] = self._base[topic]

    def lag(self, topic: str, group: str) -> int:
        with self._lock:
            return self._next[topic] - max(self._offsets[(group, topic)], self._base[topic])

    def stats(self) -> dict:
        return {"mode": self.mode, "fallback_reason": self.fallback_reason, "published": dict(self.published),
                "partitions": self.partitions}

    def close(self) -> None:
        pass


class KafkaBus:
    """Thin wrapper over kafka-python. Raises on construction if the broker is unreachable."""
    mode = "kafka"

    def __init__(self, bootstrap: str):
        from kafka import KafkaConsumer, KafkaProducer  # type: ignore
        self._Consumer = KafkaConsumer
        self.bootstrap = bootstrap
        opts = {"bootstrap_servers": bootstrap, "value_serializer": lambda v: json.dumps(v).encode(),
                "key_serializer": lambda k: k.encode() if k else None, "request_timeout_ms": 3000, "linger_ms": 5}
        if "api_version_auto_timeout_ms" in KafkaProducer.DEFAULT_CONFIG:  # kafka-python < 3 only
            opts["api_version_auto_timeout_ms"] = 3000
        self.producer = KafkaProducer(**opts)
        self._consumers: dict[tuple[str, str], Any] = {}
        self.published: dict[str, int] = defaultdict(int)
        self.fallback_reason = ""

    def publish(self, topic: str, value: dict, key: str | None = None) -> int:
        self.producer.send(topic, value=value, key=key)
        self.published[topic] += 1
        return -1

    def consume(self, topic: str, group: str, max_messages: int = 500) -> list[dict]:
        c = self._consumers.get((topic, group))
        if c is None:
            c = self._consumers[(topic, group)] = self._Consumer(
                topic, bootstrap_servers=self.bootstrap, group_id=group, auto_offset_reset="earliest",
                enable_auto_commit=True, value_deserializer=lambda b: json.loads(b.decode()), consumer_timeout_ms=50)
        out = []
        for batch in c.poll(timeout_ms=50, max_records=max_messages).values():
            for m in batch:
                out.append({"offset": m.offset, "partition": m.partition, "key": m.key, "ts": m.timestamp / 1000,
                            "value": m.value})
        return out

    def seek_beginning(self, topic: str, group: str) -> None:
        c = self._consumers.get((topic, group))
        if c:
            c.seek_to_beginning()

    def lag(self, topic: str, group: str) -> int:
        return 0

    def stats(self) -> dict:
        return {"mode": self.mode, "bootstrap": self.bootstrap, "published": dict(self.published)}

    def close(self) -> None:
        try:
            self.producer.flush(2)
            self.producer.close(2)
        except Exception:
            pass


def make_bus(bootstrap: str = "", buffer: int = 100_000):
    """Kafka if configured and reachable, else in-memory (graceful degradation)."""
    if bootstrap:
        try:
            return KafkaBus(bootstrap)
        except Exception as exc:  # noqa: BLE001 - any failure means fall back
            return InMemoryBus(buffer, fallback_reason=f"kafka unavailable: {type(exc).__name__}: {exc}"[:200])
    return InMemoryBus(buffer)
