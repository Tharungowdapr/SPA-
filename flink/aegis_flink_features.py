"""Apache Flink (PyFlink DataStream) job: keyed, stateful, event-time streaming features per user.

Computes the same velocity/timing features as aegis.streaming.features.FeatureEngine (parity-tested):
clicks_10s/1m/5m/1h, avg_interval, min_interval, interval_std, interval_cv, timing_entropy, burst_score.

Run locally (file in -> file out, used by the parity test):
    python flink/aegis_flink_features.py --input events.jsonl --output features.jsonl
Run against Kafka (needs flink-sql-connector-kafka jar on the classpath; NOT exercised in the build sandbox):
    python flink/aegis_flink_features.py --kafka kafka:9092 --topic-in ad-click-events --topic-out click-features --jar /path/kafka-connector.jar
Input event JSON needs: event_id, user_id, timestamp (epoch seconds, event time).
"""
import argparse
import json
import math
import os
import sys
from bisect import bisect_left

from pyflink.common import Types
from pyflink.datastream import KeyedProcessFunction, RuntimeContext, StreamExecutionEnvironment
from pyflink.datastream.state import ValueStateDescriptor

HORIZON, CAP = 3600.0, 2000
_BINS = [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600]


def _entropy(iv):
    if len(iv) < 4:
        return 2.5
    counts = {}
    for x in iv:
        b = bisect_left(_BINS, x)
        counts[b] = counts.get(b, 0) + 1
    n = len(iv)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def compute(ts_list, now):
    """ts_list: ascending timestamps including `now`, already trimmed to the 1 h horizon / cap."""
    n = len(ts_list)
    cnt = lambda since: n - bisect_left(ts_list, since)  # noqa: E731
    c10, c1m, c5m, c1h = cnt(now - 10), cnt(now - 60), cnt(now - 300), n
    recent = ts_list[-21:]
    iv = [b - a for a, b in zip(recent, recent[1:])]
    if iv:
        avg = sum(iv) / len(iv)
        std = math.sqrt(sum((x - avg) ** 2 for x in iv) / len(iv))
        mn = min(iv)
    else:
        avg, std, mn = 300.0, 50.0, 300.0
    return {"clicks_10s": float(c10), "clicks_1m": float(c1m), "clicks_5m": float(c5m), "clicks_1h": float(c1h),
            "avg_interval": avg, "min_interval": mn, "interval_std": std,
            "interval_cv": (std / avg) if avg > 0 and len(iv) >= 3 else 1.0,
            "timing_entropy": _entropy(iv), "burst_score": c10 / (1.0 + c5m / 30.0)}


class UserFeatures(KeyedProcessFunction):
    def open(self, runtime_context: RuntimeContext):
        self.state = runtime_context.get_state(ValueStateDescriptor("ts", Types.PICKLED_BYTE_ARRAY()))

    def process_element(self, value, ctx):
        event_id, user_id, ts = value
        window = self.state.value() or []
        i = bisect_left(window, ts)
        window.insert(i, ts)
        cut = bisect_left(window, ts - HORIZON)
        extra = len(window) - cut - CAP
        if extra > 0:
            cut += extra
        if cut:
            window = window[cut:]
        self.state.update(window)
        yield json.dumps({"event_id": event_id, "user_id": user_id, "timestamp": ts, "features": compute(window, ts)})


def parse(line):
    d = json.loads(line)
    return d["event_id"], d["user_id"], float(d["timestamp"])


def main():
    # Flink launches Python workers via `python` on PATH: make sure it is THIS interpreter (the one with pyflink)
    os.environ["PATH"] = os.path.dirname(os.path.abspath(sys.executable)) + os.pathsep + os.environ.get("PATH", "")
    ap = argparse.ArgumentParser()
    ap.add_argument("--input")
    ap.add_argument("--output")
    ap.add_argument("--kafka")
    ap.add_argument("--topic-in", default="ad-click-events")
    ap.add_argument("--topic-out", default="click-features")
    ap.add_argument("--jar")
    ap.add_argument("--parallelism", type=int, default=1)
    a = ap.parse_args()
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(a.parallelism)
    row = Types.TUPLE([Types.STRING(), Types.STRING(), Types.DOUBLE()])
    if a.kafka:  # production wiring (requires the Kafka connector jar)
        from pyflink.common.serialization import SimpleStringSchema
        from pyflink.datastream.connectors.kafka import KafkaOffsetsInitializer, KafkaRecordSerializationSchema, KafkaSink, KafkaSource
        from pyflink.common import WatermarkStrategy
        if a.jar:
            env.add_jars("file://" + a.jar)
        src = KafkaSource.builder().set_bootstrap_servers(a.kafka).set_topics(a.topic_in).set_group_id("aegis-flink") \
            .set_starting_offsets(KafkaOffsetsInitializer.earliest()).set_value_only_deserializer(SimpleStringSchema()).build()
        raw = env.from_source(src, WatermarkStrategy.no_watermarks(), "kafka-click-events")
        out = raw.map(parse, output_type=row).key_by(lambda r: r[1]).process(UserFeatures(), output_type=Types.STRING())
        sink = KafkaSink.builder().set_bootstrap_servers(a.kafka).set_record_serializer(
            KafkaRecordSerializationSchema.builder().set_topic(a.topic_out).set_value_serialization_schema(SimpleStringSchema()).build()).build()
        out.sink_to(sink)
        env.execute("aegis-click-features")
        return
    lines = [ln for ln in open(a.input) if ln.strip()]
    ds = env.from_collection(lines, type_info=Types.STRING()).map(parse, output_type=row)
    out = ds.key_by(lambda r: r[1]).process(UserFeatures(), output_type=Types.STRING())
    with open(a.output, "w") as f, out.execute_and_collect() as results:
        for r in results:
            f.write(r + "\n")


if __name__ == "__main__":
    main()
