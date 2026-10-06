# Apache Flink job

`aegis_flink_features.py` is a PyFlink DataStream job: keyed (per user), stateful, event-time click features
(clicks 10s/1m/5m/1h, intervals, entropy, burst). It is **parity-tested** against the Python `FeatureEngine`
(`tests/test_flink.py`, max difference < 1e-6 on 3,000+ events, run on a real local Flink mini-cluster).

```bash
# separate venv (apache-flink pins an older numpy) + Java 11/17/21
python -m venv .flinkenv && .flinkenv/bin/pip install apache-flink
make flink-test FLINK_PY=$PWD/.flinkenv/bin/python
.flinkenv/bin/python flink/aegis_flink_features.py --input events.jsonl --output features.jsonl
```
Kafka mode (`--kafka host:9092 --jar flink-sql-connector-kafka.jar`) reads `ad-click-events` and writes `click-features`.
That path is written against the documented PyFlink Kafka connector API but was **not run** (no broker/connector jar in the build sandbox).
The platform's default stream engine is the in-process Python `FeatureEngine`; Flink is an optional, equivalent implementation.
