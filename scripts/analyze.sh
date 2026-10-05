#!/usr/bin/env bash

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RYU_ENV="${RYU_ENV:-/home/anirudh/ryu-env}"

REPO_ROOT="$REPO_ROOT" "$RYU_ENV/bin/python" - <<'PY'
import csv
import json
import os
from pathlib import Path

results_dir = Path(os.environ["REPO_ROOT"]) / "results"
metrics_files = sorted(results_dir.glob("*_metrics.csv"))
if not metrics_files:
    raise SystemExit(
        "No metrics CSV found. Start Ryu first, then run scripts/syn.sh."
    )

path = metrics_files[-1]
with path.open(newline="") as metrics_file:
    rows = list(csv.DictReader(metrics_file))

anomalies = [
    row for row in rows
    if row["anomaly"].strip().lower() == "true"
]
run_id = path.stem.removesuffix("_metrics")
summary_path = path.with_name(f"{run_id}_summary.json")

print("Metrics:", path)
print("Total metric rows:", len(rows))
print("Anomalous rows:", len(anomalies))
print("Unique anomaly timestamps:", len({row["timestamp"] for row in anomalies}))
print("Affected switches:", len({row["switch_id"] for row in anomalies}))
for field in ("packet_rate_z", "new_flow_rate_z", "packet_in_rate_z"):
    print(f"Maximum {field}:", max((float(row[field]) for row in rows), default=0.0))

if anomalies:
    print("First anomaly:")
    print(anomalies[0])

if summary_path.exists():
    with summary_path.open(encoding="utf-8") as summary_file:
        summary = json.load(summary_file)
    results = summary.get("results", {})
    print("Detection latency (seconds):", results.get("detection_latency_seconds"))
    print("Mitigation latency (seconds):", summary.get("mitigation_latency_seconds"))
PY