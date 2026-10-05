#!/usr/bin/env python3

import argparse
import csv
import json
import os
import signal
from subprocess import TimeoutExpired
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from syn_experiment_topology import SynExperimentTopology


CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633
ATTACKER_IP = "10.0.0.1"
VICTIM_IP = "10.0.0.10"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
RESULTS_DIR = Path(
    os.environ.get("DDOS_RESULTS_DIR", "/home/anirudh/mininet/results")
)
METRICS_FILE = RESULTS_DIR / f"run_{RUN_ID}_metrics.csv"
MARKERS_FILE = RESULTS_DIR / f"run_{RUN_ID}_markers.json"
SUMMARY_FILE = RESULTS_DIR / f"run_{RUN_ID}_summary.json"
CONTROL_FILE = RESULTS_DIR / "current_run.json"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_marker(markers, phase, event):
    current_timestamp = timestamp()
    markers.append(
        {"timestamp": current_timestamp, "phase": phase, "event": event}
    )
    return current_timestamp


def write_json(path, value):
    with path.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def make_user_owned(path, mode):
    if os.geteuid() != 0:
        return
    user_id = os.environ.get("SUDO_UID")
    group_id = os.environ.get("SUDO_GID")
    if user_id is None or group_id is None:
        return
    os.chown(path, int(user_id), int(group_id))
    os.chmod(path, mode)


def summarize_metrics(path, markers):
    if not path.exists():
        return {"metrics_available": False}
    with path.open(newline="", encoding="utf-8") as metrics_file:
        rows = list(csv.DictReader(metrics_file))
    anomalies = [
        row for row in rows if row.get("anomaly", "").strip().lower() == "true"
    ]
    attack_start = next(
        (
            datetime.fromisoformat(row["timestamp"])
            for row in markers
            if row["phase"] == "syn_flood" and row["event"] == "start"
        ),
        None,
    )
    anomalies.sort(key=lambda row: row["timestamp"])
    first_anomaly = (
        datetime.fromisoformat(anomalies[0]["timestamp"])
        if anomalies
        else None
    )
    return {
        "metrics_available": True,
        "rows": len(rows),
        "anomalous_rows": len(anomalies),
        "unique_anomaly_timestamps": len(
            {row["timestamp"] for row in anomalies}
        ),
        "affected_switches": len({row["switch_id"] for row in anomalies}),
        "max_packet_rate_z": max(
            (float(row["packet_rate_z"]) for row in rows),
            default=0.0,
        ),
        "max_new_flow_rate_z": max(
            (float(row["new_flow_rate_z"]) for row in rows),
            default=0.0,
        ),
        "max_packet_in_rate_z": max(
            (float(row["packet_in_rate_z"]) for row in rows),
            default=0.0,
        ),
        "first_anomaly_timestamp": (
            first_anomaly.isoformat() if first_anomaly else None
        ),
        "detection_latency_seconds": (
            (first_anomaly - attack_start).total_seconds()
            if first_anomaly and attack_start
            else None
        ),
    }


def mitigation_summary(attack_start):
    try:
        with CONTROL_FILE.open(encoding="utf-8") as control_file:
            control = json.load(control_file)
    except (OSError, json.JSONDecodeError):
        return {"mitigation_install_time": None, "mitigation_latency_seconds": None}
    mitigation_time = control.get("mitigation_install_time")
    return {
        "mitigation_install_time": mitigation_time,
        "mitigation_latency_seconds": (
            (
                datetime.fromisoformat(mitigation_time)
                - datetime.fromisoformat(attack_start)
            ).total_seconds()
            if mitigation_time and attack_start
            else None
        ),
    }


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait()


def run(baseline_seconds, attack_seconds):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    make_user_owned(RESULTS_DIR, 0o775)
    write_json(
        CONTROL_FILE,
        {"run_id": RUN_ID, "metrics_path": str(METRICS_FILE)},
    )
    make_user_owned(CONTROL_FILE, 0o664)
    markers = []
    setLogLevel("info")
    controller = RemoteController(
        "c0",
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )
    network = Mininet(
        topo=SynExperimentTopology(),
        controller=controller,
        switch=OVSKernelSwitch,
    )

    normal_processes = []
    attack_process = None
    try:
        info("*** Starting SYN experiment topology\n")
        network.start()
        victim = network["h10"]
        attacker = network["h1"]
        victim.cmd(
            "python3 -m http.server 80 >/tmp/h10_http.log 2>&1 &"
        )

        write_marker(markers, "baseline", "start")
        info("*** Collecting baseline for %d seconds\n", baseline_seconds)
        for host_name in ("h2", "h3"):
            normal_processes.append(
                network[host_name].popen(
                    "ping -i 0.2 %s" % VICTIM_IP,
                    shell=True,
                    start_new_session=True,
                )
            )
        time.sleep(baseline_seconds)
        write_marker(markers, "baseline", "end")

        write_marker(markers, "syn_flood", "start")
        info("*** Sending bounded TCP SYN traffic from h1 to h10\n")
        packet_count = attack_seconds * 1000
        attack_process = attacker.popen(
            "hping3 -S -p 80 -c %d -i u1000 %s"
            % (packet_count, VICTIM_IP),
            shell=True,
            start_new_session=True,
        )
        time.sleep(attack_seconds)
        write_marker(markers, "syn_flood", "end")
    except KeyboardInterrupt:
        info("*** Experiment interrupted; stopping traffic generators\n")
    finally:
        for process in normal_processes:
            stop_process(process)
        stop_process(attack_process)
        info("*** Stopping SYN experiment topology\n")
        network.stop()
    experiment_end = timestamp()
    marker_by_event = {
        (event["phase"], event["event"]): event["timestamp"]
        for event in markers
    }
    write_json(
        MARKERS_FILE,
        {
            "run_id": RUN_ID,
            "baseline_start": marker_by_event.get(("baseline", "start")),
            "baseline_end": marker_by_event.get(("baseline", "end")),
            "attack_start": marker_by_event.get(("syn_flood", "start")),
            "attack_end": marker_by_event.get(("syn_flood", "end")),
            "experiment_end": experiment_end,
            "events": markers,
        }
    )
    write_json(
        SUMMARY_FILE,
        {
            "run_id": RUN_ID,
            "attacker": ATTACKER_IP,
            "victim": VICTIM_IP,
            "baseline_seconds": baseline_seconds,
            "attack_seconds": attack_seconds,
            "metrics_path": str(METRICS_FILE),
            "markers_path": str(MARKERS_FILE),
            "results": summarize_metrics(METRICS_FILE, markers),
            **mitigation_summary(
                next(
                    (
                        event["timestamp"]
                        for event in markers
                        if event["phase"] == "syn_flood"
                        and event["event"] == "start"
                    ),
                    None,
                ),
            ),
        },
    )
    make_user_owned(MARKERS_FILE, 0o664)
    make_user_owned(SUMMARY_FILE, 0o664)
    print(f"Run ID: {RUN_ID}")
    print(f"Metrics : {METRICS_FILE}")
    print(f"Markers : {MARKERS_FILE}")
    print(f"Summary : {SUMMARY_FILE}")


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(
        description="Run a baseline followed by a bounded TCP SYN experiment"
    )
    argument_parser.add_argument("--baseline-seconds", type=int, default=30)
    argument_parser.add_argument("--attack-seconds", type=int, default=30)
    arguments = argument_parser.parse_args()
    run(arguments.baseline_seconds, arguments.attack_seconds)