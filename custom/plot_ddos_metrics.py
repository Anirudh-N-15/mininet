#!/usr/bin/env python3

import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as pyplot


def load_metrics(path):
    per_switch = defaultdict(lambda: defaultdict(dict))
    with open(path, newline="", encoding="utf-8") as metrics_file:
        for row in csv.DictReader(metrics_file):
            timestamp = row["timestamp"]
            switch_id = row["switch_id"]
            per_switch[timestamp][switch_id] = {
                "rx_pps": float(row["rx_pps"]),
                "tx_pps": float(row["tx_pps"]),
                "active_flows": int(float(row["active_flows"])),
                "packet_in_per_second": float(row["packet_in_per_second"]),
            }

    timestamps = sorted(per_switch, key=datetime.fromisoformat)
    if not timestamps:
        raise ValueError("The metrics file contains no data rows")

    start = datetime.fromisoformat(timestamps[0])
    seconds = [
        (datetime.fromisoformat(timestamp) - start).total_seconds()
        for timestamp in timestamps
    ]
    packet_rate = []
    active_flows = []
    packet_in_rate = []
    for timestamp in timestamps:
        switches = per_switch[timestamp].values()
        packet_rate.append(
            sum(item["rx_pps"] + item["tx_pps"] for item in switches)
        )
        active_flows.append(sum(item["active_flows"] for item in switches))
        packet_in_rate.append(
            sum(item["packet_in_per_second"] for item in switches)
        )

    return seconds, packet_rate, active_flows, packet_in_rate


def save_plot(seconds, values, ylabel, title, output_path, color):
    figure, axis = pyplot.subplots(figsize=(10, 5))
    axis.plot(seconds, values, color=color, linewidth=1.8)
    axis.set_title(title)
    axis.set_xlabel("Time since first sample (seconds)")
    axis.set_ylabel(ylabel)
    axis.grid(True, alpha=0.25)
    figure.tight_layout()
    figure.savefig(output_path, dpi=150)
    pyplot.close(figure)


def main():
    parser = argparse.ArgumentParser(description="Plot DDoS monitoring metrics")
    parser.add_argument(
        "--input",
        default="/home/anirudh/mininet/ddos_metrics.csv",
        help="CSV metrics file",
    )
    parser.add_argument(
        "--output-dir",
        default="/home/anirudh/mininet/plots",
        help="Directory for generated PNG files",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    seconds, packet_rate, active_flows, packet_in_rate = load_metrics(args.input)
    save_plot(
        seconds,
        packet_rate,
        "Packets per second",
        "Packet rate vs time",
        os.path.join(args.output_dir, "packet_rate_vs_time.png"),
        "#1565c0",
    )
    save_plot(
        seconds,
        active_flows,
        "Active flows",
        "Active flows vs time",
        os.path.join(args.output_dir, "active_flows_vs_time.png"),
        "#2e7d32",
    )
    save_plot(
        seconds,
        packet_in_rate,
        "Packet-In events per second",
        "Packet-In rate vs time",
        os.path.join(args.output_dir, "packet_in_rate_vs_time.png"),
        "#c62828",
    )
    print("Generated plots:")
    print(os.path.join(args.output_dir, "packet_rate_vs_time.png"))
    print(os.path.join(args.output_dir, "active_flows_vs_time.png"))
    print(os.path.join(args.output_dir, "packet_in_rate_vs_time.png"))


if __name__ == "__main__":
    main()