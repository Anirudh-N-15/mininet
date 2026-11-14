#!/usr/bin/env python3
"""Step 1 acceptance test: do the counters tell real users from a SYN flood?

    ./egl/run_step1.sh [kernel|user]        (starts Ryu, runs this, cleans up)

Timeline: 15 s users only | 15 s users + spoofed SYN flood | 10 s users only.
Pass: completion ~1 with users only, ~0 during the flood; SYN rate jumps.
The last phase shows recovery (reported only: half-open entries live ~63 s).
"""

import argparse
import csv
import os
import time

from egl.scenario import Scenario
from egl.topology import SERVER_IP

CLIENTS = ("h2", "h3", "h6")   # two behind the core, one on the server's switch
ATTACKER = "h1"


def phase_means(rows, t0, t1):
    sel = [r for r in rows if t0 <= float(r["wall_time"]) < t1]
    syn = [float(r["syn_rate"]) for r in sel]
    comp = [float(r["completion"]) for r in sel if r["completion"]]
    mean = lambda v: sum(v) / len(v) if v else float("nan")
    return len(sel), mean(syn), mean(comp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datapath", default="kernel", choices=("kernel", "user"))
    ap.add_argument("--csv", default=os.environ.get(
        "EGL_TELEMETRY_CSV", "results/egl_telemetry.csv"))
    ap.add_argument("--rate", type=int, default=200, help="flood packets/s")
    args = ap.parse_args()

    with Scenario(args.datapath) as sc:
        sc.start_users(CLIENTS)
        marks = {"users": time.time()}
        time.sleep(15)
        marks["flood"] = time.time()
        interval = max(1, 1_000_000 // args.rate)
        flood = sc.run_bg(ATTACKER, "hping3 -S -p 80 --rand-source -i u%d %s"
                          % (interval, SERVER_IP))
        time.sleep(15)
        flood.terminate()
        marks["calm"] = time.time()
        time.sleep(10)
        marks["end"] = time.time()

    with open(args.csv, newline="") as f:
        rows = list(csv.DictReader(f))
    phases = [("users only", "users", "flood"), ("users + flood", "flood", "calm"),
              ("users only again", "calm", "end")]
    print("\n%-18s %8s %10s %12s" % ("phase", "windows", "SYN/s", "completion"))
    results = {}
    for label, a, b in phases:
        # skip the evidence window (5 s) + 1, which still mixes the last phase
        n, syn, comp = phase_means(rows, marks[a] + 6, marks[b])
        results[label] = (syn, comp)
        print("%-18s %8d %10.1f %12.3f" % (label, n, syn, comp))

    # Recovery is reported, not required: half-open entries live ~63 s
    # (SYN-ACK retries at 1+2+4+8+16+32 s), so a real server stays clogged
    # for a while after the flood stops.
    ok = (results["users only"][1] > 0.8 and results["users + flood"][1] < 0.3
          and results["users + flood"][0] > 5 * results["users only"][0])
    print("\nSTEP 1", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
