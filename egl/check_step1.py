#!/usr/bin/env python3
"""Step 1 acceptance test: do the counters tell real users from a SYN flood?

Start Ryu first (other terminal):
    ryu-manager --ofp-tcp-listen-port 6653 egl/egl_controller.py
Then:
    sudo python3 -m egl.check_step1            # add --datapath user if no OVS kernel module

Timeline: 15 s users only | 15 s users + spoofed SYN flood | 10 s users only.
Pass criteria (printed at the end):
    completion ~1 when only users, ~0 during the flood; SYN rate jumps.
"""

import argparse
import csv
import os
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from egl.topology import SERVER_HOST, SERVER_IP, EGLTopology

CLIENTS = ("h2", "h3", "h6")   # two behind the core, one on the server's switch
ATTACKER = "h1"


def curl_loop(host_ip):
    # a fresh TCP connection every 0.5 s; python http.server closes it (FIN)
    return ("while true; do curl -s -o /dev/null --max-time 3 http://%s/; "
            "sleep 0.5; done" % host_ip)


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

    setLogLevel("warning")
    net = Mininet(topo=EGLTopology(datapath=args.datapath), switch=OVSSwitch,
                  controller=RemoteController("c0", ip="127.0.0.1", port=6653),
                  autoSetMacs=True)
    procs = []
    try:
        net.start()
        if args.datapath == "user":
            # OVS userspace datapath does not fill in TCP checksums that the
            # veth driver left for "hardware" offload, so receivers drop every
            # TCP packet (ping still works). Compute checksums in software.
            for host in net.hosts:
                host.cmd("ethtool -K %s tx off >/dev/null 2>&1" % host.defaultIntf())
        server = net[SERVER_HOST]
        server.cmd("sysctl -qw net.ipv4.tcp_syncookies=0")
        server.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
        time.sleep(2)
        net.pingAll(timeout=1)               # learn MACs, confirm reachability

        for name in CLIENTS:
            procs.append(net[name].popen(curl_loop(SERVER_IP), shell=True))
        marks = {"users": time.time()}
        time.sleep(15)

        marks["flood"] = time.time()
        interval = max(1, 1_000_000 // args.rate)
        flood = net[ATTACKER].popen(
            "hping3 -S -p 80 --rand-source -i u%d %s" % (interval, SERVER_IP),
            shell=True)
        time.sleep(15)
        flood.terminate()
        marks["calm"] = time.time()
        time.sleep(10)
        marks["end"] = time.time()
    finally:
        for p in procs:
            p.terminate()
        net.stop()

    with open(args.csv, newline="") as f:
        rows = list(csv.DictReader(f))
    phases = [("users only", "users", "flood"), ("users + flood", "flood", "calm"),
              ("users only again", "calm", "end")]
    print("\n%-18s %8s %10s %12s" % ("phase", "windows", "SYN/s", "completion"))
    results = {}
    for label, a, b in phases:
        n, syn, comp = phase_means(rows, marks[a] + 6, marks[b])  # skip evidence window (5 s) + 1
        results[label] = (syn, comp)
        print("%-18s %8d %10.1f %12.3f" % (label, n, syn, comp))

    ok = (results["users only"][1] > 0.8 and results["users + flood"][1] < 0.3
          and results["users + flood"][0] > 5 * results["users only"][0]
          and results["users only again"][1] > 0.8)
    print("\nSTEP 1", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
