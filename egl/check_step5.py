#!/usr/bin/env python3
"""Step 5: does acting on the alarm protect the server without hurting users?

    ./egl/run_step5.sh [kernel|user]      (runs every policy x scenario)

Ryu runs egl_controller + detector_app + mitigator_app. The mitigation policy
comes from the environment (set by run_step5.sh):
    EGL_MITIGATE_ON  none | static | ewma | ewma_egl   (which detector acts)
    EGL_BYPASS       1 = verified clients skip the meter, 0 = plain meter

Users are first-time visitors as far as the server's kernel is concerned
(tcp_no_metrics_save=1), and every user host sends from a pool of
--pool addresses, so "verified client" means a real address that finished a
connection, not a whole host.

Scenarios as in step 3 (60 s warm-up first): abrupt 10x flood, ramp +0.5 %/s
to 10x, or a legitimate flash crowd (x5 in 60 s). Measured per phase
(warm-up, event before mitigation, event while mitigating):
    users:  success %, connect time p50/p95, % of requests that needed a retry
    server: half-open connections (peak, mean)
    switch: SYNs dropped by the meter, verified clients, bypass rules
Writes results/step5_<scenario>_<policy>.json.
"""

import argparse
import csv
import json
import os
import time

from egl import user_metrics as um
from egl.attack import seconds_to_reach
from egl.scenario import Scenario
from egl.topology import SERVER_IP

USERS = ("h2", "h3", "h6")
ATTACKER = "h1"
SETTLE = 6


def policy_label():
    on = os.environ.get("EGL_MITIGATE_ON", "ewma_egl")
    if on == "none":
        return "none"
    return "%s-%s" % (on, "bypass" if os.environ.get("EGL_BYPASS", "1") == "1" else "meter")


def mitigation_spans(path, t_end):
    spans, start = [], None
    try:
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
    except OSError:
        return [], {}
    for r in rows:
        if r["event"] == "on" and start is None:
            start = float(r["wall_time"])
        elif r["event"] == "off" and start is not None:
            spans.append((start, float(r["wall_time"])))
            start = None
    if start is not None:
        spans.append((start, t_end))
    last = rows[-1] if rows else {}
    return spans, {"meter_rate_pps": last.get("meter_rate") or None,
                   "meter_dropped_total": int(last.get("meter_dropped_total") or 0),
                   "verified_clients": int(last.get("verified") or 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=("abrupt", "ramp", "crowd"), required=True)
    ap.add_argument("--datapath", default="kernel", choices=("kernel", "user"))
    ap.add_argument("--results", default="results")
    ap.add_argument("--warmup", type=int, default=60)
    ap.add_argument("--growth", type=float, default=0.005)
    ap.add_argument("--cap", type=float, default=10.0)
    ap.add_argument("--pool", type=int, default=20, help="client addresses per user host")
    ap.add_argument("--base", type=float, default=6.0)
    args = ap.parse_args()
    label = policy_label()
    tag = "step5_%s_%s" % (args.scenario, label)
    res = os.path.abspath(args.results)
    client_dir = os.path.join(res, tag + "_clients")
    half_open_log = os.path.join(res, tag + "_half_open.log")
    for path in (half_open_log,):
        if os.path.exists(path):
            os.remove(path)
    if os.path.isdir(client_dir):
        for f in os.listdir(client_dir):
            os.remove(os.path.join(client_dir, f))

    with Scenario(args.datapath, new_visitors=True, pool=args.pool,
                  log_dir=client_dir) as sc:
        sc.start_half_open_sampler(half_open_log)
        sc.start_users(USERS)
        t_users = time.time()
        time.sleep(args.warmup)
        t_event = time.time()
        if args.scenario == "crowd":
            sc.start_crowd(len(USERS), 5.0, 60.0)
            time.sleep(90)
        else:
            mode = "ramp" if args.scenario == "ramp" else "abrupt"
            dur = seconds_to_reach(args.cap, args.growth) + 20 if mode == "ramp" else 60
            sender = sc.run_bg(ATTACKER, (
                "python3 -m egl.syn_sender --dst %s --mode %s --base %s --growth %s "
                "--cap %s --duration %s --log %s"
                % (SERVER_IP, mode, args.base, args.growth, args.cap, dur,
                   os.path.join(res, tag + "_attack.csv"))))
            sender.wait(timeout=dur + 30)
        t_end = time.time()
        time.sleep(2)

    det_csv = os.environ["EGL_DETECTOR_CSV"]
    with open(det_csv, newline="") as fh:
        windows = [r for r in csv.DictReader(fh) if float(r["wall_time"]) >= t_users + SETTLE]
    base = [float(r["syn_rate"]) for r in windows if float(r["wall_time"]) < t_event]
    base_mean = sum(base) / len(base)
    target = os.environ.get("EGL_MITIGATE_ON", "ewma_egl")
    first_alarm = None
    if target != "none":
        hits = [r for r in windows if float(r["wall_time"]) >= t_event
                and r.get("%s_alarm" % target) == "1"]
        if hits:
            first_alarm = float(hits[0]["wall_time"]) - t_event
    spans, mit = mitigation_spans(os.environ["EGL_MITIGATION_CSV"], t_end)
    event_spans = [(t_event, t_end)]
    mitigated = [(max(a, t_event), min(b, t_end)) for a, b in spans if b > t_event and a < t_end]
    unmitigated = []
    cursor = t_event
    for a, b in sorted(mitigated):
        if a > cursor:
            unmitigated.append((cursor, a))
        cursor = max(cursor, b)
    if cursor < t_end:
        unmitigated.append((cursor, t_end))
    # SYNs offered while mitigating, for the share the meter dropped
    offered = sum(float(r["syn_rate"]) * 1.0 for r in windows
                  if um.in_spans(float(r["wall_time"]), mitigated))

    reqs = um.load_requests(client_dir)
    half = um.load_half_open(half_open_log)
    warm = [(t_users + SETTLE, t_event)]
    summary = {
        "scenario": args.scenario, "policy": label,
        "baseline_syn_rate": round(base_mean, 2),
        "first_alarm_s": None if first_alarm is None else round(first_alarm, 1),
        "mitigation_seconds": round(sum(b - a for a, b in mitigated), 1),
        **mit,
        "meter_dropped_share_pct": None if not offered else round(
            100.0 * mit.get("meter_dropped_total", 0) / offered, 1),
        "users": {"warmup": um.request_stats(reqs, warm),
                  "event": um.request_stats(reqs, event_spans),
                  "event_unmitigated": um.request_stats(reqs, unmitigated),
                  "event_mitigated": um.request_stats(reqs, mitigated)},
        "half_open": {"warmup": um.half_open_stats(half, warm),
                      "event": um.half_open_stats(half, event_spans),
                      "event_mitigated": um.half_open_stats(half, mitigated)},
    }
    with open(os.path.join(res, tag + ".json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    u = summary["users"]
    print("\n== step 5: %s, policy %s ==" % (args.scenario, label))
    print("first alarm of acting detector: %s s; mitigating for %s s; meter %s pps, "
          "dropped %s SYNs (%s%% of offered); %s verified clients"
          % (summary["first_alarm_s"], summary["mitigation_seconds"],
             summary["meter_rate_pps"], summary["meter_dropped_total"],
             summary["meter_dropped_share_pct"], summary["verified_clients"]))
    print("%-20s %9s %9s %10s %10s %9s" % ("users", "requests", "success%", "conn p50",
                                          "conn p95", "retried%"))
    for k in ("warmup", "event", "event_unmitigated", "event_mitigated"):
        s = u[k]
        print("%-20s %9s %9s %10s %10s %9s" % (k, s["requests"], s["success_pct"],
                                               s["connect_p50_s"], s["connect_p95_s"],
                                               s["slow_pct"]))
    h = summary["half_open"]
    print("server half-open: warm-up peak %s | event peak %s mean %s | while mitigating mean %s"
          % (h["warmup"]["peak"], h["event"]["peak"], h["event"]["mean"],
             h["event_mitigated"]["mean"]))
    ok = (u["warmup"]["success_pct"] or 0) >= 95
    print("\nSTEP 5 (%s, %s) sanity %s" % (args.scenario, label, "PASS" if ok else "FAIL"))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
