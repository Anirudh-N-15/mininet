#!/usr/bin/env python3
"""Step 3: three detectors, live in Ryu, on three kinds of traffic growth.

    ./egl/run_step3.sh [kernel|user]        (runs all three scenarios)

Ryu runs egl.egl_controller + egl.detector_app; every detector sees the same
per-second windows. Each scenario: 60 s of 3 users (warm-up), then
  abrupt : spoofed SYN flood jumps straight to 10x the users' rate (30 s)
  ramp   : spoofed SYN flood grows +0.5 %/s up to 10x (frog-boiling, ~8 min)
  crowd  : NO attacker; real users grow 3 -> 15 (x5) in 60 s, then stay 30 s

The question per detector: does it alarm, when, and at what x-fold of the
normal rate? An alarm in "crowd" is a FALSE alarm (only real users).
Writes results/step3_<scenario>.json and keeps the per-window CSV.

Sanity checks (STEP 3 PASS/FAIL): no detector alarms during the warm-up of
any scenario, and every detector catches the abrupt flood within 5 s.
"""

import argparse
import csv
import json
import os
import time

from egl.attack import seconds_to_reach
from egl.scenario import Scenario
from egl.topology import SERVER_IP

USERS = ("h2", "h3", "h6")
ATTACKER = "h1"
SETTLE = 6
DETS = ("static", "ewma", "hst")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=("abrupt", "ramp", "crowd"), required=True)
    ap.add_argument("--datapath", default="kernel", choices=("kernel", "user"))
    ap.add_argument("--detector-csv", default=os.environ.get(
        "EGL_DETECTOR_CSV", "results/egl_detectors.csv"))
    ap.add_argument("--warmup", type=int, default=60)
    ap.add_argument("--growth", type=float, default=0.005, help="ramp: per second")
    ap.add_argument("--cap", type=float, default=10.0)
    ap.add_argument("--crowd-factor", type=float, default=5.0)
    ap.add_argument("--crowd-seconds", type=float, default=60.0)
    ap.add_argument("--base", type=float, default=6.0, help="attacker's estimate of users' SYN/s")
    args = ap.parse_args()
    out_dir = os.path.dirname(os.path.abspath(args.detector_csv))

    with Scenario(args.datapath) as sc:
        sc.start_users(USERS)
        t_users = time.time()
        time.sleep(args.warmup)
        t_event = time.time()
        if args.scenario == "crowd":
            sc.start_crowd(len(USERS), args.crowd_factor, args.crowd_seconds)
            time.sleep(args.crowd_seconds + 30)
        else:
            dur = (seconds_to_reach(args.cap, args.growth) + 20
                   if args.scenario == "ramp" else 30)
            mode = "ramp" if args.scenario == "ramp" else "abrupt"
            sender = sc.run_bg(ATTACKER, (
                "python3 -m egl.syn_sender --dst %s --mode %s --base %s --growth %s "
                "--cap %s --duration %s --log %s"
                % (SERVER_IP, mode, args.base, args.growth, args.cap, dur,
                   os.path.join(out_dir, "step3_%s_attack.csv" % args.scenario))))
            sender.wait(timeout=dur + 30)
        t_end = time.time()
        time.sleep(3)

    with open(args.detector_csv, newline="") as f:
        rows = [r for r in csv.DictReader(f) if float(r["wall_time"]) >= t_users + SETTLE]
    base = [float(r["syn_rate"]) for r in rows if float(r["wall_time"]) < t_event]
    base_mean = sum(base) / len(base)
    during = [r for r in rows if t_event <= float(r["wall_time"]) <= t_end]
    peak = max(float(r["syn_rate"]) for r in during) / base_mean

    summary = {"scenario": args.scenario, "baseline_syn_rate": round(base_mean, 2),
               "peak_x_fold": round(peak, 2), "detectors": {}}
    if args.scenario == "ramp":
        summary["growth_per_s"] = args.growth
    if args.scenario == "crowd":
        summary["crowd"] = "x%g users in %g s" % (args.crowd_factor, args.crowd_seconds)
    for d in DETS:
        pre = sum(1 for r in rows if float(r["wall_time"]) < t_event
                  and r["%s_alarm" % d] == "1")
        hits = [r for r in during if r["%s_alarm" % d] == "1"]
        first = hits[0] if hits else None
        summary["detectors"][d] = {
            "alarms_in_warmup": pre,
            "alarm_windows": len(hits),
            "first_alarm_s": None if not first else round(float(first["wall_time"]) - t_event, 1),
            "x_fold_at_first_alarm": None if not first else round(
                float(first["syn_rate"]) / base_mean, 2),
        }
    with open(os.path.join(out_dir, "step3_%s.json" % args.scenario), "w") as f:
        json.dump(summary, f, indent=2)

    kind = "FALSE alarm" if args.scenario == "crowd" else "alarm"
    print("\n== step 3, scenario=%s (normal %.1f SYN/s, peak %.1fx) =="
          % (args.scenario, base_mean, peak))
    print("%-8s %10s %12s %14s %12s" % ("detector", "warm-up", kind + "s", "first at (s)", "at x-fold"))
    for d, s in summary["detectors"].items():
        print("%-8s %10d %12d %14s %12s" % (d, s["alarms_in_warmup"], s["alarm_windows"],
                                            s["first_alarm_s"], s["x_fold_at_first_alarm"]))
    ok = all(s["alarms_in_warmup"] == 0 for s in summary["detectors"].values())
    if args.scenario == "abrupt":
        ok = ok and all(s["first_alarm_s"] is not None and s["first_alarm_s"] <= 5
                        for s in summary["detectors"].values())
    print("\nSTEP 3 (%s) sanity %s" % (args.scenario, "PASS" if ok else "FAIL"))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
