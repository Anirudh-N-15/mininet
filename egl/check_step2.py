#!/usr/bin/env python3
"""Step 2: does the frog-boiling ramp really reach 10x without an alarm?

    ./egl/run_step2.sh [kernel|user]      (runs --mode abrupt, then --mode ramp)

Timeline: 40 s of 3 real users (baseline) | attack | 5 s tail.
  abrupt : total SYN rate jumps straight to cap x the users' rate
  ramp   : total SYN rate grows by --growth per second up to cap x

Afterwards the measured per-second SYN rate (from step 1's telemetry CSV) is
replayed through an EWMA-z detector (detectors.py), the adaptive kind used by
recent SDN papers. Two separate verdicts are printed:
  STEP 2 PASS/FAIL  -> did the attacker produce the planned traffic?
  RESULT            -> did the detector notice? (that is the experiment)
Outputs: results/step2_<mode>.json (summary), results/step2_<mode>_trace.csv
(one row per second: rate, detector mean/threshold, alarm) for the plots.
"""

import argparse
import csv
import json
import os
import time

from egl.attack import amplification, seconds_to_reach
from egl.detectors import EWMAZ
from egl.scenario import Scenario
from egl.topology import SERVER_IP

USERS = ("h2", "h3", "h6")
ATTACKER = "h1"
SETTLE = 6   # skip the first seconds of the baseline (5 s evidence window + 1)


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("abrupt", "ramp"), required=True)
    ap.add_argument("--datapath", default="kernel", choices=("kernel", "user"))
    ap.add_argument("--csv", default=os.environ.get(
        "EGL_TELEMETRY_CSV", "results/egl_telemetry.csv"))
    ap.add_argument("--baseline", type=int, default=40, help="seconds of users only")
    ap.add_argument("--base", type=float, default=6.0,
                    help="users' SYN/s as the attacker estimates it")
    ap.add_argument("--growth", type=float, default=0.02)
    ap.add_argument("--cap", type=float, default=10.0)
    ap.add_argument("--duration", type=float, default=None,
                    help="attack seconds (default: ramp time to cap + 20 s; abrupt 30 s)")
    args = ap.parse_args()
    if args.duration is None:
        args.duration = (seconds_to_reach(args.cap, args.growth) + 20
                         if args.mode == "ramp" else 30)
    out_dir = os.path.dirname(os.path.abspath(args.csv))
    attack_log = os.path.join(out_dir, "step2_%s_attack.csv" % args.mode)

    with Scenario(args.datapath) as sc:
        sc.start_users(USERS)
        t_users = time.time()
        time.sleep(args.baseline)
        t_attack = time.time()
        sender = sc.run_bg(ATTACKER, (
            "python3 -m egl.syn_sender --dst %s --mode %s --base %s --growth %s "
            "--cap %s --duration %s --log %s"
            % (SERVER_IP, args.mode, args.base, args.growth, args.cap,
               args.duration, attack_log)))
        sender.wait(timeout=args.duration + 30)
        time.sleep(5)

    rows = [r for r in load(args.csv) if float(r["wall_time"]) >= t_users + SETTLE]
    sent = load(attack_log)
    base = [float(r["syn_rate"]) for r in rows if float(r["wall_time"]) < t_attack]
    base_mean = sum(base) / len(base)
    base_sd = (sum((v - base_mean) ** 2 for v in base) / len(base)) ** 0.5

    # --- replay the measured trace through the adaptive detector -----------
    det = EWMAZ(beta=0.1, kappa=3.0, warmup=20)
    trace, alarms = [], []
    for r in rows:
        x, dt = float(r["syn_rate"]), float(r["dt"])
        t_rel = float(r["wall_time"]) - t_attack
        learned = det.mu is not None
        mu_before = det.mu
        thr_before = det.threshold(dt) if learned else None
        alarm = det.step(x, dt)
        if alarm:
            alarms.append((t_rel, x / base_mean))
        trace.append({
            "t_rel": round(t_rel, 3), "syn_rate": x,
            "planned_total": round(base_mean * amplification(args.mode, t_rel,
                                                             args.growth, args.cap), 2),
            "ewma_mean": "" if mu_before is None else round(mu_before, 2),
            "ewma_threshold": "" if thr_before is None else round(thr_before, 2),
            "alarm": int(alarm),
        })

    # --- did the attacker do what it was told? -----------------------------
    attack_rows = [r for r in rows if t_attack + 2 <= float(r["wall_time"])
                   <= t_attack + args.duration]
    measured_extra = sum(float(r["syn_rate"]) - base_mean for r in attack_rows)
    sent_total = sum(int(r["sent"]) for r in sent
                     if 2 <= float(r["wall_time"]) - t_attack <= args.duration)
    fidelity = measured_extra / sent_total if sent_total else float("nan")
    tail = [float(r["syn_rate"]) for r in attack_rows[-10:]]
    reached = (sum(tail) / len(tail)) / base_mean if tail else float("nan")

    first = alarms[0] if alarms else None
    summary = {
        "mode": args.mode, "growth_per_s": args.growth, "cap": args.cap,
        "attack_seconds": round(args.duration, 1),
        "baseline_syn_rate_mean": round(base_mean, 2),
        "baseline_syn_rate_sd": round(base_sd, 2),
        "attack_packets_sent": sent_total,
        "fidelity_measured_over_sent": round(fidelity, 3),
        "amplification_reached": round(reached, 2),
        "ewma_alarms": len(alarms),
        "first_alarm_s_after_attack_start": None if not first else round(first[0], 1),
        "amplification_at_first_alarm": None if not first else round(first[1], 2),
    }
    with open(os.path.join(out_dir, "step2_%s.json" % args.mode), "w") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(out_dir, "step2_%s_trace.csv" % args.mode), "w",
              newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(trace[0]))
        w.writeheader()
        w.writerows(trace)

    print("\n== step 2, mode=%s ==" % args.mode)
    for k, v in summary.items():
        print("  %-34s %s" % (k, v))
    ok = 0.85 <= fidelity <= 1.15 and reached >= 0.8 * args.cap
    print("\nSTEP 2 (%s attacker) %s" % (args.mode, "PASS" if ok else "FAIL"))
    if first:
        print("RESULT: EWMA alarmed %.1f s after attack start, at %.1fx the normal rate"
              % first)
    else:
        print("RESULT: EWMA never alarmed; attack reached %.1fx the normal rate" % reached)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
