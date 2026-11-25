#!/usr/bin/env python3
"""Timeline figure: what happens second by second when mitigation switches on.

    python3 -m egl.plot_timeline [--dir results/eval/mitigation] \
        [--runs step5_ramp_none_r1 step5_ramp_ewma_egl-bypass_r1]

One column per run (same attack, different policy). Rows:
  1. SYN rate at the server (x normal) and the completion ratio's gate:
     grey band = Learning Gate closed, red line = EWMA+gate alarm,
     blue band = mitigation active (meter + verified-client bypass)
  2. half-open connections held by the server (its queue fills at ~385)
  3. every real user request: its TCP connect time (dots), failures at the top
Reads the files check_step5.py writes for each run.
"""

import argparse
import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from egl import user_metrics as um

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES, CRITICAL, MITIG, GATE = "#2a78d6", "#d03b3b", "#2a78d6", "#8d8b85"
TITLES = {"none": "No mitigation", "ewma_egl-bypass": "EWMA+gate -> meter + verified-client bypass",
          "ewma_egl-meter": "EWMA+gate -> plain SYN meter"}


def spans(times, flags):
    out, start = [], None
    for t, f in zip(times, flags):
        if f and start is None:
            start = t
        if not f and start is not None:
            out.append((start, t))
            start = None
    if start is not None:
        out.append((start, times[-1]))
    return out


def load_run(d, tag):
    s = json.load(open(os.path.join(d, tag + ".json")))
    t0 = s["t_event"]
    det = list(csv.DictReader(open(os.path.join(d, tag + "_detectors.csv"))))
    det = [r for r in det if float(r["wall_time"]) >= s["t_users"] + 6]
    base = s["baseline_syn_rate"]
    t = [float(r["wall_time"]) - t0 for r in det]
    x = [float(r["syn_rate"]) / base for r in det]
    gate_closed = [r["gate_open"] == "0" for r in det]
    alarm = [r.get("ewma_egl_alarm") == "1" for r in det]
    mit = []
    path = os.path.join(d, tag + "_mitigation.csv")
    if os.path.exists(path):
        rows = list(csv.DictReader(open(path)))
        mt = [float(r["wall_time"]) - t0 for r in rows]
        mit = spans(mt, [r["active"] == "1" for r in rows])
    half = [(tt - t0, v) for tt, v in um.load_half_open(os.path.join(d, tag + "_half_open.log"))]
    reqs = [(tt - t0, code, c) for tt, code, c in um.load_requests(os.path.join(d, tag + "_clients"))]
    return dict(s=s, t=t, x=x, gate=spans(t, gate_closed), alarm=spans(t, alarm), mit=mit,
                half=half, reqs=reqs, t_end=s["t_end"] - t0)


def style(ax):
    ax.set_facecolor(SURFACE)
    ax.grid(axis="y", color=GRID, lw=0.8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(INK2)
    ax.tick_params(colors=INK2, labelsize=8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="results/eval/mitigation")
    ap.add_argument("--runs", nargs="+",
                    default=["step5_ramp_none_r1", "step5_ramp_ewma_egl-bypass_r1"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    runs = [load_run(args.dir, tag) for tag in args.runs]
    fig, axes = plt.subplots(3, len(runs), figsize=(6.2 * len(runs), 7.4), squeeze=False,
                             sharex="col", gridspec_kw=dict(height_ratios=[1.3, 1, 1], hspace=0.12))
    fig.patch.set_facecolor(SURFACE)
    xmin = -30
    for col, run in enumerate(runs):
        pol = run["s"]["policy"]
        xmax = run["t_end"] + 5
        a1, a2, a3 = axes[0][col], axes[1][col], axes[2][col]
        for ax in (a1, a2, a3):
            for a, b in run["mit"]:
                ax.axvspan(max(a, xmin), b, color=MITIG, alpha=0.10, lw=0)
            style(ax)
            ax.set_xlim(xmin, xmax)
        for a, b in run["gate"]:
            a1.axvspan(max(a, xmin), b, ymin=0.0, ymax=0.06, color=GATE, alpha=0.9, lw=0)
        if run["alarm"]:
            first = run["alarm"][0][0]
            for ax in (a1, a2, a3):
                ax.axvline(first, color=CRITICAL, lw=1.4, ls=(0, (4, 2)))
            a1.text(first, 11.6, "alarm at %.0f s" % first, color=CRITICAL, fontsize=8.5,
                    ha="center", va="bottom")
        a1.plot(run["t"], run["x"], color=SERIES, lw=1.6)
        a1.set_ylim(0, 11.5)
        a1.set_clip_on(False)
        a1.set_title(TITLES.get(pol, pol), loc="left", fontsize=10.5, color=INK, pad=16)
        hx = [t for t, _ in run["half"] if xmin <= t <= xmax]
        hy = [v for t, v in run["half"] if xmin <= t <= xmax]
        a2.plot(hx, hy, color=INK2, lw=1.6)
        a2.axhline(385, color=CRITICAL, lw=0.8, ls=":")
        a2.text(xmin + 2, 392, "server queue full", fontsize=7.5, color=CRITICAL)
        a2.set_ylim(0, 440)
        ok = [(t, c) for t, code, c in run["reqs"] if code == "200" and xmin <= t <= xmax]
        bad = [t for t, code, c in run["reqs"] if code != "200" and xmin <= t <= xmax]
        a3.scatter([t for t, _ in ok], [c for _, c in ok], s=5, color=SERIES, alpha=0.6, lw=0)
        a3.scatter(bad, [3.6] * len(bad), s=12, marker="x", color=CRITICAL, lw=1)
        a3.set_ylim(-0.1, 3.9)
        a3.set_xlabel("seconds since the attack started", color=INK2, fontsize=9)
        if col == 0:
            a1.set_ylabel("SYN rate (x normal)", color=INK2, fontsize=9)
            a2.set_ylabel("half-open\nconnections", color=INK2, fontsize=9)
            a3.set_ylabel("user connect time (s)\nx = failed", color=INK2, fontsize=9)
    kind = {"ramp": "A slow SYN ramp", "abrupt": "An abrupt 10x SYN flood",
            "crowd": "A real flash crowd"}.get(runs[0]["s"]["scenario"], "The attack")
    fig.suptitle(kind + ", second by second: when the alarm fires and what mitigation changes",
                 x=0.01, ha="left", fontsize=12.5, color=INK, y=0.995)
    fig.text(0.01, 0.955, "Blue band = mitigation active.  Red dashed = EWMA+gate alarm.  "
             "Grey strip (top row) = Learning Gate closed.  Connect times near 1 s or 3 s = a SYN "
             "had to be retried.", fontsize=8.5, color=INK2)
    fig.subplots_adjust(left=0.08, right=0.99, top=0.86, bottom=0.07, wspace=0.12)
    out = args.out or os.path.join(args.dir, "..", "report", "fig_timeline_ramp.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    print("wrote", os.path.normpath(out))


if __name__ == "__main__":
    main()
