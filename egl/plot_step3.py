#!/usr/bin/env python3
"""Figure for step 3: when does each detector alarm, per scenario?

    python3 -m egl.plot_step3 [--results results]

One column per scenario (abrupt flood, slow ramp flood, legitimate flash
crowd). Top: the measured SYN rate at the server as a multiple of normal.
Below: one strip per detector, a red tick for every window it alarmed in.
In the flash crowd every tick is a FALSE alarm (only real users).
"""

import argparse
import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES, CRITICAL = "#2a78d6", "#d03b3b"
DETS = (("static", "Static"), ("ewma", "EWMA"), ("hst", "Half-Space Trees"))
SCENARIOS = (("abrupt", "Attack: abrupt 10x flood"),
             ("ramp", "Attack: ramp +0.5%/s to 10x"),
             ("crowd", "Legitimate: users grow 5x in 60 s"))


def load(results, sc):
    with open(os.path.join(results, "step3_%s_detectors.csv" % sc), newline="") as f:
        rows = list(csv.DictReader(f))
    with open(os.path.join(results, "step3_%s.json" % sc)) as f:
        summary = json.load(f)
    return rows, summary


def event_start(results, sc, rows):
    """Wall time the attack / crowd started (attack log, or first crowd growth)."""
    log = os.path.join(results, "step3_%s_attack.csv" % sc)
    if os.path.exists(log):
        with open(log, newline="") as f:
            return float(next(csv.DictReader(f))["wall_time"]) - 1
    # crowd: warm-up is 60 s after users start; users start ~6 s before row 0
    return float(rows[0]["wall_time"]) + 60


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    present = [(k, t) for k, t in SCENARIOS
               if os.path.exists(os.path.join(args.results, "step3_%s.json" % k))]
    widths = [1, 3, 1.4][:len(present)] if len(present) == 3 else [1] * len(present)
    fig, axes = plt.subplots(2, len(present), figsize=(13, 5.2), squeeze=False,
                             gridspec_kw=dict(height_ratios=[3, 1.3], width_ratios=widths,
                                              hspace=0.08))
    fig.patch.set_facecolor(SURFACE)
    for col, (sc, title) in enumerate(present):
        rows, summary = load(args.results, sc)
        t0 = event_start(args.results, sc, rows)
        base = summary["baseline_syn_rate"]
        rows = [r for r in rows if float(r["wall_time"]) >= t0 - 20]
        t = [float(r["wall_time"]) - t0 for r in rows]
        x = [float(r["syn_rate"]) / base for r in rows]
        top, strip = axes[0][col], axes[1][col]
        top.axvspan(0, max(t), color=GRID, alpha=0.4, lw=0)
        top.plot(t, x, lw=1.8, color=SERIES)
        top.axhline(1, color=INK2, lw=0.8, ls=(0, (2, 3)))
        top.set_title(title, loc="left", fontsize=10.5, color=INK, pad=6)
        top.set_ylim(0, 12)
        top.grid(axis="y", color=GRID, lw=0.8)
        top.tick_params(labelbottom=False)
        for i, (key, label) in enumerate(DETS):
            hit = [tt for tt, r in zip(t, rows) if r["%s_alarm" % key] == "1"]
            strip.vlines(hit, i + 0.15, i + 0.85, color=CRITICAL, lw=1.4)
            if col == 0:
                strip.text(-0.02, i + 0.5, label, transform=strip.get_yaxis_transform(),
                           ha="right", va="center", fontsize=9, color=INK)
        strip.set_ylim(len(DETS), 0)
        strip.set_yticks([])
        strip.set_xlabel("seconds since %s started" % ("growth" if sc == "crowd" else "attack"),
                         color=INK2, fontsize=8.5)
        for ax in (top, strip):
            ax.set_xlim(min(t), max(t))
            ax.set_facecolor(SURFACE)
            for side in ("top", "right"):
                ax.spines[side].set_visible(False)
            for side in ("left", "bottom"):
                ax.spines[side].set_color(INK2)
            ax.tick_params(colors=INK2, labelsize=8)
        if col == 0:
            top.set_ylabel("SYN rate (x normal)", color=INK2, fontsize=9)
    fig.suptitle("Volume detectors either miss the slow attack or false-alarm on real users",
                 x=0.01, ha="left", fontsize=13, color=INK, y=0.995)
    fig.text(0.01, 0.925, "Red ticks = windows in which that detector alarmed. "
             "In the flash crowd every alarm is false.", fontsize=9, color=INK2)
    fig.subplots_adjust(left=0.11, right=0.99, top=0.84, bottom=0.11, wspace=0.12)
    out = args.out or os.path.join(args.results, "step3_detectors.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    print("wrote", out)


if __name__ == "__main__":
    main()
