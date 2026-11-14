#!/usr/bin/env python3
"""Figure for step 2: abrupt flood vs frog-boiling ramp against EWMA-z.

    python3 -m egl.plot_step2 [--results results] [--out results/step2_ramp_vs_abrupt.png]

Two panels, same y-scale: measured SYN rate at the server (blue), the EWMA
detector's alarm threshold at that moment (grey dashed), alarms (red x).
Reads results/step2_<mode>_trace.csv written by check_step2.py.
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


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    num = lambda r, k: float(r[k]) if r[k] != "" else None
    return [dict(t=num(r, "t_rel"), x=num(r, "syn_rate"),
                 thr=num(r, "ewma_threshold"), alarm=r["alarm"] == "1") for r in rows]


def panel(ax, rows, title, ymax, attack_s):
    t = [r["t"] for r in rows]
    ax.axvspan(0, attack_s, color=GRID, alpha=0.45, lw=0)
    ax.text(1.5, ymax * 0.97, "attack running", va="top", fontsize=8.5, color=INK2)
    thr = [(r["t"], r["thr"]) for r in rows if r["thr"] is not None]
    ax.plot([a for a, _ in thr], [b for _, b in thr], ls=(0, (4, 3)),
            lw=1.5, color=INK2, label="EWMA alarm threshold")
    ax.plot(t, [r["x"] for r in rows], lw=2, color=SERIES,
            label="measured SYN rate at server")
    al = [r for r in rows if r["alarm"]]
    if al:
        ax.scatter([r["t"] for r in al], [r["x"] for r in al], marker="x", s=36,
                   lw=1.6, color=CRITICAL, zorder=5, label="alarm")
    ax.set_title(title, loc="left", fontsize=11, color=INK, pad=8)
    ax.set_xlabel("seconds since attack start", color=INK2, fontsize=9)
    ax.set_ylim(0, ymax)
    ax.grid(axis="y", color=GRID, lw=0.8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(INK2)
    ax.tick_params(colors=INK2, labelsize=8.5)
    ax.set_facecolor(SURFACE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    abrupt = load(os.path.join(args.results, "step2_abrupt_trace.csv"))
    ramp = load(os.path.join(args.results, "step2_ramp_trace.csv"))
    ymax = 1.1 * max(r["x"] for r in abrupt + ramp)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=True,
                             gridspec_kw=dict(width_ratios=[1, 2]))
    fig.patch.set_facecolor(SURFACE)
    n_abrupt = sum(r["alarm"] for r in abrupt)
    n_ramp = sum(r["alarm"] for r in ramp)
    dur = lambda m: json.load(open(os.path.join(args.results, "step2_%s.json" % m)))["attack_seconds"]
    panel(axes[0], abrupt, "Abrupt 10x flood: %d alarms" % n_abrupt, ymax, dur("abrupt"))
    panel(axes[1], ramp, "Ramp +2%%/s to 10x: %d alarms" % n_ramp, ymax, dur("ramp"))
    axes[0].set_ylabel("SYN packets / s", color=INK2, fontsize=9)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(0.005, 0.925), ncol=3,
               frameon=False, fontsize=9, labelcolor=INK)
    fig.suptitle("The same 10x flood is caught when it jumps and missed when it creeps",
                 x=0.01, ha="left", fontsize=13, color=INK, y=0.99)
    fig.tight_layout(rect=(0, 0, 1, 0.86))
    out = args.out or os.path.join(args.results, "step2_ramp_vs_abrupt.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    print("wrote", out)


if __name__ == "__main__":
    main()
