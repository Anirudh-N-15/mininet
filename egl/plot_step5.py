#!/usr/bin/env python3
"""Figure for step 5: what each mitigation policy costs users and saves the server.

    python3 -m egl.plot_step5 [--results results]

Left:  % of real users' requests during the event that FAILED or needed a SYN
       retry (>= ~1 s extra wait) -- what users feel.
Right: mean half-open connections on the server during the event -- the
       resource a SYN flood exhausts.
One row per (scenario, policy); colour = how the switch acts (no mitigation,
plain SYN meter, meter + verified-client bypass); the label says which
detector triggers it.
"""

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
STYLE = {"none": ("#a8a7a1", "no mitigation"),
         "meter": ("#eb6834", "plain SYN meter"),
         "bypass": ("#2a78d6", "meter + verified-client bypass")}
TRIGGER = {"ewma_egl": "EWMA+gate", "static": "Static", "ewma": "EWMA", "hst": "HST",
           "hst_egl": "HST+gate"}
SCENARIOS = (("abrupt", "Abrupt 10x flood"), ("ramp", "Slow ramp to 10x"),
             ("crowd", "Real flash crowd (no attack)"))
ORDER = ("none", "ewma_egl-meter", "ewma_egl-bypass", "static-meter", "static-bypass")


def bad_pct(users):
    ok, slow = users["success_pct"], users["slow_pct"] or 0.0
    if ok is None:
        return None
    return (100.0 - ok) + ok * slow / 100.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    rows = []   # (label, style, bad%, half-open mean) ; None = scenario header
    for sc, title in SCENARIOS:
        runs = {}
        for pol in ORDER:
            path = os.path.join(args.results, "step5_%s_%s.json" % (sc, pol))
            if os.path.exists(path):
                with open(path) as fh:
                    runs[pol] = json.load(fh)
        if not runs:
            continue
        rows.append((title, None, None, None))
        for pol in ORDER:
            if pol not in runs:
                continue
            s = runs[pol]
            style = "none" if pol == "none" else pol.split("-")[1]
            if pol == "none":
                label = "no mitigation"
            else:
                trig = TRIGGER.get(pol.split("-")[0], pol)
                fired = s["first_alarm_s"] is not None
                label = "%s -> %s%s" % (trig, "plain meter" if style == "meter" else "meter + bypass",
                                        "" if fired else " (never fired)")
            rows.append((label, style, bad_pct(s["users"]["event"]),
                         s["half_open"]["event"]["mean"]))

    n = len(rows)
    fig, axes = plt.subplots(1, 2, figsize=(12, 0.36 * n + 1.9), sharey=True,
                             gridspec_kw=dict(wspace=0.08))
    fig.patch.set_facecolor(SURFACE)
    ys = list(range(n))
    for ax, idx, xlabel, fmt in ((axes[0], 2, "user requests failed or delayed by a retry (%)", "%.0f%%"),
                                 (axes[1], 3, "server half-open connections (mean)", "%.0f")):
        vals = [r[idx] for r in rows if r[1] is not None and r[idx] is not None]
        top = max(vals) if vals else 1
        for y, r in zip(ys, rows):
            if r[1] is None:
                continue
            v = r[idx] or 0.0
            ax.barh(y, v, height=0.62, color=STYLE[r[1]][0], edgecolor=SURFACE, linewidth=2)
            ax.text(v + top * 0.015, y, fmt % v, va="center", fontsize=8.5, color=INK)
        ax.set_xlim(0, top * 1.18)
        ax.set_xlabel(xlabel, color=INK2, fontsize=9)
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        ax.set_facecolor(SURFACE)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(INK2)
        ax.tick_params(colors=INK2, labelsize=8.5, left=False)
    axes[0].set_yticks(ys)
    axes[0].set_yticklabels([r[0] for r in rows], fontsize=9)
    for lab, r in zip(axes[0].get_yticklabels(), rows):
        if r[1] is None:
            lab.set_fontweight("bold")
            lab.set_color(INK)
        else:
            lab.set_color(INK2)
    axes[0].set_ylim(n - 0.5, -0.6)
    fig.legend(handles=[Patch(color=c, label=l) for c, l in STYLE.values()],
               loc="upper left", bbox_to_anchor=(0.24, 0.935), ncol=3, frameon=False,
               fontsize=9, labelcolor=INK)
    fig.suptitle("Verified-client bypass protects the server without delaying real users",
                 x=0.01, ha="left", fontsize=13, color=INK, y=0.995)
    fig.subplots_adjust(left=0.24, right=0.98, top=0.84, bottom=0.12)
    out = args.out or os.path.join(args.results, "step5_mitigation.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    print("wrote", out)


if __name__ == "__main__":
    main()
